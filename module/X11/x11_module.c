/**
 * FreeRDS: FreeRDP Remote Desktop Services (RDS)
 * X11 Server Module
 *
 * Copyright 2013 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 * Copyright 2013 Thincast Technologies GmbH
 * Copyright 2013 DI (FH) Martin Haimberger <martin.haimberger@thincast.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include <limits.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <errno.h>

#include <winpr/wlog.h>

#include <freerds/backend.h>
#include <freerds/auth.h>

#include "x11_module.h"

RDS_MODULE_CONFIG_CALLBACKS g_Config;
RDS_MODULE_STATUS_CALLBACKS g_Status;

#define X11_DISPLAY_OFFSET 10
#define X11_LOCKFILE_FORMAT "/tmp/.X%d-lock"
#define X11_UNIX_SOCKET_FORMAT "/tmp/.X11-unix/X%d"
#define X11_DISPLAY_MAX 1024

#define USE_IMPERSONATION 1

static wLog* gModuleLog;

struct rds_module_x11
{
	RDS_MODULE_COMMON commonModule;
	UINT32 displayNum;
	pid_t childPid;

	// TODO: rinse all of these.
	STARTUPINFO X11StartupInfo;
	PROCESS_INFORMATION X11ProcessInformation;

	HANDLE monitorThread;
	HANDLE monitorStopEvent;
	STARTUPINFO CSStartupInfo;
	PROCESS_INFORMATION CSProcessInformation;
	STARTUPINFO WMStartupInfo;
	PROCESS_INFORMATION WMProcessInformation;
};
typedef struct rds_module_x11 rdsModuleX11;

void x11_rds_module_reset_process_informations(STARTUPINFO* si, PROCESS_INFORMATION* pi)
{
	ZeroMemory(si, sizeof(STARTUPINFO));
	si->cb = sizeof(STARTUPINFO);
	ZeroMemory(pi, sizeof(PROCESS_INFORMATION));
}

RDS_MODULE_COMMON* x11_rds_module_new(void)
{
	rdsModuleX11* module = (rdsModuleX11*) calloc(1, sizeof(rdsModuleX11));
	ZeroMemory(module, sizeof(rdsModuleX11));
	return (RDS_MODULE_COMMON*) module;
}

void x11_rds_module_free(RDS_MODULE_COMMON* module)
{
	rdsModuleX11* moduleCon = (rdsModuleX11*) module;

	if (moduleCon->commonModule.authToken)
		free(moduleCon->commonModule.authToken);

	if (moduleCon->commonModule.baseConfigPath)
		free(moduleCon->commonModule.baseConfigPath);

	free(module);
}

static unsigned int detect_free_display()
{
	struct stat tstats;
	unsigned int i = 0;
	char buf[256];
	char buf2[256];

	for (i = X11_DISPLAY_OFFSET; i <= X11_DISPLAY_MAX; i++)
	{
		snprintf(buf,256, X11_LOCKFILE_FORMAT, i);
		snprintf(buf2,256, X11_UNIX_SOCKET_FORMAT, i);

		if(stat (buf, &tstats) != 0 && stat(buf2, &tstats) != 0)
		{
			break;
		}
	}

	return i;
}

static int delete_named_pipe(char* pipeName)
{
	char* pipePath = GetNamedPipeUnixDomainSocketFilePathA(pipeName);
	int status;
	if (unlink(pipePath) && errno != ENOENT)
	{
		WLog_Print(gModuleLog, WLOG_ERROR, "unlink(%s): %s", pipePath, strerror(errno));
		status = -1;
	}
	else
	{
		WLog_Print(gModuleLog, WLOG_DEBUG, "unlink(%s): %s (OK)", pipePath, strerror(errno));
		status = 0;
	}
	free(pipePath);
	return status;
}

static int wait_named_pipe_exists(int pid, char* pipeName)
{
	char* pipePath = GetNamedPipeUnixDomainSocketFilePathA(pipeName);
	struct stat stats;
	int i;
	for(i = 0; i < 10; i++)
	{
		if (kill(pid, 0) != 0)
		{
			WLog_Print(gModuleLog, WLOG_ERROR, "Process gave up!");
			free(pipePath);
			return -1;
		}
		if (stat(pipePath, &stats) == 0)
		{
			free(pipePath);
			return 0;
		}
		WLog_Print(gModuleLog, WLOG_DEBUG, "%s doesn't exist yet, waiting...", pipeName);
		usleep(500000);

	}
	WLog_Print(gModuleLog, WLOG_ERROR, "Timed out waiting for %s to appear!", pipePath);
	free(pipePath);
	return -1;
}

char* x11_rds_module_start(RDS_MODULE_COMMON* module)
{
	rdsModuleX11* x11 = (rdsModuleX11*) module;
	x11->displayNum = detect_free_display();
	char displayName[256];
	sprintf_s(displayName, 255, ":%d", x11->displayNum);

	signal(SIGCHLD, SIG_IGN);  // Thwarting a zombie apocalypse: it's that simple.

	char* pipeName = (char*) malloc(MAXPATHLEN);
	if (! pipeName)
	{
		return NULL;
	}

	freerds_named_pipe_get_endpoint_name(x11->displayNum, "X11", pipeName, MAXPATHLEN - 1);
	WLog_Print(gModuleLog, WLOG_DEBUG, "pipeName is: %s", pipeName);

	if (delete_named_pipe(pipeName)) {
		free(pipeName);
		return NULL;
	};

	char x11StartScript[MAXPATHLEN], x11StartScriptQualified[MAXPATHLEN];

	if (!getPropertyStringWrapper(x11->commonModule.baseConfigPath, &g_Config, "startscript", x11StartScript, 256)) {
		char* moduleName = strchr(x11->commonModule.baseConfigPath, '.') + 1;
		snprintf(x11StartScript,  MAXPATHLEN - 1, "start_%s", moduleName);
	}
	if (x11StartScript[0] == '/') {
		x11StartScriptQualified[0] = '\0';
		strncat(x11StartScriptQualified, x11StartScript, MAXPATHLEN - 1);
	} else {
		snprintf(x11StartScriptQualified, MAXPATHLEN - 1, "%s/%s", FREERDS_SBIN_PATH, x11StartScript);
	}

	pid_t child_pid = fork();
	if (child_pid == -1)
	{
		WLog_Print(gModuleLog, WLOG_ERROR, "Cannot fork(): %s", strerror(errno));
		free(pipeName);
		return NULL;
	}
	else if (child_pid != 0)
	{
		// Parent process
		x11->childPid = child_pid;
		if (wait_named_pipe_exists(child_pid, pipeName) == 0) {
			WLog_Print(gModuleLog, WLOG_DEBUG, "Success - Returning pipeName: %s", pipeName);
			return pipeName;
		} else {
			free(pipeName);
			return NULL;
		}
	}

	signal(SIGCHLD, SIG_DFL);
	// The child process will execl() or _exit() trying; malloc() is now free (no pun intended)
	char buf[256];
	buf[255] = '\0';

	int maxfd;
#ifdef F_MAXFD // on some BSD derivates
	maxfd = fcntl(0, F_MAXFD);
#else
	maxfd = sysconf(_SC_OPEN_MAX);
#endif
	int fd;
	for(fd=3; fd<maxfd; fd++)
		close(fd);

	char* path = strdup(getenv("PATH"));
	clearenv();
	setenv("PATH", path, 0);
	setenv("DISPLAY", displayName, 0);

	snprintf(buf, 255, "%d", module->desktopWidth);
	setenv("FREERDS_DESKTOP_WIDTH", buf, 0);
	snprintf(buf, 255, "%d", module->desktopHeight);
	setenv("FREERDS_DESKTOP_HEIGHT", buf, 0);
	setenv("FREERDS_DESKTOP_DEPTH", "24", 0);
	setenv("FREERDS_DESKTOP_DPI", "96", 0);

	snprintf(buf, sizeof(buf), "%d", (int) (x11->commonModule.sessionId));
	setenv("FREERDS_SID", buf, 0);

	if (x11->commonModule.userToken == 0)
	{
		chdir("/");
	}
	else
	{
		struct passwd *pw = getpwnam (x11->commonModule.userName);

		setenv ("HOME", pw->pw_dir, 0);
		setenv ("USER", pw->pw_name, 0);
		setenv ("LOGNAME", pw->pw_name, 0);
		setenv ("SHELL", pw->pw_shell, 0);

                int rc = setgid((gid_t) pw->pw_gid);
                if (rc < 0)
		{
		}
                else
		{
			initgroups(pw->pw_name, pw->pw_gid);
		}
		setuid(pw->pw_uid);
		if (chdir(pw->pw_dir))
		{
			WLog_Print(gModuleLog, WLOG_ERROR, "chdir(%s): %s", pw->pw_dir, strerror(errno));
		}
		setsid();

		if (x11->commonModule.childProcessCallback)
		{
			x11->commonModule.childProcessCallback(x11->commonModule.childProcessCallbackData);
		}
	}
	execl(x11StartScriptQualified, x11StartScript, displayName, (char *) NULL);

	WLog_Print(gModuleLog, WLOG_ERROR, "Cannot execl() %s: %s", x11StartScriptQualified, strerror(errno));
	_exit(253);
}

int x11_rds_module_stop(RDS_MODULE_COMMON* module)
{
	rdsModuleX11* x11 = (rdsModuleX11*) module;

	if (! x11->childPid) {
		WLog_Print(gModuleLog, WLOG_ERROR, "x11 stop: not started!");
		return -1;
	}
		
	WLog_Print(gModuleLog, WLOG_INFO, "Stopping");
	kill(x11->childPid, SIGTERM);
	int waitStatus = waitpid(x11->childPid, &waitStatus, 0);
	return (waitStatus == 0) ? 0 : -1;
}


int RdsModuleEntry(RDS_MODULE_ENTRY_POINTS* pEntryPoints)
{
	pEntryPoints->Version = 1;

	pEntryPoints->New = x11_rds_module_new;
	pEntryPoints->Free = x11_rds_module_free;

	pEntryPoints->Start = x11_rds_module_start;
	pEntryPoints->Stop = x11_rds_module_stop;

	pEntryPoints->Name = "X11";

	g_Status = pEntryPoints->status;
	g_Config = pEntryPoints->config;

	WLog_Init();
	gModuleLog = WLog_Get("com.freerds.module.x11");
	WLog_SetLogLevel(gModuleLog, WLOG_DEBUG);

	return 0;
}

