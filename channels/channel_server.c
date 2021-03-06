/**
 * FreeRDS: FreeRDP Remote Desktop Services (RDS)
 * FreeRDS channel server for hosting virtual channel plugins
 *
 * Copyright 2014 Dell Software <Mike.McDonald@software.dell.com>
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

#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/pam_appl.h>

#include <winpr/collections.h>
#include <winpr/file.h>
#include <winpr/library.h>
#include <winpr/path.h>
#include <winpr/string.h>
#include <winpr/wlog.h>
#include <winpr/wtsapi.h>
#include <winpr/wtypes.h>

#include <freerds/channel_plugin.h>

#include "channel_utils.h"

#define USE_IMPERSONATION 1

static const char *g_standardPlugins[] =
{
	"libfreerds-cliprdr-plugin",
	"libfreerds-rdpdr-plugin",
	"libfreerds-rdpsnd-plugin"
};
static int g_standardPluginsCount = sizeof(g_standardPlugins) / sizeof(const char *);

static wArrayList *g_pluginList;

static wLog *g_logger;

static ULONG g_ulSessionId;
static ULONG g_ulX11DisplayNum;

static VCPlugin *load_vc_plugin(const char *name)
{
	HMODULE hModule = NULL;
	LPVCPluginEntryPoint pEntryPoint = NULL;
	VCPlugin *pVCPlugin = NULL;
	char path[256];

	WLog_Print(g_logger, WLOG_DEBUG, "Loading plugin '%s'", name);

	sprintf(path, "%s.so", name);

	hModule = LoadLibrary(path);
	if (!hModule)
	{
		WLog_Print(g_logger, WLOG_ERROR, "Failed to load plugin '%s'", name);
		goto FAIL;
	}

	pEntryPoint = (LPVCPluginEntryPoint) GetProcAddress(hModule, "VCPluginEntry");
	if (!pEntryPoint)
	{
		WLog_Print(g_logger, WLOG_ERROR, "Failed to get entry point for plugin '%s'", name);
		goto FAIL;
	}

	pVCPlugin = (VCPlugin *) malloc(sizeof(VCPlugin));
	if (!pVCPlugin)
	{
		WLog_Print(g_logger, WLOG_ERROR, "Failed to allocate memory");
		goto FAIL;
	}

	ZeroMemory(pVCPlugin, sizeof(VCPlugin));

	pVCPlugin->hModule = hModule;
	pVCPlugin->sessionId = g_ulSessionId;
	pVCPlugin->x11DisplayNum = g_ulX11DisplayNum;

	if (!pEntryPoint(pVCPlugin))
	{
		WLog_Print(g_logger, WLOG_ERROR, "Failed to initialize plugin '%s'", name);
		goto FAIL;
	}

	if (pVCPlugin->OnPluginInitialize)
	{
		if (!pVCPlugin->OnPluginInitialize(pVCPlugin))
		{
			WLog_Print(g_logger, WLOG_ERROR, "Failed to initialize plugin '%s'", name);
			goto FAIL;
		}
	}

	WLog_Print(g_logger, WLOG_DEBUG, "Successfully loaded plugin '%s'", name);

	return pVCPlugin;

FAIL:
	if (hModule)
	{
		FreeLibrary(hModule);
	}

	if (pVCPlugin)
	{
		free(pVCPlugin);
	}

	return NULL;
}

static void load_vc_plugins()
{
	int i;
	char *delimiter;
	HANDLE hFindFile;
	char filePath[MAX_PATH];
	char pluginsDir[MAX_PATH];
	WIN32_FIND_DATA win32FindData;

	if (g_pluginList) return;

	/* Initialize the list of plugins. */
	g_pluginList = ArrayList_New(FALSE);
	
	/* Load standard plugins (e.g., CLIPRDR, RDPDR, RDPSND, etc.). */
	for (i = 0; i < g_standardPluginsCount; i++)
	{
		VCPlugin *pVCPlugin;

		pVCPlugin = load_vc_plugin(g_standardPlugins[i]);

		if (pVCPlugin)
		{
			ArrayList_Add(g_pluginList, pVCPlugin);
		}
	}

	/* Load third party plugins. */
	GetModuleFileName(NULL, pluginsDir, sizeof(pluginsDir));
	if ((delimiter = strrchr(pluginsDir, '/')) != NULL)
	{
		sprintf(delimiter + 1, "plugins");
	}

	WLog_Print(g_logger, WLOG_DEBUG, "pluginsDir=%s", pluginsDir);

	sprintf(filePath, "%s/*", pluginsDir);
	hFindFile = FindFirstFile(filePath, &win32FindData);

	if (hFindFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			char *fileExt;
			VCPlugin* pVCPlugin;

			if (strcmp(win32FindData.cFileName, ".") == 0) continue;
			if (strcmp(win32FindData.cFileName, "..") == 0) continue;

			sprintf(filePath, "%s/%s", pluginsDir, win32FindData.cFileName);

			fileExt = strstr(filePath, ".so");
			if (fileExt && (strlen(fileExt) == 3))
			{
				*fileExt = '\0';
			}

			pVCPlugin = load_vc_plugin(filePath);

			if (pVCPlugin)
			{
				ArrayList_Add(g_pluginList, pVCPlugin);
			}
		}
		while (FindNextFile(hFindFile, &win32FindData));

		FindClose(hFindFile);
	}
}

static void unload_vc_plugins()
{
	if (!g_pluginList) return;

	while (ArrayList_Count(g_pluginList) > 0)
	{
		VCPlugin *pVCPlugin;

		pVCPlugin = (VCPlugin *) ArrayList_GetItem(g_pluginList, 0);
		ArrayList_RemoveAt(g_pluginList, 0);

		if (pVCPlugin->OnPluginTerminate)
		{
			pVCPlugin->OnPluginTerminate(pVCPlugin);
		}

		FreeLibrary(pVCPlugin->hModule);

		free(pVCPlugin);
	}

	ArrayList_Free(g_pluginList);

	g_pluginList = NULL;
}

static void pam_get_service_name(char *service_name, int service_name_length)
{
	if (PathFileExistsA("/etc/pam.d/freerds"))
	{
		strncpy(service_name, "freerds", service_name_length);
	}
	else if (PathFileExistsA("/etc/pam.d/common-session"))
	{
		strncpy(service_name, "common-session", service_name_length);
	}
	else
	{
		strncpy(service_name, "gdm", service_name_length);
	}
}

static int pam_conversation(
	int num_msgs,
	const struct pam_message **msg,
	struct pam_response **resp,
	void *data
)
{
	return PAM_SUCCESS;
}

static uid_t g_savedUID;
static gid_t g_savedGID;

static BOOL impersonate_user(const char *username)
{
	struct passwd *passwd;

	if (!username) return FALSE;

	WLog_Print(g_logger, WLOG_INFO, "impersonating user '%s'", username);

	passwd = getpwnam(username);
	if (passwd)
	{
		g_savedUID = geteuid();
		g_savedGID = getegid();

		initgroups(passwd->pw_name, passwd->pw_gid);
		seteuid(passwd->pw_uid);
		setegid(passwd->pw_gid);
	}

	return TRUE;
}

static void revert_to_self()
{
	struct passwd *passwd;

	WLog_Print(g_logger, WLOG_INFO, "reverting to self");

	passwd = getpwuid(0);
	if (passwd)
	{
		seteuid(g_savedUID);
		setegid(g_savedGID);
		initgroups(passwd->pw_name, passwd->pw_gid);
	}
}

static void fire_session_event(int event)
{
	const char *username;
	BOOL impersonate;
	int count;
	int i;

	impersonate = FALSE;

	username = getenv("USER");

	/* Invoke PAM to deliver open_session and close_session */
	if ((event == WTS_EVENT_LOGON) || (event == WTS_EVENT_LOGOFF))
	{
		char service_name[128];
		struct pam_conv pamc;
		pam_handle_t *pamh;
		int pam_status;

		if (username && (strlen(username) > 0))
		{
			pam_get_service_name(service_name, sizeof(service_name));

			pamc.conv = &pam_conversation;
			pamc.appdata_ptr = NULL;

			pam_status = pam_start(service_name, username, &pamc, &pamh);
			if (pam_status == PAM_SUCCESS)
			{
				switch (event)
				{
					case WTS_EVENT_LOGON:
						pam_open_session(pamh, PAM_SILENT);
						break;

					case WTS_EVENT_LOGOFF:
						pam_close_session(pamh, PAM_SILENT);
						break;

					default:
						break;
				}

				pam_end(pamh, PAM_SUCCESS);
			}
			else
			{
				WLog_Print(g_logger, WLOG_ERROR, "error calling pam_start");
			}
		}
	}

#if USE_IMPERSONATION
	/* Impersonate the logged on user. */
	impersonate = impersonate_user(username);
#endif

	/* Deliver the event to every plugin. */
	count = ArrayList_Count(g_pluginList);

	for (i = 0; i < count; i++)
	{
		VCPlugin *pVCPlugin;

		pVCPlugin = (VCPlugin *) ArrayList_GetItem(g_pluginList, i);

		/* Deliver the event. */
		switch (event)
		{
			case WTS_EVENT_CREATE:
				if (pVCPlugin->OnSessionCreate)
				{
					pVCPlugin->OnSessionCreate(pVCPlugin);
				}
				break;

			case WTS_EVENT_DELETE:
				if (pVCPlugin->OnSessionDelete)
				{
					pVCPlugin->OnSessionDelete(pVCPlugin);
				}
				break;

			case WTS_EVENT_CONNECT:
				if (pVCPlugin->OnSessionConnect)
				{
					pVCPlugin->OnSessionConnect(pVCPlugin);
				}
				break;

			case WTS_EVENT_DISCONNECT:
				if (pVCPlugin->OnSessionDisconnect)
				{
					pVCPlugin->OnSessionDisconnect(pVCPlugin);
				}
				break;

			case WTS_EVENT_LOGON:
				if (pVCPlugin->OnSessionLogon)
				{
					pVCPlugin->OnSessionLogon(pVCPlugin);
				}
				break;

			case WTS_EVENT_LOGOFF:
				if (pVCPlugin->OnSessionLogoff)
				{
					pVCPlugin->OnSessionLogoff(pVCPlugin);
				}
				break;

			default:
				break;
		}
	}

	/* Stop impersonatation. */
	if (impersonate)
	{
		revert_to_self();
	}
}

static void process_ts_events()
{
	WTS_CONNECTSTATE_CLASS sessionState;

	sessionState = WTSConnected;

	fire_session_event(WTS_EVENT_CREATE);
	fire_session_event(WTS_EVENT_CONNECT);

	for (;;)
	{
		static DWORD dwEventMask =
			WTS_EVENT_CONNECT |
			WTS_EVENT_DISCONNECT |
			WTS_EVENT_LOGON |
			WTS_EVENT_LOGOFF;

		WTS_CONNECTSTATE_CLASS newSessionState;
		DWORD dwEventFlags;

		newSessionState = channel_utils_get_session_state();

		WLog_Print(g_logger, WLOG_DEBUG, "Session %lu changed state from %u to %u", g_ulSessionId, sessionState, newSessionState);

		if (newSessionState != sessionState)
		{
			switch (newSessionState)
			{
				case WTSConnected:
					WLog_Print(g_logger, WLOG_DEBUG, "Firing connect event");
					fire_session_event(WTS_EVENT_CONNECT);
					break;
				case WTSDisconnected:
					WLog_Print(g_logger, WLOG_DEBUG, "Firing disconnect event");
					fire_session_event(WTS_EVENT_DISCONNECT);
					break;
				case WTSActive:
					if (sessionState == WTSDisconnected)
					{
						WLog_Print(g_logger, WLOG_DEBUG, "Firing connect event");
						fire_session_event(WTS_EVENT_CONNECT);
					}
					WLog_Print(g_logger, WLOG_DEBUG, "Firing logon event");
					fire_session_event(WTS_EVENT_LOGON);
					break;
				default:
					break;
			}

			sessionState = newSessionState;
		}

		if (!WTSWaitSystemEvent(WTS_CURRENT_SERVER_HANDLE, dwEventMask, &dwEventFlags))
		{
			WLog_Print(g_logger, WLOG_ERROR, "Error waiting on WTS event");
			break;
		}

		WLog_Print(g_logger, WLOG_DEBUG, "WTSWaitSystemEvent for session %lu complete with flags 0x%lx", g_ulSessionId, dwEventFlags);
	}

	fire_session_event(WTS_EVENT_DELETE);
}

void shutdown(int signal)
{
	WLog_Print(g_logger, WLOG_DEBUG, "Shutdown due to signal %d\n", signal);

	fire_session_event(WTS_EVENT_LOGOFF);
	fire_session_event(WTS_EVENT_DELETE);

	exit(0);
}

int main(int argc, char **argv)
{
	g_logger = WLog_Get("freerds.channels.server");

	g_ulSessionId = channel_utils_get_session_id();
	if (g_ulSessionId == 0)
	{
		WLog_Print(g_logger, WLOG_ERROR, "Channel server cannot be run in session 0");
		return 1;
	}

	g_ulX11DisplayNum = channel_utils_get_x11_display_num();
	if (g_ulX11DisplayNum == 0)
	{
		WLog_Print(g_logger, WLOG_ERROR, "Channel server cannot run in X11 display 0");
		return 1;
	}

	WLog_Print(g_logger, WLOG_INFO, "Channel server started in session %lu, X11 display %lu", g_ulSessionId, g_ulX11DisplayNum);

	signal(SIGINT, shutdown);
	signal(SIGKILL, shutdown);
	signal(SIGTERM, shutdown);

	load_vc_plugins();

	process_ts_events();

	unload_vc_plugins();

	return 0;
}

