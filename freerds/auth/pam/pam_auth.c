/**
 * FreeRDS: FreeRDP Remote Desktop Services (RDS)
 * PAM authentication module
 *
 * Copyright 2013 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <winpr/crt.h>
#include <winpr/path.h>

#include <security/pam_appl.h>

#include "pam_auth.h"

struct t_user_pass
{
	char user[256];
	char pass[256];
};

struct rds_auth_module_pam
{
	rdsAuthModule common;
	struct t_user_pass user_pass;
	struct pam_conv pamc;
	int pam_error;
	pam_handle_t *ph;
};

struct rds_auth_module_pam* rds_auth_module_new(void)
{
	struct rds_auth_module_pam* pam = (struct rds_auth_module_pam*) malloc(sizeof(struct rds_auth_module_pam));

	if (!pam)
		return NULL;

	ZeroMemory(pam, sizeof(struct rds_auth_module_pam));
	return pam;
}

void rds_auth_module_free(struct rds_auth_module_pam* pam)
{
	if (!pam)
		return;
	if (pam->ph) {
		pam_end(pam->ph, pam->pam_error);
	}

	free(pam);
}

static int verify_pam_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
	int i;
	struct pam_response* reply;
	struct t_user_pass* user_pass;

	reply = malloc(sizeof(struct pam_response) * num_msg);

	if (!reply)
		return -1;

	ZeroMemory(reply, sizeof(struct pam_response) * num_msg);

	for (i = 0; i < num_msg; i++)
	{
		switch (msg[i]->msg_style)
		{
			case PAM_PROMPT_ECHO_ON: /* username */
				user_pass = appdata_ptr;
				reply[i].resp = _strdup(user_pass->user);
				reply[i].resp_retcode = PAM_SUCCESS;
				break;

			case PAM_PROMPT_ECHO_OFF: /* password */
				user_pass = appdata_ptr;
				reply[i].resp = _strdup(user_pass->pass);
				reply[i].resp_retcode = PAM_SUCCESS;
				break;

			default:
				printf("unknown in verify_pam_conv\r\n");
				free(reply);
				return PAM_CONV_ERR;
		}
	}

	*resp = reply;
	return PAM_SUCCESS;
}

BOOL freerds_authenticate_pam(struct rds_auth_module_pam* pam, char* username, char* password, int* errorcode)
{
	pam->user_pass.user[0] = '\0';
	strncat(pam->user_pass.user, username, 255);
	if (password) {
		pam->user_pass.pass[0] = '\0',
		strncat(pam->user_pass.pass, password, 255);
	}
	pam->pamc.conv = &verify_pam_conv;
	pam->pamc.appdata_ptr = &(pam->user_pass);
	pam->pam_error = pam_start("freerds", 0, &(pam->pamc), &(pam->ph));

	if (pam->pam_error != PAM_SUCCESS)
	{
		if (errorcode != NULL)
			*errorcode = pam->pam_error;

		printf("pam_start failed\n");
		return FALSE;
	}

	pam->pam_error = pam_authenticate(pam->ph, 0);

	if (pam->pam_error != PAM_SUCCESS)
	{
		if (errorcode != NULL)
			*errorcode = pam->pam_error;

		printf("pam_authenticate failed: %s\n", pam_strerror(pam->ph, pam->pam_error));
		return FALSE;
	}

	pam->pam_error = pam_acct_mgmt(pam->ph, 0);

	if (pam->pam_error != PAM_SUCCESS)
	{
		if (errorcode != NULL)
			*errorcode = pam->pam_error;

		printf("pam_acct_mgmt failed: %s\n", pam_strerror(pam->ph, pam->pam_error));
		return FALSE;
	}

	return TRUE;
}
 
/**
 * FreeRDS Authentication Module Interface
 */

int rds_auth_logon_user(struct rds_auth_module_pam* pam, char* username, char* domain, char* password)
{
	BOOL auth_status;
	int error_code = 0;

	if (!pam)
		return -1;

	auth_status = freerds_authenticate_pam(pam, username, password, &error_code);

	if (!auth_status)
		return -1;

	return 0;
}

int rds_auth_module_session_start(struct rds_auth_module_pam* pam) {
	if (!pam)
		return -1;

	pam->pam_error = pam_open_session (pam->ph, 0);
	if (pam->pam_error != PAM_SUCCESS) {
		printf("pam_open_session failed: %s\n", pam_strerror(pam->ph, pam->pam_error));
		return -1;
	}

	return 0;
}

int rds_auth_module_session_stop(struct rds_auth_module_pam* pam) {
	if (!pam)
		return -1;

	pam->pam_error = pam_close_session (pam->ph, 0);
	if (PAM_SUCCESS != pam->pam_error) {
		printf("pam_close_session failed: %s", pam_strerror (pam->ph, pam->pam_error));
		return -1;
	}

	return 0;
}

int RdsAuthModuleEntry(RDS_AUTH_MODULE_ENTRY_POINTS* pEntryPoints)
{
	pEntryPoints->Version = 1;

	pEntryPoints->New = (pRdsAuthModuleNew) rds_auth_module_new;
	pEntryPoints->Free = (pRdsAuthModuleFree) rds_auth_module_free;
	pEntryPoints->SessionStart = (pRdsAuthModuleSessionStart) rds_auth_module_session_start;
	pEntryPoints->SessionStop = (pRdsAuthModuleSessionStop) rds_auth_module_session_stop;

	pEntryPoints->LogonUser = (pRdsAuthLogonUser) rds_auth_logon_user;

	return 0;
}
