/**
 * FreeRDS: FreeRDP Remote Desktop Services (RDS)
 *
 * Copyright 2013-2014 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#include "freerds.h"

#include <winpr/crt.h>
#include <winpr/file.h>
#include <winpr/path.h>
#include <winpr/synch.h>
#include <winpr/thread.h>
#include <winpr/wlog.h>

#include <freerdp/freerdp.h>
#include <freerdp/listener.h>

#include <errno.h>

#ifndef _WIN32
#include <sys/select.h>
#include <sys/signal.h>
#endif

#include <freerds/auth.h>

#include "rpc.h"
#include "channels.h"

#define TAG "freerds.server.process"

extern rdsServer* g_Server;

int freerds_init_client(HANDLE hClientPipe, rdpSettings* settings, wStream* s)
{
	RDS_MSG_CAPABILITIES capabilities;

	ZeroMemory(&capabilities, sizeof(RDS_MSG_CAPABILITIES));
	capabilities.type = RDS_CLIENT_CAPABILITIES;
	capabilities.Version = 1;
	capabilities.DesktopWidth = settings->DesktopWidth;
	capabilities.DesktopHeight = settings->DesktopHeight;
	capabilities.KeyboardLayout = settings->KeyboardLayout;
	capabilities.KeyboardType = settings->KeyboardType;
	capabilities.KeyboardSubType = settings->KeyboardSubType;

	freerds_write_capabilities(s, &capabilities);

	return freerds_named_pipe_write(hClientPipe, Stream_Buffer(s), Stream_GetPosition(s));
}

BOOL freerds_peer_capabilities(freerdp_peer* client)
{
	return TRUE;
}

BOOL freerds_peer_post_connect(freerdp_peer* client)
{
	int error_code;
	char* endpoint;
	UINT32 ColorDepth;
	UINT32 DesktopWidth;
	UINT32 DesktopHeight;
	rdpSettings* settings;
	rdsConnection* connection;
	rdsBackendConnector* connector;
	FDSAPI_LOGON_USER_REQUEST request;
	FDSAPI_LOGON_USER_RESPONSE response;

	settings = client->settings;
	connection = (rdsConnection*) client->context;
	connector = connection->connector;

	WLog_INFO(TAG, "Client %s is connected", client->hostname);

	if (settings->Username && settings->Password)
		settings->AutoLogonEnabled = TRUE;

	if (client->settings->AutoLogonEnabled)
	{
		WLog_INFO(TAG, "Client wants to login automatically as %s\\%s",
			client->settings->Domain ? client->settings->Domain : "",
			client->settings->Username);
	}

	DesktopWidth = settings->DesktopWidth;
	DesktopHeight = settings->DesktopHeight;
	ColorDepth = settings->ColorDepth;

	if (settings->MultifragMaxRequestSize < 0x3F0000)
		settings->NSCodec = FALSE; /* NSCodec compressor does not support fragmentation yet */

	WLog_INFO(TAG, "Client requested desktop: %dx%dx%d",
		settings->DesktopWidth, settings->DesktopHeight, settings->ColorDepth);

	if ((DesktopWidth != settings->DesktopWidth) || (DesktopHeight != settings->DesktopHeight)
			|| (ColorDepth != settings->ColorDepth))
	{
		WLog_INFO(TAG, "Resizing desktop to %dx%dx%d", DesktopWidth, DesktopHeight, ColorDepth);

		settings->DesktopWidth = DesktopWidth;
		settings->DesktopHeight = DesktopHeight;
		settings->ColorDepth = ColorDepth;

		client->update->DesktopResize(client->update->context);
	}

	freerds_channels_post_connect(connection);

	ZeroMemory(&request, sizeof(request));

	request.ConnectionId = connection->id;
	request.User = settings->Username;
	request.Password = settings->Password;
	request.Domain = settings->Domain;
	request.DesktopWidth = settings->DesktopWidth;
	request.DesktopHeight = settings->DesktopHeight;
	request.ColorDepth = settings->ColorDepth;
	request.ClientName = settings->ClientHostname;
	request.ClientAddress = settings->ClientAddress;
	request.ClientBuild = settings->ClientBuild;
	request.ClientProductId = 1;
	request.ClientHardwareId = 0;
	request.ClientProtocolType = 2;

	error_code = freerds_icp_LogonUser(&request, &response);

	endpoint = response.ServiceEndpoint;

	if (error_code != 0)
	{
		WLog_ERR(TAG, "freerds_icp_LogonUser failed %d", error_code);
		return FALSE;
	}

	if (!connector)
		connection->connector = connector = freerds_connector_new(connection);

	connector->Endpoint = _strdup(endpoint);

	if (!freerds_connector_connect(connector))
		return FALSE;

	return TRUE;
}

BOOL freerds_peer_activate(freerdp_peer* client)
{
	rdpSettings* settings;
	rdsConnection* connection = (rdsConnection*) client->context;

	WLog_INFO(TAG, "Client Activated");

	settings = client->settings;

	if (settings->KeyboardType == 7)
	{
		settings->KeyboardType = 4;
	}

	if (settings->ClientDir && (strcmp(settings->ClientDir, "librdp") == 0))
	{
		/* Hack for Mac/iOS/Android Microsoft RDP clients */

		settings->RemoteFxCodec = FALSE;

		settings->NSCodec = FALSE;
		settings->NSCodecAllowSubsampling = FALSE;

		settings->SurfaceFrameMarkerEnabled = FALSE;
	}

	connection->codecMode = (settings->RemoteFxCodec && settings->FrameAcknowledge &&
						settings->SurfaceFrameMarkerEnabled);

	if (connection->encoder)
	{
		freerds_encoder_free(connection->encoder);
		connection->encoder = NULL;
	}

	connection->encoder = freerds_encoder_new(connection,
		settings->DesktopWidth, settings->DesktopHeight, settings->ColorDepth);

	return TRUE;
}

void freerds_input_synchronize_event(rdpInput* input, UINT32 flags)
{
	rdsConnection* connection = (rdsConnection*) input->context;
	rdsBackend* backend = (rdsBackend *)connection->connector;

	if (backend)
	{
		if (backend->client->SynchronizeKeyboardEvent)
		{
			backend->client->SynchronizeKeyboardEvent(backend, flags);
		}
	}
}

void freerds_input_keyboard_event(rdpInput* input, UINT16 flags, UINT16 code)
{
	rdsConnection* connection = (rdsConnection*) input->context;
	rdsBackend* backend = (rdsBackend *)connection->connector;

	if (backend)
	{
		if (backend->client->ScancodeKeyboardEvent)
		{
			backend->client->ScancodeKeyboardEvent(backend, flags, code, connection->settings->KeyboardType);
		}
	}
}

void freerds_input_unicode_keyboard_event(rdpInput* input, UINT16 flags, UINT16 code)
{
	rdsConnection* connection = (rdsConnection*) input->context;
	rdsBackend* backend = (rdsBackend *)connection->connector;

	if (backend)
	{
		if (backend->client->UnicodeKeyboardEvent)
		{
			backend->client->UnicodeKeyboardEvent(backend, flags, code);
		}
	}
}

void freerds_input_mouse_event(rdpInput* input, UINT16 flags, UINT16 x, UINT16 y)
{
	rdsConnection* connection = (rdsConnection*) input->context;
	rdsBackend* backend = (rdsBackend *)connection->connector;

	if (backend)
	{
		if (backend->client->MouseEvent)
		{
			backend->client->MouseEvent(backend, flags, x, y);
		}
	}
}

void freerds_input_extended_mouse_event(rdpInput* input, UINT16 flags, UINT16 x, UINT16 y)
{
	rdsConnection* connection = (rdsConnection*) input->context;
	rdsBackend* backend = (rdsBackend *)connection->connector;

	if (backend)
	{
		if (backend->client->ExtendedMouseEvent)
		{
			backend->client->ExtendedMouseEvent(backend, flags, x, y);
		}
	}
}

void freerds_input_register_callbacks(rdpInput* input)
{
	input->SynchronizeEvent = freerds_input_synchronize_event;
	input->KeyboardEvent = freerds_input_keyboard_event;
	input->UnicodeKeyboardEvent = freerds_input_unicode_keyboard_event;
	input->MouseEvent = freerds_input_mouse_event;
	input->ExtendedMouseEvent = freerds_input_extended_mouse_event;
}

void freerds_update_frame_acknowledge(rdpContext* context, UINT32 frameId)
{
	SURFACE_FRAME* frame;
	rdsConnection* connection = (rdsConnection*) context;

	frame = (SURFACE_FRAME*) ListDictionary_GetItemValue(connection->FrameList, (void*) (size_t) frameId);

	if (frame)
	{
		ListDictionary_Remove(connection->FrameList, (void*) (size_t) frameId);
		free(frame);
	}
}

void freerds_suppress_output(rdpContext* context, BYTE allow, RECTANGLE_16* area)
{
	rdsConnection* connection = (rdsConnection*) context;
	rdsBackend* backend = (rdsBackend *)connection->connector;

	if (backend && backend->client && backend->client->SuppressOutput)
		backend->client->SuppressOutput(backend, allow);
}

BOOL freerds_client_process_switch_session(rdsConnection* connection, wMessage* message)
{
	int error = 0;
	BOOL status = FALSE;
	rdsBackendConnector* connector = NULL;
	FDSAPI_SWITCH_SERVICE_ENDPOINT_REQUEST* request;
	FDSAPI_SWITCH_SERVICE_ENDPOINT_RESPONSE response;

	request = (FDSAPI_SWITCH_SERVICE_ENDPOINT_REQUEST*) message->wParam;

	freerds_connector_free(connection->connector);
	connection->connector = connector = freerds_connector_new(connection);
	connector->Endpoint = _strdup(request->ServiceEndpoint);

	status = freerds_connector_connect(connector);

	response.status = status ? 0 : 1;
	response.callId = request->callId;
	response.msgType = FDSAPI_RESPONSE_ID(request->msgType);

	error = freerds_icp_SwitchServiceEndpointResponse(&response);

	free(request->ServiceEndpoint);
	free(request);

	if (error != 0)
	{
		WLog_ERR(TAG, "problem occured while switching session");
		return FALSE;
	}

	return TRUE;
}

BOOL freerds_client_process_logoff(rdsConnection* connection, wMessage* message)
{
	int status = 0;
	FDSAPI_LOGOFF_USER_REQUEST* request;
	FDSAPI_LOGOFF_USER_RESPONSE response;

	request = (FDSAPI_LOGOFF_USER_REQUEST*) message->wParam;

	if (connection->connector)
	{
		freerds_connector_free(connection->connector);
		connection->connector = NULL;
	}

	connection->client->Close(connection->client);

	response.status = 0;
	response.callId = request->callId;
	response.msgType = FDSAPI_RESPONSE_ID(request->msgType);

	status = freerds_icp_LogoffUserResponse(&response);
	free(request);

	return FALSE;
}

BOOL freerds_client_process_channel_endpoint_open(rdsConnection* connection, wMessage* message)
{
	int status = 0;
	rdsChannel* channel;
	freerdp_peer* client;
	FDSAPI_CHANNEL_ENDPOINT_OPEN_REQUEST* request;
	FDSAPI_CHANNEL_ENDPOINT_OPEN_RESPONSE response;

	request = (FDSAPI_CHANNEL_ENDPOINT_OPEN_REQUEST*) message->wParam;

	channel = freerds_channel_new(connection, request->ChannelName);

	if (!channel)
		return FALSE;

	freerds_channel_server_add(connection->channelServer, channel);

	response.status = 0;
	response.callId = request->callId;
	response.msgType = FDSAPI_RESPONSE_ID(request->msgType);

	response.ChannelPort = channel->port;
	response.ChannelGuid = _strdup(channel->guidString);

	status = freerds_icp_ChannelEndpointOpenResponse(&response);

	freerds_rpc_msg_free(request->msgType, request);
	free(request);

	if (WaitForSingleObject(channel->readyEvent, 5000) != WAIT_OBJECT_0)
	{
		freerds_channel_free(channel);
		return FALSE;
	}

	freerds_channel_server_remove(connection->channelServer, channel);

	client = connection->client;

	channel->rdpChannel = client->VirtualChannelOpen(client, channel->name, 0);
	client->VirtualChannelSetData(client, channel->rdpChannel, (void*) channel);

	freerds_client_add_channel(connection, channel);

	return TRUE;
}

BOOL freerds_client_process_notification(rdsConnection* connection, wMessage* message)
{
	BOOL status = FALSE;

	switch (message->id)
	{
		case FDSAPI_SWITCH_SERVICE_ENDPOINT_REQUEST_ID:
			status = freerds_client_process_switch_session(connection, message);
			break;

		case FDSAPI_LOGOFF_USER_REQUEST_ID:
			status = freerds_client_process_logoff(connection, message);
			break;

		case FDSAPI_CHANNEL_ENDPOINT_OPEN_REQUEST_ID:
			status = freerds_client_process_channel_endpoint_open(connection, message);
			break;

		default:
			WLog_ERR(TAG, "%s: unhandled message 0x%x", __FUNCTION__, message->id);
			break;
	}

	return status;
}

void* freerds_connection_main_thread(void* arg)
{
	DWORD status;
	DWORD nCount;
	HANDLE events[128];
	BOOL bServerClose;
	HANDLE ClientEvent;
	HANDLE ChannelEvent;
	HANDLE LocalTermEvent;
	HANDLE GlobalTermEvent;
	HANDLE NotificationEvent;
	rdsConnection* connection;
	rdpSettings* settings;
	rdsBackendConnector* connector = NULL;
	freerdp_peer* client = (freerdp_peer*) arg;
#ifndef _WIN32
	sigset_t set;
	int ret;
#endif

	WLog_INFO(TAG, "We've got a client %s", client->hostname);

	bServerClose = FALSE;

	connection = (rdsConnection*) client->context;
	settings = client->settings;

	freerds_server_add_connection(g_Server, connection);

	settings->RdpSecurity = TRUE;
	settings->TlsSecurity = TRUE;

	/**
	 * Disable NLA Security for now.
	 * TODO: make this a configurable option.
	 */
	settings->NlaSecurity = FALSE;

	client->Capabilities = freerds_peer_capabilities;
	client->PostConnect = freerds_peer_post_connect;
	client->Activate = freerds_peer_activate;

	client->Initialize(client);

	freerds_input_register_callbacks(client->input);

	client->update->SurfaceFrameAcknowledge = freerds_update_frame_acknowledge;
	client->update->SuppressOutput = freerds_suppress_output;

	ClientEvent = client->GetEventHandle(client);
	ChannelEvent = WTSVirtualChannelManagerGetEventHandle(connection->vcm);

	GlobalTermEvent = g_get_term_event();
	LocalTermEvent = connection->TermEvent;
	NotificationEvent = MessageQueue_Event(connection->notifications);

#ifndef _WIN32
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	ret = pthread_sigmask(SIG_BLOCK, &set, NULL);
	if (0 != ret)
		WLog_ERR(TAG, "couldn't block SIGPIPE");
#endif

	while (1)
	{
		nCount = 0;
		events[nCount++] = ClientEvent;
		events[nCount++] = ChannelEvent;
		events[nCount++] = GlobalTermEvent;
		events[nCount++] = LocalTermEvent;
		events[nCount++] = NotificationEvent;

		if (client->activated)
		{
			connector = (rdsBackendConnector*) connection->connector;

			if (connector && connector->GetEventHandles)
				connector->GetEventHandles((rdsBackend*) connector, events, &nCount);
		}

		freerds_client_get_channel_event_handles(connection, events, &nCount);

		status = WaitForMultipleObjects(nCount, events, FALSE, INFINITE);

		if (WaitForSingleObject(GlobalTermEvent, 0) == WAIT_OBJECT_0)
		{
			WLog_INFO(TAG, "GlobalTermEvent");
			break;
		}

		if (WaitForSingleObject(LocalTermEvent, 0) == WAIT_OBJECT_0)
		{
			WLog_INFO(TAG, "LocalTermEvent");
			break;
		}

		if (WaitForSingleObject(ClientEvent, 0) == WAIT_OBJECT_0)
		{
			if (client->CheckFileDescriptor(client) != TRUE)
			{
				WLog_ERR(TAG, "Failed to check freerdp file descriptor");
				break;
			}
		}

		if (WaitForSingleObject(ChannelEvent, 0) == WAIT_OBJECT_0)
		{
			if (WTSVirtualChannelManagerCheckFileDescriptor(connection->vcm) != TRUE)
			{
				WLog_ERR(TAG, "WTSVirtualChannelManagerCheckFileDescriptor failure");
				break;
			}
		}

		freerds_client_check_channel_event_handles(connection);

		if (client->activated)
		{
			if (connector && connector->CheckEventHandles)
			{
				if (connector->CheckEventHandles((rdsBackend*) connector) < 0)
				{
					WLog_ERR(TAG, "ModuleClient->CheckEventHandles failure");
					bServerClose = TRUE;
					break;
				}
			}
		}

		if (WaitForSingleObject(NotificationEvent, 0) == WAIT_OBJECT_0)
		{
			wMessage message;

			MessageQueue_Peek(connection->notifications, &message, TRUE);

			if (!freerds_client_process_notification(connection, &message))
				break;
		}
	}

	WLog_INFO(TAG, "Client %s disconnected.", client->hostname);

	if (connection->connector)
	{
		FDSAPI_DISCONNECT_USER_REQUEST request;
		FDSAPI_DISCONNECT_USER_RESPONSE response;

		freerds_connector_free(connection->connector);
		connection->connector = NULL;

		request.ConnectionId = connection->id;
		freerds_icp_DisconnectUserSession(&request, &response);
	}

	if (bServerClose)
	{
		client->Close(client);
	}
	else
	{
		client->Disconnect(client);
	}
	freerds_server_remove_connection(g_Server, connection->id);

	freerdp_peer_context_free(client);
	freerdp_peer_free(client);

	return NULL;
}

