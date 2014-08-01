/**
 *  FDSApiServer
 *
 *  Starts and stops the thrift server.
 *
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

#include "FDSApiServer.h"

#include <appcontext/ApplicationContext.h>
#include "FDSApiHandler.h"
#include "FDSApiMessages.h"

#include <thrift/concurrency/PosixThreadFactory.h>
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/server/TThreadPoolServer.h>
#include <thrift/server/TThreadedServer.h>
#include <thrift/transport/TSSLServerSocket.h>
#include <thrift/transport/TSSLSocket.h>
#include <thrift/transport/TTransportUtils.h>

#include <winpr/wlog.h>
#include <winpr/thread.h>
#include <winpr/stream.h>

#include <freerds/rpc.h>

using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using namespace apache::thrift::server;

using boost::shared_ptr;

namespace freerds {
	namespace sessionmanager {
		namespace fdsapi {

		static wLog * logger_FDSApiServer = WLog_Get("freerds.sessionmanager.fdsapiserver");

		shared_ptr<FDSApiHandler> FDSApiServer::mFDSApiHandler;

		int FDSApiServer::RpcConnectionAccepted(rdsRpcClient* rpcClient)
		{
			return 0;
		}

		int FDSApiServer::RpcConnectionClosed(rdsRpcClient* rpcClient)
		{
			return 0;
		}

		int FDSApiServer::RpcMessageReceived(rdsRpcClient* rpcClient, BYTE* buffer, UINT32 length)
		{
			static const std::string authToken = "HUGO";

			shared_ptr<FDSApiHandler> FDSApiHandler = FDSApiServer::mFDSApiHandler;

			FDSAPI_MESSAGE requestMsg;
			FDSAPI_MESSAGE responseMsg;
			wStream* requestStream;
			wStream* responseStream;
			int status;

			WLog_Print(logger_FDSApiServer, WLOG_DEBUG, "received message (buffer=%p, length=%u)", buffer, length);

			status = -1;

			requestStream = Stream_New(buffer, length);
			if (requestStream == NULL) return status;

			ZeroMemory(&requestMsg, sizeof(FDSAPI_MESSAGE));
			ZeroMemory(&responseMsg, sizeof(FDSAPI_MESSAGE));

			// Decode the request message.
			if (FDSAPI_DecodeMessage(requestStream, &requestMsg))
			{
				switch (requestMsg.messageId)
				{
					case FDSAPI_DISCONNECT_SESSION_REQUEST_ID:
					{
						responseMsg.messageId = FDSAPI_DISCONNECT_SESSION_RESPONSE_ID;
						responseMsg.requestId = requestMsg.requestId;

						responseMsg.u.disconnectSessionResponse.result =
							FDSApiHandler->disconnectSession(
								authToken,
								requestMsg.u.disconnectSessionRequest.sessionId,
								requestMsg.u.disconnectSessionRequest.wait);

						break;
					}

					case FDSAPI_LOGOFF_SESSION_REQUEST_ID:
					{
						responseMsg.messageId = FDSAPI_LOGOFF_SESSION_RESPONSE_ID;
						responseMsg.requestId = requestMsg.requestId;

						responseMsg.u.logoffSessionResponse.result =
							FDSApiHandler->logoffSession(
								authToken,
								requestMsg.u.logoffSessionRequest.sessionId,
								requestMsg.u.logoffSessionRequest.wait);

						break;
					}

					case FDSAPI_SHUTDOWN_SYSTEM_REQUEST_ID:
					{
						responseMsg.messageId = FDSAPI_SHUTDOWN_SYSTEM_RESPONSE_ID;
						responseMsg.requestId = requestMsg.requestId;

						responseMsg.u.shutdownSystemResponse.result =
							FDSApiHandler->shutdownSystem(
								authToken,
								requestMsg.u.shutdownSystemRequest.shutdownFlag);

						break;
					}

					case FDSAPI_ENUMERATE_SESSIONS_REQUEST_ID:
					{
						TReturnEnumerateSessions apiReturn;

						WLog_Print(logger_FDSApiServer, WLOG_DEBUG, "calling FDSAPIHandler::enumerateSessions");

						FDSApiHandler->enumerateSessions(
							apiReturn,
							authToken,
							requestMsg.u.enumerateSessionsRequest.version);

						responseMsg.messageId = FDSAPI_ENUMERATE_SESSIONS_RESPONSE_ID;
						responseMsg.requestId = requestMsg.requestId;

						responseMsg.u.enumerateSessionsResponse.result = apiReturn.returnValue;
						if (apiReturn.returnValue)
						{
							size_t count = apiReturn.sessionInfoList.size();

							FDSAPI_SESSION_INFO* pSessionInfo;

							pSessionInfo = (FDSAPI_SESSION_INFO*)malloc(count * sizeof(FDSAPI_SESSION_INFO));
							if (pSessionInfo)
							{
								for (int i = 0; i < count; i++)
								{
									pSessionInfo[i].sessionId = apiReturn.sessionInfoList.at(i).sessionId;
									pSessionInfo[i].winStationName = strdup(apiReturn.sessionInfoList.at(i).winStationName.c_str());
									pSessionInfo[i].connectState = apiReturn.sessionInfoList.at(i).connectState;
								}

								responseMsg.u.enumerateSessionsResponse.cSessions = count;
								responseMsg.u.enumerateSessionsResponse.pSessionInfo = pSessionInfo;
							}
						}

						break;
					}

					case FDSAPI_QUERY_SESSION_INFORMATION_REQUEST_ID:
					{
						TReturnQuerySessionInformation apiReturn;

						WLog_Print(logger_FDSApiServer, WLOG_DEBUG, "calling FDSAPIHandler::querySessionInformation");

						FDSApiHandler->querySessionInformation(
							apiReturn,
							authToken,
							requestMsg.u.querySessionInformationRequest.sessionId,
							requestMsg.u.querySessionInformationRequest.infoClass);

						responseMsg.messageId = FDSAPI_QUERY_SESSION_INFORMATION_RESPONSE_ID;
						responseMsg.requestId = requestMsg.requestId;

						responseMsg.u.querySessionInformationResponse.result = apiReturn.returnValue;
						if (apiReturn.returnValue)
						{
							FDSAPI_SESSION_INFO_VALUE* infoValue;

							infoValue = &responseMsg.u.querySessionInformationResponse.infoValue;

							switch (requestMsg.u.querySessionInformationRequest.infoClass)
							{
								case WTSClientProductId:
								case WTSClientProtocolType:
									infoValue->t = FDSAPI_SESSION_INFO_VALUE_UINT16;
									infoValue->u.uint16Value = apiReturn.infoValue.int16Value;
									break;

								case WTSSessionId:
								case WTSConnectState:
								case WTSClientBuildNumber:
								case WTSClientHardwareId:
									infoValue->t = FDSAPI_SESSION_INFO_VALUE_UINT32;
									infoValue->u.uint32Value = apiReturn.infoValue.int32Value;
									break;

								case WTSUserName:
								case WTSWinStationName:
								case WTSDomainName:
								case WTSClientName:
								case WTSClientAddress:
									infoValue->t = FDSAPI_SESSION_INFO_VALUE_STRING;
									infoValue->u.stringValue = strdup(apiReturn.infoValue.stringValue.c_str());
									break;

								case WTSClientDisplay:
									infoValue->t = FDSAPI_SESSION_INFO_VALUE_DISPLAY;
									infoValue->u.displayValue.displayWidth = apiReturn.infoValue.displayValue.displayWidth;
									infoValue->u.displayValue.displayHeight = apiReturn.infoValue.displayValue.displayHeight;
									infoValue->u.displayValue.colorDepth = apiReturn.infoValue.displayValue.colorDepth;
									break;

								default:
									responseMsg.u.querySessionInformationResponse.result = FALSE;
									break;
							}
						}

						break;
					}

					case FDSAPI_AUTHENTICATE_USER_REQUEST_ID:
					{
						responseMsg.messageId = FDSAPI_AUTHENTICATE_USER_RESPONSE_ID;
						responseMsg.requestId = requestMsg.requestId;

						std::string domain;
						std::string username;
						std::string password;

						if (requestMsg.u.authenticateUserRequest.domain)
						{
							domain = requestMsg.u.authenticateUserRequest.domain;
						}

						if (requestMsg.u.authenticateUserRequest.username)
						{
							username = requestMsg.u.authenticateUserRequest.username;
						}

						if (requestMsg.u.authenticateUserRequest.password)
						{
							password = requestMsg.u.authenticateUserRequest.password;
						}

						WLog_Print(logger_FDSApiServer, WLOG_DEBUG, "calling FDSAPIHandler::authenticateUser");

						responseMsg.u.authenticateUserResponse.result =
							FDSApiHandler->authenticateUser(
								authToken,
								requestMsg.u.authenticateUserRequest.sessionId,
								username,
								password,
								domain);

						break;
					}

					default:
						break;
				}			

				// Send the response message.
				responseStream = FDSAPI_EncodeMessage(&responseMsg);
				if (responseStream)
				{
					status = freerds_rpc_client_send_message(rpcClient, Stream_Buffer(responseStream), Stream_Length(responseStream));
					Stream_Free(responseStream, TRUE);
				}
			}

			FDSAPI_FreeMessage(&requestMsg);
			FDSAPI_FreeMessage(&responseMsg);

			Stream_Free(requestStream, FALSE);

			return status;
		}

		FDSApiServer::FDSApiServer()
		{
			if (!InitializeCriticalSectionAndSpinCount(&mCSection, 0x00000400))
			{
				WLog_Print(logger_FDSApiServer, WLOG_ERROR, "FDSApiServer: InitializeCriticalSectionAndSpinCount failed!");
			}
			mServerThread = NULL;
			mPort = 9091;

			shared_ptr<FDSApiHandler> handler(new FDSApiHandler());

			mFDSApiHandler = handler;

			mRpcServer = freerds_rpc_server_new("FDSAPI");
			mRpcServer->custom = (void*) this;
			mRpcServer->ConnectionAccepted = FDSApiServer::RpcConnectionAccepted;
			mRpcServer->ConnectionClosed = FDSApiServer::RpcConnectionClosed;
			mRpcServer->MessageReceived = FDSApiServer::RpcMessageReceived;
		}

		FDSApiServer::~FDSApiServer()
		{
		}

		void FDSApiServer::setServer(boost::shared_ptr<apache::thrift::server::TServer> server)
		{
			mServer = server;
		}

		void FDSApiServer::setPort(DWORD port)
		{
			mPort = port;
		}

		DWORD FDSApiServer::getPort()
		{
			return mPort;
		}

		CRITICAL_SECTION* FDSApiServer::getCritSection()
		{
			return &mCSection;
		}

		void FDSApiServer::fireSessionEvent(UINT32 sessionId, UINT32 stateChange)
		{
			FDSAPI_MESSAGE msg;
			wStream *s;

			WLog_Print(logger_FDSApiServer, WLOG_DEBUG, "sessionId=%u, stateChange=%u", sessionId, stateChange);

			// Broadcast a FDSAPI_SESSION_EVENT message to every client.
			ZeroMemory(&msg, sizeof(msg));
			msg.messageId = FDSAPI_SESSION_EVENT_ID;
			msg.u.sessionEvent.sessionId = sessionId;
			msg.u.sessionEvent.stateChange = stateChange;

			s = FDSAPI_EncodeMessage(&msg);
			if (s)
			{
				freerds_rpc_server_broadcast_message(mRpcServer, Stream_Buffer(s), Stream_Length(s));
			}
		}

		void FDSApiServer::serverThread(void * param)
		{
			FDSApiServer* server = (FDSApiServer*) param;

			shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());
			shared_ptr<FDSApiHandler> handler(new FDSApiHandler());
			shared_ptr<TProcessor> processor(new fdsapiProcessor(handler));
			shared_ptr<TServerTransport> serverTransport(new TServerSocket(server->getPort()));
			shared_ptr<TTransportFactory> transportFactory(new TBufferedTransportFactory());

			shared_ptr<TServer> thriftServer(new TSimpleServer(processor, serverTransport, transportFactory, protocolFactory));
			server->setServer(thriftServer);
			LeaveCriticalSection(server->getCritSection());
			WLog_Print(logger_FDSApiServer, WLOG_INFO, "FDSApiServer started on port %d",server->getPort());
			thriftServer->serve();
			WLog_Print(logger_FDSApiServer, WLOG_INFO, "FDSApiServer stopped.");
		 }

		 void FDSApiServer::startFDSApi()
		 {
			EnterCriticalSection(&mCSection);
			freerds_rpc_server_start(mRpcServer);
			mServerThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) FDSApiServer::serverThread, (void*) this, 0, NULL);
			ResumeThread(mServerThread);
			EnterCriticalSection(&mCSection);
			LeaveCriticalSection(&mCSection);
		 }

		 void FDSApiServer::stopFDSApi()
		 {
			 if (mServer != NULL)
			 {
				 WLog_Print(logger_FDSApiServer, WLOG_INFO, "Stopping FDSApiServer ...");
				 freerds_rpc_server_stop(mRpcServer);
				 mServer->stop();
				 WaitForSingleObject(mServerThread,INFINITE);
				 CloseHandle(mServerThread);
				 mServerThread = NULL;
				 mServer.reset();
			 }
		 }

		}
	}
}


