/**
 * Callback Handlers for Modules
 *
 * Copyright 2013 Thinstuff Technologies GmbH
 * Copyright 2013 DI (FH) Martin Haimberger <martin.haimberger@thinstuff.at>
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

#include "TaskModuleShutdown.h"
#include <winpr/wlog.h>
#include <appcontext/ApplicationContext.h>
#include <call/CallOutLogOffUserSession.h>


namespace freerds
{
	namespace sessionmanager
	{
		namespace module
		{
			static wLog* logger_CallBacks = WLog_Get("freerds.SessionManager.module.taskshutdown");

			void TaskModuleShutdown::run() {
				long connectionId = APP_CONTEXT.getConnectionStore()->getConnectionIdForSessionId(mSessionId);
				if (connectionId == 0) {
					// no connection found for this session ... just shut down!
					stopSession();
				} else {
					callNS::CallOutLogOffUserSession logoffSession;
					logoffSession.setConnectionId(connectionId);
					logoffSession.encodeRequest();
					APP_CONTEXT.getRpcOutgoingQueue()->addElement(&logoffSession);
					WaitForSingleObject(logoffSession.getAnswerHandle(),INFINITE);
					if (logoffSession.getResult() == 0) {
						// no error
						logoffSession.decodeResponse();
						if (logoffSession.isLoggedOff()) {
							stopSession();
							APP_CONTEXT.getConnectionStore()->removeConnection(connectionId);
						} else {
							WLog_Print(logger_CallBacks, WLOG_ERROR, "CallOutLogOffUserSession reported that logoff in freerds was not successful!");
						}
					} else {
						// report error
						WLog_Print(logger_CallBacks, WLOG_ERROR, "CallOutLogOffUserSession reported error %d!", logoffSession.getResult());
					}
				}
			}

			void TaskModuleShutdown::setSessionId(long sessionId) {
				mSessionId = sessionId;
			}

			void TaskModuleShutdown::stopSession() {
				sessionNS::SessionPtr session = APP_CONTEXT.getSessionStore()->getSession(mSessionId);
				if (!session) {
					session->stopModule();
					APP_CONTEXT.getSessionStore()->removeSession(mSessionId);
				} else {
					WLog_Print(logger_CallBacks, WLOG_ERROR, "session for id %d was not found!",mSessionId);
				}
			}

		}
	}
}

