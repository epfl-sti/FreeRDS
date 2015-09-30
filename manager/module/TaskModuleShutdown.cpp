/**
 * Task for ModuleShutdown callback.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <winpr/wlog.h>

#include "TaskModuleShutdown.h"
#include <session/ApplicationContext.h>
#include <call/CallOutLogOffUserSession.h>

namespace freerds
{
	static wLog* logger_TaskModuleShutdown = WLog_Get("freerds.TaskModuleShutdown");

	void TaskModuleShutdown::run()
	{
		UINT32 connectionId = APP_CONTEXT.getConnectionStore()->getConnectionIdForSessionId(m_SessionId);

		stopSession();

		if (connectionId != 0)
		{
			CallOutLogOffUserSession logoffSession;
			logoffSession.setConnectionId(connectionId);
			APP_CONTEXT.getRpcOutgoingQueue()->addElement(&logoffSession);
			WaitForSingleObject(logoffSession.getAnswerHandle(),INFINITE);

			APP_CONTEXT.getConnectionStore()->removeConnection(connectionId);
		}
	}

	void TaskModuleShutdown::setSessionId(UINT32 sessionId) {
		m_SessionId = sessionId;
	}

	void TaskModuleShutdown::stopSession()
	{
		SessionPtr session = APP_CONTEXT.getSessionStore()->getSession(m_SessionId);

		if (session)
		{
			session->stopModule();
			APP_CONTEXT.getSessionStore()->removeSession(m_SessionId);
		}
		else
		{
			WLog_Print(logger_TaskModuleShutdown, WLOG_ERROR, "session for id %d was not found!", m_SessionId);
		}
	}
}

