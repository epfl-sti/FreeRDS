/**
 * Connection class
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

#ifndef CONNECTION_H_
#define CONNECTION_H_

#include <config.h>
#include <string>
#include <list>

#include <winpr/crt.h>
#include <winpr/wtsapi.h>
#include <winpr/synch.h>
#include <boost/shared_ptr.hpp>

#include <freerds/module.h>

namespace freerds { class AuthModule; }

namespace freerds
{
	typedef struct _CLIENT_INFORMATION
	{
		long with;
		long height;
		long colordepth;
	} CLIENT_INFORMATION, * pCLIENT_INFORMATION;

	class Connection
	{
	public:
		Connection(DWORD connectionId);
		~Connection();

		std::string getDomain();
		std::string getUserName();

		void setSessionId(UINT32 sessionId);
		UINT32 getSessionId();

		UINT32 getAbout2SwitchSessionId();
		void setAbout2SwitchSessionId(UINT32 switchSessionId);

		pCLIENT_INFORMATION getClientInformation();

		UINT32 getConnectionId();

		freerds::AuthModule* authenticateUser(std::string username, std::string domain, std::string password);

	private:
		UINT32 m_ConnectionId;
		UINT32 m_SessionId;
		UINT32 m_About2SwitchSessionId;

		int m_AuthStatus;

		CLIENT_INFORMATION m_ClientInformation;

		std::string m_Username;
		std::string m_Domain;
		CRITICAL_SECTION m_CSection;
	};

	typedef boost::shared_ptr<Connection> ConnectionPtr;
}

#endif // CONNECTION_H_
