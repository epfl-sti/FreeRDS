/**
 * Connection store class
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


#ifndef __CONNECTION_STORE_H_
#define __CONNECTION_STORE_H_

#include <config.h>

#include "Connection.h"

#include <map>
#include <string>

#include <winpr/synch.h>

namespace freerds
{
	typedef std::map<UINT32, ConnectionPtr> TConnectionMap;
	typedef std::pair<UINT32, ConnectionPtr> TConnectionPair;

	class ConnectionStore
	{
	public:
		ConnectionStore();
		~ConnectionStore();

		ConnectionPtr getOrCreateConnection(UINT32 connectionId);
		ConnectionPtr getConnection(UINT32 connectionId);
		int removeConnection(UINT32 connectionId);

		UINT32 getConnectionIdForSessionId(UINT32 sessionId);

		void reset();

	private:
		TConnectionMap m_ConnectionMap;
		CRITICAL_SECTION m_CSection;
	};
}

#endif //__CONNECTION_STORE_H_
