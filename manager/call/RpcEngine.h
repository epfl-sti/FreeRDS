/**
 * Rpc engine build upon google protocol buffers
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

#ifndef RPCENGINE_H_
#define RPCENGINE_H_

#include <winpr/synch.h>

#include <freerds/rpc.h>

#include <list>

#include <call/Call.h>
#include <call/CallOut.h>

#define PIPE_BUFFER_SIZE	0xFFFF

namespace freerds
{
	class RpcEngine
	{
	public:
		RpcEngine();
		~RpcEngine();

		int startEngine();
		int stopEngine();

		HANDLE acceptClient();
		int serveClient();
		void resetStatus();

	private:
		int createServerPipe(void);
		HANDLE createServerPipe(const char* endpoint);
		static void* listenerThread(void* arg);
		int read();
		int readHeader();
		int readPayload();
		int processData();
		int send(Call * call);
		int sendError(UINT32 callId, UINT32 msgType);
		int sendInternal(FDSAPI_MSG_HEADER* header, BYTE* buffer);
		int processOutgoingCall(Call* call);

	private:
		HANDLE m_hClientPipe;
		HANDLE m_hServerPipe;
		HANDLE m_hServerThread;
		HANDLE m_hStopEvent;

		DWORD m_PacketLength;

		DWORD m_PayloadRead;
		BYTE m_PayloadBuffer[PIPE_BUFFER_SIZE];

		DWORD m_HeaderRead;
		BYTE* m_HeaderBuffer;
		FDSAPI_MSG_HEADER m_Header;

		UINT32 m_NextOutCall;
		std::list<CallOut*> m_AnswerWaitingQueue;
	};
}

#endif /* RPCENGINE_H_ */
