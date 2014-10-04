/**
 * FreeRDS: FreeRDP Remote Desktop Services (RDS)
 *
 * Copyright 2014 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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
#include <winpr/stream.h>

#include "rpc.h"

#include <freerds/rpc.h>

int msgpack_stream_write(wStream* s, const BYTE* buf, size_t len)
{
	Stream_EnsureRemainingCapacity(s, len);
	Stream_Write(s, buf, len);
	return 0;
}

void msgpack_stream_packer_init(msgpack_packer* pk, wStream* s)
{
	pk->data = (void*) s;
	pk->callback = (msgpack_packer_write) msgpack_stream_write;
}

BOOL msgpack_unpack_array(msgpack_object* obj, size_t* n)
{
	if (obj->type != MSGPACK_OBJECT_ARRAY)
		return FALSE;

	*n = obj->via.array.size;
	return TRUE;
}

BOOL msgpack_unpack_array_min(msgpack_object* obj, size_t* n, size_t min)
{
	if (obj->type != MSGPACK_OBJECT_ARRAY)
		return FALSE;

	if (obj->via.array.size < min)
		return FALSE;

	*n = obj->via.array.size;
	return TRUE;
}

BOOL msgpack_unpack_uint32(msgpack_object* obj, UINT32* d)
{
	if (obj->type != MSGPACK_OBJECT_POSITIVE_INTEGER)
		return FALSE;

	*d = (UINT32) obj->via.u64;
	return TRUE;
}

int msgpack_pack_cstr(msgpack_packer* pk, const char* cstr)
{
	size_t length;

	if (cstr)
	{
		length = strlen(cstr);
		msgpack_pack_raw(pk, length);
		msgpack_pack_raw_body(pk, cstr, length);
	}
	else
	{
		msgpack_pack_raw(pk, 0);
		msgpack_pack_raw_body(pk, NULL, 0);
	}

	return 0;
}

BOOL msgpack_unpack_cstr(msgpack_object* obj, char** cstr)
{
	size_t length;

	if (obj->type != MSGPACK_OBJECT_RAW)
		return FALSE;

	length = obj->via.raw.size;

	if (length < 1)
	{
		*cstr = NULL;
		return TRUE;
	}

	*cstr = (char*) malloc(length + 1);

	if (!(*cstr))
		return FALSE;

	CopyMemory(*cstr, obj->via.raw.ptr, length);
	(*cstr)[length] = '\0';

	return TRUE;
}

/* Function Tables */

extern RDS_RPC_PACK_FUNC* g_S2M_FUNCS[];

RDS_RPC_PACK_FUNC* freerds_rpc_msg_find_func(UINT32 msgType)
{
	int index = 0;
	BOOL found = FALSE;
	RDS_RPC_PACK_FUNC** func = g_S2M_FUNCS;

	while (func[index])
	{
		if (msgType == func[index]->msgType)
		{
			found = TRUE;
			break;
		}

		index++;
	}

	return (found) ? func[index] : NULL;
}

wStream* freerds_rpc_msg_pack(void* data, wStream* s)
{
	UINT32 msgType;
	RDS_RPC_PACK_FUNC* func;

	if (!data)
		return NULL;

	msgType = *((UINT32*) data);
	func = freerds_rpc_msg_find_func(msgType);

	if (!func)
		return NULL;

	return func->Pack(data, s);
}

BOOL freerds_rpc_msg_unpack(void* data, const BYTE* buffer, UINT32 size)
{
	UINT32 msgType;
	RDS_RPC_PACK_FUNC* func;

	if (!data)
		return FALSE;

	msgType = *((UINT32*) data);
	func = freerds_rpc_msg_find_func(msgType);

	if (!func)
		return FALSE;

	return func->Unpack(data, buffer, size);
}

void freerds_rpc_msg_free(void* data)
{
	UINT32 msgType;
	RDS_RPC_PACK_FUNC* func;

	if (!data)
		return;

	msgType = *((UINT32*) data);
	func = freerds_rpc_msg_find_func(msgType);

	if (!func)
		return;

	return func->Free(data);
}
