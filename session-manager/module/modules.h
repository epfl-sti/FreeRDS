/**
 * Module interface
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

#ifndef MODULES_H_
#define MODULES_H_

#include "../common/config/PropertyCWrapper.h"

typedef struct rds_module_entry_points_v1 RDS_MODULE_ENTRY_POINTS_V1;
typedef RDS_MODULE_ENTRY_POINTS_V1 RDS_MODULE_ENTRY_POINTS;

struct _RDS_MODULE_COMMON
{
	WORD sessionId;
	char* authToken;
	char* userName;
	HANDLE userToken;
	char** envBlock;
};
typedef struct _RDS_MODULE_COMMON RDS_MODULE_COMMON;


/**
 * Module Entry Points
 */

typedef RDS_MODULE_COMMON* (*pRdsModuleNew)();
typedef void (*pRdsModuleFree)(RDS_MODULE_COMMON* module);

typedef char* (*pRdsModuleStart)(RDS_MODULE_COMMON* module);
typedef int (*pRdsModuleStop)(RDS_MODULE_COMMON* module);

struct rds_module_entry_points_v1
{
	DWORD Version;

	pRdsModuleNew New;
	pRdsModuleFree Free;

	pRdsModuleStart Start;
	pRdsModuleStop Stop;
	char* Name;

	pgetPropertyBool getPropertyBool;
	pgetPropertyNumber getPropertyNumber;
	pgetPropertyString getPropertyString;
};

#define RDS_MODULE_INTERFACE_VERSION	1
#define RDS_MODULE_ENTRY_POINT_NAME	"RdsModuleEntry"

typedef int (*pRdsModuleEntry)(RDS_MODULE_ENTRY_POINTS* pEntryPoints);

#endif /* MODULES_H_ */
