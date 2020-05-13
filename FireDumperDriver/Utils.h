#pragma once

#include "KeAPI.h"

#define POOL_TAG 'ENON'

NTSTATUS FdCopyVirtualMemory(PEPROCESS targetProcess, PVOID sourceAddress, PVOID targetAddress, SIZE_T size);
NTSTATUS FdReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size);
NTSTATUS FdWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size);

NTSTATUS FdGetProcessListSize(OUT SIZE_T* processListSize);
NTSTATUS FdGetProcessList(IN PVOID processListPtr, OUT SIZE_T* processListCount);

NTSTATUS FdGetModuleListSize(IN HANDLE processId, OUT SIZE_T* moduleListSize);
NTSTATUS FdGetModuleList(IN HANDLE processId, IN PVOID moduleListPtr, OUT SIZE_T* moduleListCount);

#pragma pack(push, 1)
typedef struct _PROCESS_LIST_ITEM {

	HANDLE  ProcessId;
    WCHAR   ProcessFilePath[256];
    DWORD64 MainModuleBase;
    DWORD64 MainModuleEntry;
    DWORD   ImageSize;
    BOOLEAN ImageType;
	
} PROCESS_LIST_ITEM, *PPROCESS_LIST_ITEM;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _MODULE_LIST_ITEM {

	WCHAR   ModulePath[256];
    DWORD64 ModuleBase;
    DWORD64 ModuleEntry;
    DWORD   ModuleSize;
    BOOLEAN ModuleType;
	
} MODULE_LIST_ITEM, * PMODULE_LIST_ITEM;
#pragma pack(pop)