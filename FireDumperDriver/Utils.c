#include "Utils.h"

NTSTATUS FdCopyVirtualMemory(PEPROCESS targetProcess, PVOID sourceAddress, PVOID targetAddress, SIZE_T size)
{
	SIZE_T readBytes;
	return MmCopyVirtualMemory(targetProcess, sourceAddress, PsGetCurrentProcess(), targetAddress, size, UserMode, &readBytes);
}

NTSTATUS FdReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes;
	NTSTATUS Status;

	__try
	{
		if (NT_SUCCESS(Status = MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(),
			TargetAddress, Size, KernelMode, &Bytes)))
			Status = STATUS_SUCCESS;
		else
			Status = STATUS_ACCESS_DENIED;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = GetExceptionCode();

		if (Status == STATUS_ACCESS_VIOLATION)
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Nyuu: THREW -> STATUS_ACCESS_VIOLATION while trying to read from 0x%p\n", TargetAddress);
	}

	return Status;
}

NTSTATUS FdWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes;
	NTSTATUS Status;

	__try
	{
		if (NT_SUCCESS(Status = MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process,
			TargetAddress, Size, KernelMode, &Bytes)))
			Status = STATUS_SUCCESS;
		else
			Status = STATUS_ACCESS_DENIED;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = GetExceptionCode();

		if (Status == STATUS_ACCESS_VIOLATION)
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Nyuu: THREW -> STATUS_ACCESS_VIOLATION while trying to write to 0x%p\n", TargetAddress);
	}

	return Status;
}

static PSYSTEM_PROCESS_INFORMATION RawProcessList = NULL;
static SIZE_T ProcessListSize = 0;
//internal use
PSYSTEM_PROCESS_INFORMATION FdGetRawProcessList()
{
	ULONG rawProcessListSize = 0;
	ZwQuerySystemInformation(SystemProcessInformation, 0, rawProcessListSize, &rawProcessListSize);
	
	PSYSTEM_PROCESS_INFORMATION rawProcessListPtr = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, rawProcessListSize, POOL_TAG);

	if (rawProcessListPtr != NULL)
	{
		ZwQuerySystemInformation(SystemProcessInformation, rawProcessListPtr, rawProcessListSize, &rawProcessListSize);
	}
	
	return rawProcessListPtr;
}
PVOID SanitizeUserPointer(PVOID pointer, SIZE_T size)
{
	MEMORY_BASIC_INFORMATION memInfo;

	if (NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), pointer, MemoryBasicInformation, &memInfo, sizeof(MEMORY_BASIC_INFORMATION), NULL)))
	{
		if (!(((uintptr_t)memInfo.BaseAddress + memInfo.RegionSize) < (((uintptr_t)pointer + size))))
		{
			if (memInfo.State & MEM_COMMIT || !(memInfo.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
			{
				if (memInfo.Protect & PAGE_EXECUTE_READWRITE || memInfo.Protect & PAGE_EXECUTE_WRITECOPY || memInfo.Protect & PAGE_READWRITE || memInfo.Protect & PAGE_WRITECOPY)
				{
					return pointer;
				}
			}
		}
	}
	return NULL;
}
NTSTATUS DriverSleep(int ms)
{
	LARGE_INTEGER li;
	li.QuadPart = -10000;

	for (int i = 0; i < ms; i++)
	{
		KeDelayExecutionThread(KernelMode, FALSE, &li);
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}
PLDR_DATA_TABLE_ENTRY GetMainModuleDataTableEntry(PPEB peb)
{
	if (SanitizeUserPointer(peb, sizeof(PEB)))
	{
		if (peb->Ldr)
		{
			if (SanitizeUserPointer(peb->Ldr, sizeof(PEB_LDR_DATA)))
			{
				if (!peb->Ldr->Initialized)
				{
					int initLoadCount = 0;

					while (!peb->Ldr->Initialized && initLoadCount++ < 4)
					{
						DriverSleep(250);
					}
				}

				if (peb->Ldr->Initialized)
				{
					return CONTAINING_RECORD(peb->Ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				}
			}
		}
	}
	return NULL;
}

NTSTATUS FdGetProcessListSize(OUT SIZE_T* processListSize)
{
	SIZE_T size = 0;
	PSYSTEM_PROCESS_INFORMATION rawProcessList = FdGetRawProcessList();

	if (!rawProcessList)
		return STATUS_UNSUCCESSFUL;
	
	PVOID rawProcessListPtr = rawProcessList;
	while (rawProcessList->NextEntryOffset)
	{
		size += sizeof(PROCESS_LIST_ITEM);
		rawProcessList = (PSYSTEM_PROCESS_INFORMATION)(((CHAR*)rawProcessList) + rawProcessList->NextEntryOffset);
	}

	if (!size)
	{
		ExFreePoolWithTag(rawProcessListPtr, POOL_TAG);
		return STATUS_UNSUCCESSFUL;
	}
	
	RawProcessList = rawProcessListPtr;
	*processListSize = size;
	ProcessListSize = size;
	return STATUS_SUCCESS;
}

NTSTATUS FdGetProcessList(IN PVOID processListPtr, OUT SIZE_T* processListCount)
{
	/*if (processListSize <= 0)
		return STATUS_INVALID_PARAMETER_2;*/

	/*ULONG rawProcessListSize = 0;
	ZwQuerySystemInformation(SystemProcessInformation, 0, rawProcessListSize, &rawProcessListSize);
	
	PSYSTEM_PROCESS_INFORMATION RawProcessList = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, rawProcessListSize, POOL_TAG);
	PVOID RawProcessListPtr = RawProcessList;
	
	if (!RawProcessList)
		return STATUS_INSUFFICIENT_RESOURCES;

	ULONG newProcessListSize; //Use for debugging
	ZwQuerySystemInformation(SystemProcessInformation, RawProcessList, rawProcessListSize, &newProcessListSize);*/

	if (!RawProcessList)
		return STATUS_UNSUCCESSFUL;

	if (ProcessListSize <= 0)
		return STATUS_UNSUCCESSFUL;

	PVOID RawProcessListPtr = RawProcessList;
	
	PPROCESS_LIST_ITEM ProcessList = (PPROCESS_LIST_ITEM)ExAllocatePoolWithTag(NonPagedPool, ProcessListSize, POOL_TAG);
	PVOID ProcessListPtr = ProcessList;
	*processListCount = 0;
	
	if (!ProcessList)
		return STATUS_INSUFFICIENT_RESOURCES;

	while (RawProcessList->NextEntryOffset)
	{
		PEPROCESS targetProcess;
		KAPC_STATE state;

		if (NT_SUCCESS(PsLookupProcessByProcessId(RawProcessList->UniqueProcessId, &targetProcess)))
		{
			ProcessList->ProcessId = RawProcessList->UniqueProcessId;
			__try
			{
				KeStackAttachProcess(targetProcess, &state);

				__try
				{
					PVOID MainModuleBase = PsGetProcessSectionBaseAddress(targetProcess);

					if (MainModuleBase)
					{
						PPEB peb = (PPEB)PsGetProcessPeb(targetProcess);
						if (peb)
						{
							PLDR_DATA_TABLE_ENTRY MainModuleEntry = GetMainModuleDataTableEntry(peb);
							MainModuleEntry = SanitizeUserPointer(MainModuleEntry, sizeof(LDR_DATA_TABLE_ENTRY));

							if (MainModuleEntry)
							{
								ProcessList->MainModuleBase = (DWORD64)MainModuleBase;
								ProcessList->MainModuleEntry = (DWORD64)MainModuleEntry->EntryPoint;
								ProcessList->ImageSize = MainModuleEntry->SizeOfImage;
								ProcessList->ImageType = IS_WOW64_PE(MainModuleBase);

								RtlCopyMemory(ProcessList->ProcessFilePath, MainModuleEntry->FullDllName.Buffer, 256 * sizeof(WCHAR));
							}
						}
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Peb Interaction Failed.\n");
				}
			}
			__finally
			{
				KeUnstackDetachProcess(&state);
			}

			ProcessList++;
			(*processListCount)++;
			ObDereferenceObject(targetProcess);
		}

		RawProcessList = (PSYSTEM_PROCESS_INFORMATION)(((CHAR*)RawProcessList) + RawProcessList->NextEntryOffset);
	}

	/*if (processListSize != ProcessListSize)
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Length missmatch between ProcessListSize user/kernel\n");*/
	
	RtlCopyMemory(processListPtr, ProcessListPtr, ProcessListSize);

	ExFreePoolWithTag(RawProcessListPtr, POOL_TAG);
	ExFreePoolWithTag(ProcessListPtr, POOL_TAG);
	return STATUS_SUCCESS;
}

static SIZE_T ModuleListSize = 0;
NTSTATUS FdGetModuleListSize(IN HANDLE processId, OUT SIZE_T* moduleListSize)
{
	if (!processId)
		return STATUS_INVALID_PARAMETER_1;

	LARGE_INTEGER time;
	time.QuadPart = -250ll * 10 * 1000;     // 250 msec.
	
	SIZE_T size = 0;

	PEPROCESS targetProcess;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &targetProcess)))
		return STATUS_UNSUCCESSFUL;


	if (PsGetProcessWow64Process(targetProcess) != NULL)
	{ //using PPEB32, process is Wow64 aka x86 aka x32
		PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(targetProcess);
		if (!pPeb32)
			return STATUS_UNSUCCESSFUL;

		KAPC_STATE	apc;
		KeStackAttachProcess(targetProcess, &apc);

		for (INT i = 0; !pPeb32->Ldr && i < 10; i++)
			KeDelayExecutionThread(KernelMode, TRUE, &time);

		if (!pPeb32->Ldr)
		{
			KeUnstackDetachProcess(&apc);
			return STATUS_UNSUCCESSFUL;
		}

		PPEB_LDR_DATA32 LoaderData = (PPEB_LDR_DATA32)pPeb32->Ldr;

		for (PLIST_ENTRY32 pListEntry32 = (PLIST_ENTRY32)LoaderData->InLoadOrderModuleList.Flink;
			pListEntry32 != &LoaderData->InLoadOrderModuleList;
			pListEntry32 = (PLIST_ENTRY32)pListEntry32->Flink)
		{
			size += sizeof(MODULE_LIST_ITEM);
		}
		KeUnstackDetachProcess(&apc);
	}
	else
	{ //using PPEB, process is Native aka x64
		PPEB pPeb = PsGetProcessPeb(targetProcess);
		if (!pPeb)
			return STATUS_UNSUCCESSFUL;

		KAPC_STATE	apc;
		KeStackAttachProcess(targetProcess, &apc);

		for (INT i = 0; !pPeb->Ldr && i < 10; i++)
			KeDelayExecutionThread(KernelMode, TRUE, &time);

		if (!pPeb->Ldr)
		{
			KeUnstackDetachProcess(&apc);
			return STATUS_UNSUCCESSFUL;
		}

		PPEB_LDR_DATA LoaderData = pPeb->Ldr;

		for (PLIST_ENTRY pListEntry = LoaderData->InLoadOrderModuleList.Flink;
			pListEntry != &LoaderData->InLoadOrderModuleList;
			pListEntry = pListEntry->Flink)
		{
			size += sizeof(MODULE_LIST_ITEM);
		}
		KeUnstackDetachProcess(&apc);
	}

	ModuleListSize = size;
	*moduleListSize = size;
	return STATUS_SUCCESS;
}

NTSTATUS FdGetModuleList(IN HANDLE processId, IN PVOID moduleListPtr, OUT SIZE_T* moduleListCount)
{
	if (!processId)
		return STATUS_INVALID_PARAMETER_1;

	if (!moduleListPtr)
		return STATUS_INVALID_PARAMETER_2;

	if (ModuleListSize <= 0)
		return STATUS_UNSUCCESSFUL;

	SIZE_T ModuleListSizeBackup = ModuleListSize;
	
	LARGE_INTEGER time;
	time.QuadPart = -250ll * 10 * 1000;     // 250 msec.

	*moduleListCount = 0;

	PEPROCESS targetProcess;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &targetProcess)))
		return STATUS_UNSUCCESSFUL;

	PMODULE_LIST_ITEM ModuleList = (PMODULE_LIST_ITEM)ExAllocatePoolWithTag(NonPagedPool, ModuleListSize, POOL_TAG);
	PVOID ModuleListPtr = ModuleList;
	
	if (!ModuleList)
		return STATUS_INSUFFICIENT_RESOURCES;
	
	if (PsGetProcessWow64Process(targetProcess) != NULL)
	{ //using PPEB32, process is Wow64 aka x86 aka x32
		PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(targetProcess);
		if (!pPeb32)
			return STATUS_UNSUCCESSFUL;

		KAPC_STATE	apc;
		KeStackAttachProcess(targetProcess, &apc);

		for (INT i = 0; !pPeb32->Ldr && i < 10; i++)
			KeDelayExecutionThread(KernelMode, TRUE, &time);

		if (!pPeb32->Ldr)
		{
			KeUnstackDetachProcess(&apc);
			return STATUS_UNSUCCESSFUL;
		}

		PPEB_LDR_DATA32 LoaderData = (PPEB_LDR_DATA32)pPeb32->Ldr;

		for (PLIST_ENTRY32 pListEntry32 = (PLIST_ENTRY32)LoaderData->InLoadOrderModuleList.Flink;
			pListEntry32 != &LoaderData->InLoadOrderModuleList;
			pListEntry32 = (PLIST_ENTRY32)pListEntry32->Flink)
		{
			if (ModuleListSize <= 0)
				break;
			
			PLDR_DATA_TABLE_ENTRY32 pEntry32 = CONTAINING_RECORD(pListEntry32, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

			RtlCopyMemory(ModuleList->ModulePath, (PWCH)pEntry32->FullDllName.Buffer, 256 * sizeof(WCHAR));
			ModuleList->ModuleBase = pEntry32->DllBase;
			ModuleList->ModuleEntry = pEntry32->EntryPoint;
			ModuleList->ModuleSize = pEntry32->SizeOfImage;
			ModuleList->ModuleType = TRUE;
			
			ModuleList++;
			ModuleListSize -= sizeof(MODULE_LIST_ITEM);
			(*moduleListCount)++;
		}
		KeUnstackDetachProcess(&apc);
	}
	else
	{ //using PPEB, process is Native aka x64
		PPEB pPeb = PsGetProcessPeb(targetProcess);
		if (!pPeb)
			return STATUS_UNSUCCESSFUL;

		KAPC_STATE	apc;
		KeStackAttachProcess(targetProcess, &apc);

		for (INT i = 0; !pPeb->Ldr && i < 10; i++)
			KeDelayExecutionThread(KernelMode, TRUE, &time);

		if (!pPeb->Ldr)
		{
			KeUnstackDetachProcess(&apc);
			return STATUS_UNSUCCESSFUL;
		}

		PPEB_LDR_DATA LoaderData = pPeb->Ldr;

		for (PLIST_ENTRY pListEntry = LoaderData->InLoadOrderModuleList.Flink;
			pListEntry != &LoaderData->InLoadOrderModuleList;
			pListEntry = pListEntry->Flink)
		{
			if (ModuleListSize <= 0)
				break;
			
			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			RtlCopyMemory(ModuleList->ModulePath, pEntry->FullDllName.Buffer, 256 * sizeof(WCHAR));
			ModuleList->ModuleBase = (DWORD64)pEntry->DllBase;
			ModuleList->ModuleEntry = (DWORD64)pEntry->EntryPoint;
			ModuleList->ModuleSize = pEntry->SizeOfImage;
			ModuleList->ModuleType = FALSE;
			
			ModuleList++;
			ModuleListSize -= sizeof(MODULE_LIST_ITEM);
			(*moduleListCount)++;
		}
		KeUnstackDetachProcess(&apc);
	}

	RtlCopyMemory(moduleListPtr, ModuleListPtr, ModuleListSizeBackup);
	ExFreePoolWithTag(ModuleListPtr, POOL_TAG);
	return STATUS_SUCCESS;
}