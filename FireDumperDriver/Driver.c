#include "Utils.h"

NTSTATUS DevioctlDispatch(
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
)
{
	NTSTATUS Status;
	ULONG BytesIO;

	UNREFERENCED_PARAMETER(DeviceObject);

	// Code received from user space
	ULONG ControlCode = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.IoControlCode;
	if (ControlCode == IO_COPY_MEMORY_REQUEST)
	{
		PKERNEL_COPY_MEMORY_REQUEST CopyMemoryRequest = (PKERNEL_COPY_MEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS targetProcess;
		if (NT_SUCCESS(PsLookupProcessByProcessId(CopyMemoryRequest->ProcessId, &targetProcess)))
		{
			FdCopyVirtualMemory(targetProcess, CopyMemoryRequest->targetAddress, CopyMemoryRequest->bufferAddress, CopyMemoryRequest->bufferSize);
			ObDereferenceObject(targetProcess);
		}

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_COPY_MEMORY_REQUEST);
	}
	else if (ControlCode == IO_READ_MEMORY_REQUEST)
	{
		PKERNEL_READ_MEMORY_REQUEST ReadMemoryRequest = (PKERNEL_READ_MEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ReadMemoryRequest->ProcessId, &Process)))
			FdReadVirtualMemory(Process, ReadMemoryRequest->Address,
				&ReadMemoryRequest->Response, ReadMemoryRequest->Size);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_READ_MEMORY_REQUEST);
	}
	else if (ControlCode == IO_WRITE_MEMORY_REQUEST)
	{
		PKERNEL_WRITE_MEMORY_REQUEST WriteMemoryRequest = (PKERNEL_WRITE_MEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;
		if (NT_SUCCESS(PsLookupProcessByProcessId(WriteMemoryRequest->ProcessId, &Process)))
			FdWriteVirtualMemory(Process, &WriteMemoryRequest->Value,
				WriteMemoryRequest->Address, WriteMemoryRequest->Size);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_WRITE_MEMORY_REQUEST);
	}
	else if (ControlCode == IO_PROCESS_LIST_REQUEST)
	{
		PKERNEL_PROCESS_LIST_REQUEST ProcessListRequest = (PKERNEL_PROCESS_LIST_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		if (ProcessListRequest->ProcessListPtr)
			FdGetProcessList(ProcessListRequest->ProcessListPtr, &ProcessListRequest->ProcessListCount);
		else
			FdGetProcessListSize(&ProcessListRequest->ProcessListSize);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_PROCESS_LIST_REQUEST);
	}
	else if (ControlCode == IO_MODULE_LIST_REQUEST)
	{
		PKERNEL_MODULE_LIST_REQUEST ModuleListRequest = (PKERNEL_MODULE_LIST_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		if (ModuleListRequest->ModuleListPtr)
			FdGetModuleList(ModuleListRequest->ProcessId, ModuleListRequest->ModuleListPtr, &ModuleListRequest->ModuleListCount);
		else
			FdGetModuleListSize(ModuleListRequest->ProcessId, &ModuleListRequest->ModuleListSize);
		
		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_MODULE_LIST_REQUEST);
	}
	else
	{
		// if the code is unknown
		Status = STATUS_INVALID_PARAMETER;
		BytesIO = 0;
	}

	// Complete the request
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

NTSTATUS UnsupportedDispatch(
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS CreateDispatch(
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS CloseDispatch(
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS DriverInitialize(
	_In_  struct _DRIVER_OBJECT* DriverObject,
	_In_  PUNICODE_STRING RegistryPath
)
{
	UNICODE_STRING  SymLink, DevName;
	PDEVICE_OBJECT  devobj;

	UNREFERENCED_PARAMETER(RegistryPath);

	RtlInitUnicodeString(&DevName, L"\\Device\\Fdd001");
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &DevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &devobj);

	if (!NT_SUCCESS(status))
		return status;

	RtlInitUnicodeString(&SymLink, L"\\DosDevices\\Fdd001");
	status = IoCreateSymbolicLink(&SymLink, &DevName);

	devobj->Flags |= DO_BUFFERED_IO;

	for (ULONG t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		DriverObject->MajorFunction[t] = &UnsupportedDispatch;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &DevioctlDispatch;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = &CreateDispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = &CloseDispatch;
	DriverObject->DriverUnload = NULL;

	devobj->Flags &= ~DO_DEVICE_INITIALIZING;

	return status;
}

//Driver entry point
NTSTATUS DriverEntry(
	_In_  struct _DRIVER_OBJECT* DriverObject,
	_In_  PUNICODE_STRING RegistryPath
)
{
	UNICODE_STRING  drvName;

	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	//init
	RtlInitUnicodeString(&drvName, L"\\Driver\\Fdd001");

	return IoCreateDriver(&drvName, &DriverInitialize);
}