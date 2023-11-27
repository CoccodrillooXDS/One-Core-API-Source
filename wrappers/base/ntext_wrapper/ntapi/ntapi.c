/*++

Copyright (c) 2018 Shorthorn Project

Module Name:

    ntapi.c

Abstract:

    Implement User Mode Nt functions

Author:

    Skulltrail 06-March-2018

Revision History:

--*/

#include <main.h>

NTSTATUS 
NTAPI
NtLoadKeyEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile,
	IN ULONG Flags,
	IN HANDLE TrustClassKey
) 
{
	return NtLoadKey(TargetKey, SourceFile);
}

NTSTATUS 
NTAPI
NtQueryOpenSubKeysEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN ULONG BufferLength,
	IN PVOID Buffer,
	IN PULONG RequiredSize
)
{
	return NtQueryOpenSubKeys(TargetKey, RequiredSize);
}

NTSTATUS 
WINAPI 
NtUnmapViewOfSectionEx(
	HANDLE handle, 
	PVOID MemoryCache, 
	ULONG number)
{
	return NtUnmapViewOfSection(handle, MemoryCache);	
}

NTSTATUS
NTAPI
NtCreateMutantEx(
  OUT PHANDLE             MutantHandle,
  IN ACCESS_MASK          DesiredAccess,
  IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
  IN BOOLEAN              InitialOwner, 
  IN ULONG 				  Flags
)
{
	return NtCreateMutant(MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);
}

NTSTATUS 
NTAPI 
NtCreateIoCompletionEx(
	__out PHANDLE IoCompletionHandle, 
	__in ACCESS_MASK DesiredAccess, 
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes, 
	__in_opt ULONG Count
)
{
	return NtCreateIoCompletion(IoCompletionHandle, DesiredAccess, ObjectAttributes, Count);
} 

// NTSTATUS 
// NTAPI
// NtRemoveIoCompletionEx(
    // __in HANDLE IoCompletionHandle,
    // __out FILE_IO_COMPLETION_INFORMATION *IoCompletionInformation,
    // __in ULONG Count,
    // __out ULONG *NumEntriesRemoved,
    // __in_opt PLARGE_INTEGER Timeout,
    // __in BOOLEAN Alertable
// )
// {
	// PVOID CompletionKey;
	// PVOID CompletionValue;
	// IO_STATUS_BLOCK IoStatusBlock;
	// NTSTATUS Status;
	// ULONG i = 0;
	
    // for (;;)
    // {
        // while (i < Count)
        // {
			// Status = NtRemoveIoCompletion(IoCompletionHandle,
										 // &CompletionKey,
										 // &CompletionValue,
										 // &IoStatusBlock,
										  // Timeout);
                // if (NT_SUCCESS(Status))
                // {
                    // IoCompletionInformation[i].KeyContext             = CompletionKey;
                    // IoCompletionInformation[i].ApcContext             = CompletionValue;
                    // IoCompletionInformation[i].IoStatusBlock.Information = IoStatusBlock.Information;
                    // IoCompletionInformation[i].IoStatusBlock.Status    = IoStatusBlock.Status;
                // }
            // if (Status != STATUS_SUCCESS) break;
            // ++i;
        // }
        // if (i || Status != STATUS_PENDING)
        // {
            // if (Status == STATUS_PENDING) Status = STATUS_SUCCESS;
            // break;
        // }
        // Status = NtWaitForSingleObject( IoCompletionHandle, Alertable, Timeout );
        // if (Status != WAIT_OBJECT_0) break;
    // }
    // *NumEntriesRemoved = i ? i : 1;
    // return Status;
// }

NTSTATUS 
NTAPI 
NtCreateSemaphoreEx(
  IN OPTIONAL   HANDLE lpSemaphoreAttributes,
  IN       LONG                  lInitialCount,
  IN       LONG                  lMaximumCount,
  IN OPTIONAL  LPCTSTR               lpName,
  IN 	   DWORD                 dwFlags,
  IN       DWORD                 dwDesiredAccess
)
{
	return STATUS_SUCCESS;
}

NTSTATUS 
NTAPI 
NtCreateKeyTransacted(
	__out PHANDLE KeyHandle, 
	__in ACCESS_MASK DesiredAccess, 
	__in POBJECT_ATTRIBUTES ObjectAttributes, 
	ULONG TitleIndex, 
	__in_opt PUNICODE_STRING Class, 
	__in ULONG CreateOptions, 
	__in HANDLE TransactionHandle, 
	__out_opt PULONG Disposition)
{
	return NtCreateKey(KeyHandle, 
					   DesiredAccess, 
					   ObjectAttributes, 
					   TitleIndex, 
					   Class, 
					   CreateOptions, 
					   Disposition);
}

NTSTATUS 
NTAPI 
NtOpenKeyTransacted(
	__out PHANDLE KeyHandle, 
	__in ACCESS_MASK DesiredAccess, 
	__in POBJECT_ATTRIBUTES ObjectAttributes, 
	__in HANDLE TransactionHandle)
{
	return NtOpenKey(KeyHandle, 
					 DesiredAccess, 
					 ObjectAttributes);
}

/* Section Unimplemented*/
NTSTATUS
NTAPI
NtOpenPrivateNamespace(
  __out PHANDLE NamespaceHandle,
  __in ACCESS_MASK DesiredAccess,
  __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
  __in PVOID BoundaryDescriptor
)
{
	return STATUS_SUCCESS;
}

NTSTATUS 
NTAPI 
NtSetInformationVirtualMemory(HANDLE hProcess,
							  BOOL access,
							  ULONG_PTR NumberOfEntries, 
							  PMEMORY_RANGE_ENTRY VirtualAddresses, 
							  PULONG Flags,
							  DWORD other
)
{
	return STATUS_SUCCESS;
}	

NTSTATUS 
NTAPI 	
NtReplacePartitionUnit(__in PUNICODE_STRING TargetInstancePath, 
					   __in PUNICODE_STRING SpareInstancePath,
					   __in ULONG Flags)
{
	return STATUS_SUCCESS;
}

NTSTATUS 
NTAPI 
NtDeletePrivateNamespace(
  __in HANDLE NamespaceHandle
)
{
	return STATUS_SUCCESS;
}

NTSTATUS 
NTAPI 
NtCreatePrivateNamespace(
  __out PHANDLE NamespaceHandle,
  __in ACCESS_MASK DesiredAccess,
  __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
  __in PVOID BoundaryDescriptor
)
{
	return STATUS_SUCCESS;
}

NTSTATUS 
NTAPI
NtTraceControl(
	ULONG FunctionCode, 
	PVOID InBuffer, 
	ULONG InBufferLen, 
	PVOID OutBuffer, 
	ULONG OutBufferLen, 
	PULONG ReturnLength
)
{
	return STATUS_UNSUCCESSFUL;
}

VOID 
NTAPI 
NtFlushProcessWriteBuffers()	
{
	;
}

NTAPI 
NtSetSystemPowerState( 	
	IN POWER_ACTION  	SystemAction,
	IN SYSTEM_POWER_STATE  	MinSystemState,
	IN ULONG  	Flags 
)
{
	return STATUS_SUCCESS;
} 	

NTSTATUS 
WINAPI 
NtCreateThreadEx(PHANDLE hThread,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    ULONG CreateFlags,
    ULONG StackZeroBits,
    ULONG SizeOfStackCommit,
    ULONG SizeOfStackReserve,
    LPVOID lpBytesBuffer)
{
    NTSTATUS status = RtlCreateUserThread(ProcessHandle, 
										  NULL, 
										  CreateFlags & 1, 
										  0, 
										  0, 
										  0, 
										  lpStartAddress, 
										  lpParameter, 
										  hThread, 
										  NULL);
    return status;
}

NTSTATUS 
NTAPI
NtCreateTransaction(
  _Out_    PHANDLE            TransactionHandle,
  _In_     ACCESS_MASK        DesiredAccess,
  _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_opt_ LPGUID             Uow,
  _In_opt_ HANDLE             TmHandle,
  _In_opt_ ULONG              CreateOptions,
  _In_opt_ ULONG              IsolationLevel,
  _In_opt_ ULONG              IsolationFlags,
  _In_opt_ PLARGE_INTEGER     Timeout,
  _In_opt_ PUNICODE_STRING    Description
)
{
	*TransactionHandle = NULL;
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS 
NTAPI
NtQueryInformationTransaction(
  _In_      HANDLE                        TransactionHandle,
  _In_      TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
  _Out_     PVOID                         TransactionInformation,
  _In_      ULONG                         TransactionInformationLength,
  _Out_opt_ PULONG                        ReturnLength
)
{
	TransactionInformation = NULL;
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS 
NTAPI
NtSetInformationTransaction(
  _In_ HANDLE                        TransactionHandle,
  _In_ TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
  _In_ PVOID                         TransactionInformation,
  _In_ ULONG                         TransactionInformationLength
)
{
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS 
NTAPI
NtRollbackTransaction(
  _In_ HANDLE  TransactionHandle,
  _In_ BOOLEAN Wait
)
{
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS 
NTAPI
NtCommitTransaction(
  _In_ HANDLE  TransactionHandle,
  _In_ BOOLEAN Wait
)
{
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS 
NTAPI
NtOpenTransaction(
  _Out_    PHANDLE            TransactionHandle,
  _In_     ACCESS_MASK        DesiredAccess,
  _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_     LPGUID             Uow,
  _In_opt_ HANDLE             TmHandle
)
{
	*TransactionHandle = NULL;
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS 
WINAPI 
NtOpenKeyEx( 
	PHANDLE retkey, 
	ACCESS_MASK access, 
	const OBJECT_ATTRIBUTES *attr, 
	ULONG options 
)
{
    return NtOpenKey( retkey, access, attr);
}

/**************************************************************************
 *           NtCancelIoFileEx   (NTDLL.@)
 */
NTSTATUS 
WINAPI 
NtCancelIoFileEx( 
	HANDLE handle, 
	IO_STATUS_BLOCK *io, 
	IO_STATUS_BLOCK *io_status 
)
{
	/*Ignoring io parameter for now*/
	UNREFERENCED_PARAMETER(io);
	return NtCancelIoFile(handle, io_status);
}

/***********************************************************************
 *             NtRemoveIoCompletionEx (NTDLL.@)
 */
NTSTATUS WINAPI NtRemoveIoCompletionEx( HANDLE handle, FILE_IO_COMPLETION_INFORMATION *info, ULONG count,
                                        ULONG *written, LARGE_INTEGER *timeout, BOOLEAN alertable )
{
    NTSTATUS status;
    ULONG i = 0;
	PVOID CompletionKey = 0;
	PVOID CompletionValue = 0;
	PIO_STATUS_BLOCK IoStatusBlock = {0};

    for (;;)
    {
        while (i < count)
        {
			status = NtRemoveIoCompletion(handle, CompletionKey, CompletionValue, IoStatusBlock, timeout);			
            if(status == STATUS_SUCCESS)
			{
				info[i].KeyContext             = CompletionKey;
				info[i].ApcContext             = CompletionValue;
				info[i].IoStatusBlock.Information = IoStatusBlock->Information;
				info[i].IoStatusBlock.Status    = IoStatusBlock->Status;   
			}				
			if (status != STATUS_SUCCESS) break;
            ++i;
        }
        if (i || status != STATUS_PENDING)
        {
            if (status == STATUS_PENDING) status = STATUS_SUCCESS;
            break;
        }
        status = NtWaitForSingleObject( handle, alertable, timeout );
        if (status != WAIT_OBJECT_0) break;
    }
    *written = i ? i : 1;
    return status;
}