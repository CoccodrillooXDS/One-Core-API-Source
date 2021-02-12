/*++

Copyright (c) 2017  Shorthorn Project

Module Name:

    fileopcr.c

Abstract:

    This module implements File open and Create APIs for Win32

Author:

    Skulltrail 20-March-2017

Revision History:

--*/

#include "main.h"

HANDLE
WINAPI
ReOpenFile(
    HANDLE  hOriginalFile,
    DWORD   dwDesiredAccess,
    DWORD   dwShareMode,
    DWORD   dwFlags
    )
{
    ULONG CreateFlags = 0;
    ULONG CreateDisposition;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Obja;
    HANDLE Handle;
    IO_STATUS_BLOCK IoStatusBlock;
    DWORD SQOSFlags;
    SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
    UNICODE_STRING  FileName;

    if (((ULONG)hOriginalFile & 0x10000003)) {
        BaseSetLastNTError(STATUS_INVALID_HANDLE);
        return INVALID_HANDLE_VALUE;
    }

    /*
    / The attributes are useless as this reopen of an existing file.
    */

    if (dwFlags &  FILE_ATTRIBUTE_VALID_FLAGS) {
        BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    /*
    / Initialize all the create flags from the Attribute flags.
    */

    CreateFlags |= (dwFlags & FILE_FLAG_NO_BUFFERING ? FILE_NO_INTERMEDIATE_BUFFERING : 0 );
    CreateFlags |= (dwFlags & FILE_FLAG_WRITE_THROUGH ? FILE_WRITE_THROUGH : 0 );
    CreateFlags |= (dwFlags & FILE_FLAG_OVERLAPPED ? 0 : FILE_SYNCHRONOUS_IO_NONALERT );
    CreateFlags |= (dwFlags & FILE_FLAG_SEQUENTIAL_SCAN ? FILE_SEQUENTIAL_ONLY : 0 );
    CreateFlags |= (dwFlags & FILE_FLAG_RANDOM_ACCESS ? FILE_RANDOM_ACCESS : 0 );
    CreateFlags |= (dwFlags & FILE_FLAG_BACKUP_SEMANTICS ? FILE_OPEN_FOR_BACKUP_INTENT : 0 );
    CreateFlags |= (dwFlags & FILE_FLAG_OPEN_REPARSE_POINT ? FILE_OPEN_REPARSE_POINT : 0 );
    CreateFlags |= (dwFlags & FILE_FLAG_OPEN_NO_RECALL ? FILE_OPEN_NO_RECALL : 0 );

    if ( dwFlags & FILE_FLAG_DELETE_ON_CLOSE ) {
        CreateFlags |= FILE_DELETE_ON_CLOSE;
        dwDesiredAccess |= DELETE;
        }

    CreateFlags |= FILE_NON_DIRECTORY_FILE;
    CreateDisposition = FILE_OPEN;

    RtlInitUnicodeString( &FileName, L"");
    
    /*
    / Pass a NULL name relative to the original handle.
    */

    InitializeObjectAttributes(
        &Obja,
        &FileName,  
        dwFlags & FILE_FLAG_POSIX_SEMANTICS ? 0 : OBJ_CASE_INSENSITIVE,
        hOriginalFile, 
        NULL
        );

    SQOSFlags = dwFlags & SECURITY_VALID_SQOS_FLAGS;

    if ( SQOSFlags & SECURITY_SQOS_PRESENT ) {

        SQOSFlags &= ~SECURITY_SQOS_PRESENT;

        if (SQOSFlags & SECURITY_CONTEXT_TRACKING) {

            SecurityQualityOfService.ContextTrackingMode = (SECURITY_CONTEXT_TRACKING_MODE) TRUE;
            SQOSFlags &= ~SECURITY_CONTEXT_TRACKING;

        } else {

            SecurityQualityOfService.ContextTrackingMode = (SECURITY_CONTEXT_TRACKING_MODE) FALSE;
        }

        if (SQOSFlags & SECURITY_EFFECTIVE_ONLY) {

            SecurityQualityOfService.EffectiveOnly = TRUE;
            SQOSFlags &= ~SECURITY_EFFECTIVE_ONLY;

        } else {

            SecurityQualityOfService.EffectiveOnly = FALSE;
        }

        SecurityQualityOfService.ImpersonationLevel = SQOSFlags >> 16;


    } else {

        SecurityQualityOfService.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
        SecurityQualityOfService.ImpersonationLevel = SecurityImpersonation;
        SecurityQualityOfService.EffectiveOnly = TRUE;
    }

    SecurityQualityOfService.Length = sizeof( SECURITY_QUALITY_OF_SERVICE );
    Obja.SecurityQualityOfService = &SecurityQualityOfService;

    Status = NtCreateFile(
                &Handle,
                (ACCESS_MASK)dwDesiredAccess | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
                &Obja,
                &IoStatusBlock,
                NULL,
                0,
                dwShareMode,
                CreateDisposition,
                CreateFlags,
                NULL,
                0
                );

    if ( !NT_SUCCESS(Status) ) {
        BaseSetLastNTError(Status);
        return INVALID_HANDLE_VALUE;
    }

    SetLastError(0);

    return Handle;
}

/*
 * @implemented - need test
 */
BOOL 
WINAPI 
CopyFileTransactedW(
	LPCWSTR lpExistingFileName, 
	LPCWSTR lpNewFileName, 
	LPPROGRESS_ROUTINE lpProgressRoutine, 
	LPVOID lpData, 
	LPBOOL pbCancel, 
	DWORD dwCopyFlags, 
	HANDLE hTransaction
)
{
    return CopyFileExW(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
}

/*
 * @implemented - need test
 */
BOOL 
WINAPI 
CopyFileTransactedA(
	LPCSTR lpExistingFileName, 
	LPCSTR lpNewFileName, 
	LPPROGRESS_ROUTINE lpProgressRoutine, 
	LPVOID lpData, 
	LPBOOL pbCancel, 
	DWORD dwCopyFlags, 
	HANDLE hTransaction
)
{
    return CopyFileExA(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
}

HANDLE
WINAPI
CreateFileTransactedW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
)
{
	return CreateFileW(lpFileName, 
					   dwDesiredAccess, 
					   dwShareMode, 
					   lpSecurityAttributes, 
					   dwCreationDisposition, 
					   dwFlagsAndAttributes,
					   hTemplateFile);
}

HANDLE
WINAPI
CreateFileTransactedA(
    LPSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
)
{
	return CreateFileA(lpFileName, 
					   dwDesiredAccess, 
					   dwShareMode, 
					   lpSecurityAttributes, 
					   dwCreationDisposition, 
					   dwFlagsAndAttributes,
					   hTemplateFile);
}

HANDLE 
WINAPI 
CreateFile2(
  _In_      LPCWSTR lpFileName,
  _In_      DWORD dwDesiredAccess,
  _In_      DWORD dwShareMode,
  _In_      DWORD dwCreationDisposition,
  _In_opt_  LPCREATEFILE2_EXTENDED_PARAMETERS pCreateExParams
)
{
	return CreateFileW(lpFileName, 
					   dwDesiredAccess, 
					   dwShareMode, 
					   pCreateExParams->lpSecurityAttributes, 
					   dwCreationDisposition, 
					   pCreateExParams->dwFileFlags |  pCreateExParams->dwFileAttributes,
					   pCreateExParams->hTemplateFile);
}