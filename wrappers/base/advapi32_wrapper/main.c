/*
 * Copyright 2009 Henri Verbeet for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

/* INCLUDES ******************************************************************/

/* C Headers */
#include <rtl.h>
#include <winsvc.h>
#include <evntprov.h>
#include <ntsecapi.h>
#include <ndk/cmfuncs.h>
#include <wine/config.h>

#include <ntstatus.h>
#define WIN32_NO_STATUS

#include <wine/debug.h>


/* DEFINES ******************************************************************/
#define SHUTDOWN_GRACE_OVERRIDE 0x00000020
#define SHUTDOWN_RESTART 0x00000004
#define MAX_DEFAULT_HANDLES   6
#define REG_MAX_NAME_SIZE     256
#define REG_MAX_DATA_SIZE     2048
#define ClosePredefKey(Handle)                                                 \
    if ((ULONG_PTR)Handle & 0x1) {                                             \
        NtClose(Handle);                                                       \
    }
#define IsPredefKey(HKey)                                                      \
    (((ULONG_PTR)(HKey) & 0xF0000000) == 0x80000000)
#define GetPredefKeyIndex(HKey)                                                \
    ((ULONG_PTR)(HKey) & 0x0FFFFFFF)

	
WINE_DEFAULT_DEBUG_CHANNEL(advapi); 	

/* PROTOTYPES ***************************************************************/
	
static NTSTATUS MapDefaultKey (PHANDLE ParentKey, HKEY Key);
//static VOID CloseDefaultKeys(VOID);
static NTSTATUS OpenClassesRootKey(PHANDLE KeyHandle);
static NTSTATUS OpenLocalMachineKey (PHANDLE KeyHandle);
static NTSTATUS OpenUsersKey (PHANDLE KeyHandle);
static NTSTATUS OpenCurrentConfigKey(PHANDLE KeyHandle);

#define ARGUMENT_PRESENT(ArgumentPointer)((CHAR*)((ULONG_PTR)(ArgumentPointer)) != (CHAR*)NULL)

/* GLOBALS ******************************************************************/

static RTL_CRITICAL_SECTION HandleTableCS;
static HANDLE DefaultHandleTable[MAX_DEFAULT_HANDLES];
static HANDLE ProcessHeap;
static BOOLEAN DefaultHandlesDisabled = FALSE;
static BOOLEAN DefaultHandleHKUDisabled = FALSE;
static BOOLEAN DllInitialized = FALSE; /* HACK */
static const UNICODE_STRING HKLM_ClassesPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Classes");

typedef VOID( CALLBACK * PFN_SC_NOTIFY_CALLBACK ) (
    IN PVOID pParameter 
);

typedef PVOID LSA_HANDLE, *PLSA_HANDLE;

typedef ULONG64 TRACEHANDLE,*PTRACEHANDLE;

typedef struct _ENABLE_TRACE_PARAMETERS {
  ULONG                    Version;
  ULONG                    EnableProperty;
  ULONG                    ControlFlags;
  GUID                     SourceId;
  PEVENT_FILTER_DESCRIPTOR EnableFilterDesc;
  ULONG                    FilterDescCount;
} ENABLE_TRACE_PARAMETERS, *PENABLE_TRACE_PARAMETERS;

typedef enum _EVENT_INFO_CLASS { 
  EventProviderBinaryTrackInfo    = 0,
  EventProviderSetTraits          = 1,
  EventProviderUseDescriptorType  = 2,
  MaxEventInfo                    = 3
} EVENT_INFO_CLASS;

BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpv)
{
    switch(fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            break;
    }

    return TRUE;
}

/*INTERNAL FUNCTIONS ********************************************/

FORCEINLINE BOOL IsHKCRKey 	( 	_In_ HKEY  	hKey	) 	
{
	return ((ULONG_PTR)hKey & 0x2) != 0;	
}

FORCEINLINE void MakeHKCRKey 	( 	_Inout_ HKEY *  	hKey	) 	
{
	*hKey = (HKEY)((ULONG_PTR)(*hKey) | 0x2);
}

/************************************************************************
 *  RegInitDefaultHandles
 */
BOOL
RegInitialize(VOID)
{
    /* Lazy init hack */
    if (!DllInitialized)
    {
        ProcessHeap = RtlGetProcessHeap();
        RtlZeroMemory(DefaultHandleTable,
                      MAX_DEFAULT_HANDLES * sizeof(HANDLE));
        RtlInitializeCriticalSection(&HandleTableCS);

        DllInitialized = TRUE;
    }

    return TRUE;
}
/*
static VOID
CloseDefaultKeys(VOID)
{
    ULONG i;
    RegInitialize();
    RtlEnterCriticalSection(&HandleTableCS);

    for (i = 0; i < MAX_DEFAULT_HANDLES; i++)
    {
        if (DefaultHandleTable[i] != NULL)
        {
            NtClose(DefaultHandleTable[i]);
            DefaultHandleTable[i] = NULL;
        }
    }

    RtlLeaveCriticalSection(&HandleTableCS);
}*/

static NTSTATUS
OpenClassesRootKey(PHANDLE KeyHandle)
{
    OBJECT_ATTRIBUTES Attributes;
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\CLASSES");

    InitializeObjectAttributes(&Attributes,
                               &KeyName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    return NtOpenKey(KeyHandle,
                     MAXIMUM_ALLOWED,
                     &Attributes);
}

static NTSTATUS
OpenLocalMachineKey(PHANDLE KeyHandle)
{
    OBJECT_ATTRIBUTES Attributes;
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine");
    NTSTATUS Status;

    InitializeObjectAttributes(&Attributes,
                               &KeyName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    Status = NtOpenKey(KeyHandle,
                       MAXIMUM_ALLOWED,
                       &Attributes);

    return Status;
}


static NTSTATUS
OpenUsersKey(PHANDLE KeyHandle)
{
    OBJECT_ATTRIBUTES Attributes;
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\User");

    InitializeObjectAttributes(&Attributes,
                               &KeyName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    return NtOpenKey(KeyHandle,
                     MAXIMUM_ALLOWED,
                     &Attributes);
}


static NTSTATUS
OpenCurrentConfigKey (PHANDLE KeyHandle)
{
    OBJECT_ATTRIBUTES Attributes;
    UNICODE_STRING KeyName =
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Hardware Profiles\\Current");

    InitializeObjectAttributes(&Attributes,
                               &KeyName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    return NtOpenKey(KeyHandle,
                     MAXIMUM_ALLOWED,
                     &Attributes);
}

static NTSTATUS
OpenPredefinedKey(IN ULONG Index,
                  OUT HANDLE Handle)
{
    NTSTATUS Status;

    switch (Index)
    {
        case 0: /* HKEY_CLASSES_ROOT */
            Status = OpenClassesRootKey (Handle);
            break;

        case 1: /* HKEY_CURRENT_USER */
            Status = RtlOpenCurrentUser (MAXIMUM_ALLOWED,
                                         Handle);
            break;

        case 2: /* HKEY_LOCAL_MACHINE */
            Status = OpenLocalMachineKey (Handle);
            break;

        case 3: /* HKEY_USERS */
            Status = OpenUsersKey (Handle);
            break;
#if 0
        case 4: /* HKEY_PERFORMANCE_DATA */
            Status = OpenPerformanceDataKey (Handle);
            break;
#endif

        case 5: /* HKEY_CURRENT_CONFIG */
            Status = OpenCurrentConfigKey (Handle);
            break;

        case 6: /* HKEY_DYN_DATA */
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        default:
            Status = STATUS_INVALID_PARAMETER;
            break;
    }

    return Status;
}

static NTSTATUS
MapDefaultKey(OUT PHANDLE RealKey,
              IN HKEY Key)
{
    PHANDLE Handle;
    ULONG Index;
    BOOLEAN DoOpen, DefDisabled;
    NTSTATUS Status = STATUS_SUCCESS;

    if (!IsPredefKey(Key))
    {
        *RealKey = (HANDLE)((ULONG_PTR)Key & ~0x1);
        return STATUS_SUCCESS;
    }

    /* Handle special cases here */
    Index = GetPredefKeyIndex(Key);
    if (Index >= MAX_DEFAULT_HANDLES)
    {
        return STATUS_INVALID_PARAMETER;
    }
    RegInitialize(); /* HACK until delay-loading is implemented */
    RtlEnterCriticalSection (&HandleTableCS);

    if (Key == HKEY_CURRENT_USER)
        DefDisabled = DefaultHandleHKUDisabled;
    else
        DefDisabled = DefaultHandlesDisabled;

    if (!DefDisabled)
    {
        Handle = &DefaultHandleTable[Index];
        DoOpen = (*Handle == NULL);
    }
    else
    {
        Handle = RealKey;
        DoOpen = TRUE;
    }

    if (DoOpen)
    {
        /* create/open the default handle */
        Status = OpenPredefinedKey(Index,
                                   Handle);
    }

    if (NT_SUCCESS(Status))
    {
        if (!DefDisabled)
            *RealKey = *Handle;
        else
            *(PULONG_PTR)Handle |= 0x1;
    }

    RtlLeaveCriticalSection (&HandleTableCS);

    return Status;
}

/* unimplemented*/
ULONG 
WINAPI 
EventRegister(
  _In_      LPCGUID ProviderId,
  _In_opt_  PENABLECALLBACK EnableCallback,
  _In_opt_  PVOID CallbackContext,
  _Out_     PREGHANDLE RegHandle
)
{
	return ERROR_SUCCESS;
	//return EtwEventRegister(ProviderId, EnableCallback, CallbackContext, RegHandle);
}

/* unimplemented*/
ULONG WINAPI EventUnregister(
  _In_  REGHANDLE RegHandle
)
{
	//return EtwEventUnregister(RegHandle);
	return ERROR_SUCCESS;
}

/* unimplemented*/
ULONG WINAPI EventWrite(
  _In_      REGHANDLE RegHandle,
  _In_      PCEVENT_DESCRIPTOR EventDescriptor,
  _In_      ULONG UserDataCount,
  _In_opt_  PEVENT_DATA_DESCRIPTOR UserData
)
{
	//return EtwEventWrite(RegHandle, EventDescriptor, UserDataCount, UserData);
	return ERROR_SUCCESS;
}

ULONG WINAPI
EventWriteEndScenario(
    REGHANDLE RegHandle,
    PCEVENT_DESCRIPTOR EventDescriptor,
    ULONG UserDataCount,
    PEVENT_DATA_DESCRIPTOR UserData)
{
	//return EtwEventWriteEndScenario(RegHandle, EventDescriptor, UserDataCount, UserData);
	return ERROR_SUCCESS;
}

ULONG 
WINAPI
EventWriteStartScenario(
    REGHANDLE RegHandle,
    PCEVENT_DESCRIPTOR EventDescriptor,
    ULONG UserDataCount,
    PEVENT_DATA_DESCRIPTOR UserData)
{
	//return EtwEventWriteStartScenario(RegHandle, EventDescriptor, UserDataCount, UserData);
	return ERROR_SUCCESS;
}

ULONG WINAPI EventWriteString(
  _In_  REGHANDLE RegHandle,
  _In_  UCHAR Level,
  _In_  ULONGLONG Keyword,
  _In_  PCWSTR String
)
{
	return ERROR_SUCCESS;
}

/* unimplemented*/
BOOLEAN WINAPI EventEnabled(
  IN REGHANDLE RegHandle,
  IN PCEVENT_DESCRIPTOR EventDescriptor)
{
	//return EtwEventEnabled(RegHandle, EventDescriptor);
	return TRUE;
}

/* unimplemented*/
ULONG WINAPI EventWriteEx(
  _In_      REGHANDLE RegHandle,
  _In_      PCEVENT_DESCRIPTOR EventDescriptor,
  _In_      ULONG64 Filter,
  _In_      ULONG Flags,
  _In_opt_  LPCGUID ActivityId,
  _In_      LPCGUID RelatedActivityId,
  _In_      ULONG UserDataCount,
  _In_opt_  PEVENT_DATA_DESCRIPTOR UserData
)
{
	return ERROR_SUCCESS;
}

/******************************************************************************
 * load_string [Internal]
 *
 * This is basically a copy of user32/resource.c's LoadStringW. Necessary to
 * avoid importing user32, which is higher level than advapi32. Helper for
 * RegLoadMUIString.
 */
static int load_string(HINSTANCE hModule, UINT resId, LPWSTR pwszBuffer, INT cMaxChars)
{
    HGLOBAL hMemory;
    HRSRC hResource;
    WCHAR *pString;
    int idxString;

    /* Negative values have to be inverted. */
    if (HIWORD(resId) == 0xffff)
        resId = (UINT)(-((INT)resId));

    /* Load the resource into memory and get a pointer to it. */
    hResource = FindResourceW(hModule, MAKEINTRESOURCEW(LOWORD(resId >> 4) + 1), (LPWSTR)RT_STRING);
    if (!hResource) return 0;
    hMemory = LoadResource(hModule, hResource);
    if (!hMemory) return 0;
    pString = LockResource(hMemory);

    /* Strings are length-prefixed. Lowest nibble of resId is an index. */
    idxString = resId & 0xf;
    while (idxString--) pString += *pString + 1;

    /* If no buffer is given, return length of the string. */
    if (!pwszBuffer) return *pString;

    /* Else copy over the string, respecting the buffer size. */
    cMaxChars = (*pString < cMaxChars) ? *pString : (cMaxChars - 1);
    if (cMaxChars >= 0)
    {
        memcpy(pwszBuffer, pString+1, cMaxChars * sizeof(WCHAR));
        pwszBuffer[cMaxChars] = L'\0';
    }

    return cMaxChars;
}

ULONG WINAPI EnableTraceEx(
  _In_      LPCGUID ProviderId,
  _In_opt_  LPCGUID SourceId,
  _In_      TRACEHANDLE TraceHandle,
  _In_      ULONG IsEnabled,
  _In_      UCHAR Level,
  _In_      ULONGLONG MatchAnyKeyword,
  _In_      ULONGLONG MatchAllKeyword,
  _In_      ULONG EnableProperty,
  _In_opt_  PEVENT_FILTER_DESCRIPTOR EnableFilterDesc
)
{
	return ERROR_SUCCESS;	
}

/* unimplemented*/
ULONG WINAPI EventActivityIdControl(
  _In_     ULONG ControlCode,
  _Inout_  LPGUID ActivityId
)
{
	//return EtwEventActivityIdControl(ControlCode, ActivityId);
	return ERROR_SUCCESS;
}

/* unimplemented*/
BOOLEAN WINAPI EventProviderEnabled(
  _In_  REGHANDLE RegHandle,
  _In_  UCHAR Level,
  _In_  ULONGLONG Keyword
)
{
	return TRUE;
}

/* unimplemented*/
ULONG WINAPI EventAccessControl(
  _In_  LPGUID Guid,
  _In_  ULONG Operation,
  _In_  PSID Sid,
  _In_  ULONG Rights,
  _In_  BOOLEAN AllowOrDeny
)
{
	return ERROR_SUCCESS;
}


ULONG WINAPI EventWriteTransfer(
  _In_      REGHANDLE RegHandle,
  _In_      PCEVENT_DESCRIPTOR EventDescriptor,
  _In_opt_  LPCGUID ActivityId,
  _In_      LPCGUID RelatedActivityId,
  _In_      ULONG UserDataCount,
  _In_opt_  PEVENT_DATA_DESCRIPTOR UserData
)
{
	return ERROR_SUCCESS;
}

/* implemented
DWORD WINAPI InitiateShutdownW(
  _In_opt_  LPWSTR lpMachineName,
  _In_opt_  LPWSTR lpMessage,
  _In_      DWORD dwGracePeriod,
  _In_      DWORD dwShutdownFlags,
  _In_      DWORD dwReason
)
{
	BOOL shutdown;
	DWORD time = dwGracePeriod;
	switch(dwShutdownFlags)
	{
		case SHUTDOWN_GRACE_OVERRIDE:
			time = 0;
			shutdown = 1;
			break;
		case SHUTDOWN_RESTART:
			shutdown = 0;
			break;
		default:
			shutdown = 1;
			break;
	}
	InitiateSystemShutdownW(lpMachineName,lpMessage, 0, 1, shutdown);
	return ERROR_SUCCESS;
}*/
/*
DWORD WINAPI NotifyServiceStatusChangeW(
  _In_  SC_HANDLE hService,
  _In_  DWORD dwNotifyMask,
  _In_  PSERVICE_NOTIFY pNotifyBuffer
)
{
	return ERROR_SUCCESS;
}
*/
// Non-recursive RegDeleteTreeW implementation by Thomas, however it needs bugfixing
static NTSTATUS
RegpDeleteTree(IN HKEY hKey)
{
    typedef struct
    {
        LIST_ENTRY ListEntry;
        HANDLE KeyHandle;
    } REGP_DEL_KEYS, *PREG_DEL_KEYS;

    LIST_ENTRY delQueueHead;
    PREG_DEL_KEYS delKeys, newDelKeys;
    HANDLE ProcessHeap;
    ULONG BufferSize;
    PKEY_BASIC_INFORMATION BasicInfo;
    PREG_DEL_KEYS KeyDelRoot;
    NTSTATUS Status = STATUS_SUCCESS;
    NTSTATUS Status2 = STATUS_SUCCESS;

    InitializeListHead(&delQueueHead);

    ProcessHeap = RtlGetProcessHeap();

    /* NOTE: no need to allocate enough memory for an additional KEY_BASIC_INFORMATION
             structure for the root key, we only do that for subkeys as we need to
             allocate REGP_DEL_KEYS structures anyway! */
    KeyDelRoot = RtlAllocateHeap(ProcessHeap,
                                 0,
                                 sizeof(REGP_DEL_KEYS));
    if (KeyDelRoot != NULL)
    {
        KeyDelRoot->KeyHandle = hKey;
        InsertTailList(&delQueueHead,
                       &KeyDelRoot->ListEntry);

        do
        {
            delKeys = CONTAINING_RECORD(delQueueHead.Flink,
                                        REGP_DEL_KEYS,
                                        ListEntry);

            BufferSize = 0;
            BasicInfo = NULL;
            newDelKeys = NULL;

ReadFirstSubKey:
            /* check if this key contains subkeys and delete them first by queuing
               them at the head of the list */
            Status2 = NtEnumerateKey(delKeys->KeyHandle,
                                     0,
                                     KeyBasicInformation,
                                     BasicInfo,
                                     BufferSize,
                                     &BufferSize);

            if (NT_SUCCESS(Status2))
            {
                OBJECT_ATTRIBUTES ObjectAttributes;
                UNICODE_STRING SubKeyName;

                ASSERT(newDelKeys != NULL);
                ASSERT(BasicInfo != NULL);

                /* don't use RtlInitUnicodeString as the string is not NULL-terminated! */
                SubKeyName.Length = (ULONG)(USHORT)BasicInfo->NameLength;
                SubKeyName.MaximumLength = (ULONG)(USHORT)BasicInfo->NameLength;
                SubKeyName.Buffer = BasicInfo->Name;

                InitializeObjectAttributes(&ObjectAttributes,
                                           &SubKeyName,
                                           OBJ_CASE_INSENSITIVE,
                                           delKeys->KeyHandle,
                                           NULL);

                /* open the subkey */
                Status2 = NtOpenKey(&newDelKeys->KeyHandle,
                                    DELETE | KEY_ENUMERATE_SUB_KEYS,
                                    &ObjectAttributes);
                if (!NT_SUCCESS(Status2))
                {
                    goto SubKeyFailure;
                }

                /* enqueue this key to the head of the deletion queue */
                InsertHeadList(&delQueueHead,
                               &newDelKeys->ListEntry);

                /* try again from the head of the list */
                continue;
            }
            else
            {
                if (Status2 == STATUS_BUFFER_TOO_SMALL)
                {
                    newDelKeys = RtlAllocateHeap(ProcessHeap,
                                                 0,
                                                 BufferSize + sizeof(REGP_DEL_KEYS));
                    if (newDelKeys != NULL)
                    {
                        BasicInfo = (PKEY_BASIC_INFORMATION)(newDelKeys + 1);

                        /* try again */
                        goto ReadFirstSubKey;
                    }
                    else
                    {
                        /* don't break, let's try to delete as many keys as possible */
                        Status2 = STATUS_INSUFFICIENT_RESOURCES;
                        goto SubKeyFailureNoFree;
                    }
                }
                else if (Status2 == STATUS_BUFFER_OVERFLOW)
                {
                    PREG_DEL_KEYS newDelKeys2;

                    ASSERT(newDelKeys != NULL);

                    /* we need more memory to query the key name */
                    newDelKeys2 = RtlReAllocateHeap(ProcessHeap,
                                                    0,
                                                    newDelKeys,
                                                    BufferSize + sizeof(REGP_DEL_KEYS));
                    if (newDelKeys2 != NULL)
                    {
                        newDelKeys = newDelKeys2;
                        BasicInfo = (PKEY_BASIC_INFORMATION)(newDelKeys + 1);

                        /* try again */
                        goto ReadFirstSubKey;
                    }
                    else
                    {
                        /* don't break, let's try to delete as many keys as possible */
                        Status2 = STATUS_INSUFFICIENT_RESOURCES;
                    }
                }
                else if (Status2 == STATUS_NO_MORE_ENTRIES)
                {
                    /* in some race conditions where another thread would delete
                       the same tree at the same time, newDelKeys could actually
                       be != NULL! */
                    if (newDelKeys != NULL)
                    {
                        RtlFreeHeap(ProcessHeap,
                                    0,
                                    newDelKeys);
                    }
                    break;
                }

SubKeyFailure:
                /* newDelKeys can be NULL here when NtEnumerateKey returned an
                   error other than STATUS_BUFFER_TOO_SMALL or STATUS_BUFFER_OVERFLOW! */
                if (newDelKeys != NULL)
                {
                    RtlFreeHeap(ProcessHeap,
                                0,
                                newDelKeys);
                }

SubKeyFailureNoFree:
                /* don't break, let's try to delete as many keys as possible */
                if (NT_SUCCESS(Status))
                {
                    Status = Status2;
                }
            }

            Status2 = NtDeleteKey(delKeys->KeyHandle);

            /* NOTE: do NOT close the handle anymore, it's invalid already! */

            if (!NT_SUCCESS(Status2))
            {
                /* close the key handle so we don't leak handles for keys we were
                   unable to delete. But only do this for handles not supplied
                   by the caller! */

                if (delKeys->KeyHandle != hKey)
                {
                    NtClose(delKeys->KeyHandle);
                }

                if (NT_SUCCESS(Status))
                {
                    /* don't break, let's try to delete as many keys as possible */
                    Status = Status2;
                }
            }

            /* remove the entry from the list */
            RemoveEntryList(&delKeys->ListEntry);

            RtlFreeHeap(ProcessHeap,
                        0,
                        delKeys);
        } while (!IsListEmpty(&delQueueHead));
    }
    else
        Status = STATUS_INSUFFICIENT_RESOURCES;

    return Status;
}

BOOL 
WINAPI 
AddMandatoryAce(
	PACL pAcl, 
	DWORD dwAceRevision, 
	DWORD AceFlags, 
	DWORD MandatoryPolicy, 
	PSID pLabelSid
)
{
  NTSTATUS resp; // eax@1
  BOOL result; // eax@2

  resp = RtlAddMandatoryAce(pAcl, dwAceRevision, AceFlags, MandatoryPolicy, 17, pLabelSid);
  if ( resp < 0 )
  {
    result = FALSE;
  }
  else
  {
    result = TRUE;
  }
  return result;
}

ULONG 
WINAPI
EnableTraceEx2(
  _In_     TRACEHANDLE              TraceHandle,
  _In_     LPCGUID                  ProviderId,
  _In_     ULONG                    ControlCode,
  _In_     UCHAR                    Level,
  _In_     ULONGLONG                MatchAnyKeyword,
  _In_     ULONGLONG                MatchAllKeyword,
  _In_     ULONG                    Timeout,
  _In_opt_ PENABLE_TRACE_PARAMETERS EnableParameters
)
{
	return ERROR_SUCCESS;
}


ULONG 
WINAPI
EventSetInformation(
  _In_ REGHANDLE        RegHandle,
  _In_ EVENT_INFO_CLASS InformationClass,
  _In_ PVOID            EventInformation,
  _In_ ULONG            InformationLength
)
{
	return ERROR_SUCCESS;
}

NTSTATUS 
WINAPI
LsaLookupSids2(
  _In_  LSA_HANDLE                  PolicyHandle,
  _In_  ULONG                       LookupOptions,
  _In_  ULONG                       Count,
  _In_  PSID                        *Sids,
  _Out_ PLSA_REFERENCED_DOMAIN_LIST *ReferencedDomains,
  _Out_ PLSA_TRANSLATED_NAME        *Names
)
{
	return LsaLookupSids(PolicyHandle,
						 Count,
						 Sids,
						 ReferencedDomains,
						 Names);
}

BOOL
APIENTRY
GetTokenInformationInternal (
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    DWORD TokenInformationLength,
    PDWORD ReturnLength
    )
{
    // NTSTATUS Status;

    // Status = NtQueryInformationToken (
        // TokenHandle,
        // TokenInformationClass,
        // TokenInformation,
        // TokenInformationLength,
        // ReturnLength
        // );
	// DbgPrint("GetTokenInformationInternal :: NtQueryInformationToken Status: %08x\n",Status);			
		

    // if ( !NT_SUCCESS(Status) ) {
        // //BaseSetLastNTError(Status);
		// DbgPrint("GetTokenInformation :: return FALSE\n",Status);
        // return FALSE;
    // }

    // return TRUE;
	BOOL ret;
	
	ret = GetTokenInformation(TokenHandle,
							  TokenInformationClass,
							  TokenInformation,
							  TokenInformationLength,
							  ReturnLength);
							  
	if(!ret){
		//DbgPrint("GetTokenInformation :: returned False\n");	
	}

	return ret;		
	
}

BOOL
APIENTRY
SetTokenInformationInternal (
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    DWORD TokenInformationLength
    )
{ 
    // NTSTATUS Status;

    // Status = NtSetInformationToken (
        // TokenHandle,
        // TokenInformationClass,
        // TokenInformation,
        // TokenInformationLength
        // );

	// DbgPrint("SetTokenInformation :: NtSetInformationToken Status: %08x\n",Status);
	
	// if(!NT_SUCCESS(Status)){
		// DbgPrint("SetTokenInformation :: return FALSE\n",Status);
		// return FALSE; 
	// }
	
	// return TRUE;
	BOOL ret;
	
	ret = SetTokenInformation(TokenHandle,
							  TokenInformationClass,
							  TokenInformation,
							  TokenInformationLength);
							  
	if(!ret){
		DbgPrint("SetTokenInformation :: returned False\n");	
	}

	return ret;							  
}

/* set last error code from NT status and get the proper boolean return value */
 /* used for functions that are a simple wrapper around the corresponding ntdll API */
 static inline BOOL set_ntstatus( NTSTATUS status )
 {
     if (status) SetLastError( RtlNtStatusToDosError( status ));
     return !status;
}

BOOL 
WINAPI 
OpenThreadTokenInternal(
  _In_  HANDLE  ThreadHandle,
  _In_  DWORD   DesiredAccess,
  _In_  BOOL    OpenAsSelf,
  _Out_ PHANDLE TokenHandle
)
{
	// BOOL ret;
	// NTSTATUS status;
	
	// DbgPrint("OpenThreadTokenInternal :: caled\n");
	
	// status =  NtOpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);
	
	// DbgPrint("OpenThreadToken :: Status: %08x\n",status);
	
	// if(!NT_SUCCESS(status)){
		// DbgPrint("OpenThreadToken :: return FALSE\n",status);
		// return FALSE; 
	// }
	
	// return TRUE;

	BOOL ret;
	
	ret = OpenThreadToken(ThreadHandle,
							  DesiredAccess,
							  OpenAsSelf,
							  TokenHandle);
							  
	if(!ret){
		//DbgPrint("OpenThreadToken :: returned False\n");	
	}
	
	return ret;			
}

/******************************************************************************
 * OpenProcessToken			[ADVAPI32.@]
 * Opens the access token associated with a process handle.
 *
 * PARAMS
 *   ProcessHandle [I] Handle to process
 *   DesiredAccess [I] Desired access to process
 *   TokenHandle   [O] Pointer to handle of open access token
 *
 * RETURNS
 *  Success: TRUE. TokenHandle contains the access token.
 *  Failure: FALSE.
 *
 * NOTES
 *  See NtOpenProcessToken.
 */
BOOL 
WINAPI
OpenProcessTokenInternal( 
	HANDLE ProcessHandle, 
	DWORD DesiredAccess,
    HANDLE *TokenHandle 
)
{
	// BOOL ret;
	// NTSTATUS status;
	
	// DbgPrint("OpenProcessTokenInternal :: caled\n");
	
	// status =  NtOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
	
	// DbgPrint("OpenProcessToken :: NtOpenProcessToken Status: %08x\n",status);
	
	// if(!NT_SUCCESS(status)){
		// DbgPrint("OpenProcessToken :: return FALSE\n",status);
		// return FALSE; 
	// }
	
	// return TRUE;
	BOOL ret;
	
	ret = OpenProcessToken(ProcessHandle,
							  DesiredAccess,
							  TokenHandle);
							  
	if(!ret){
		DbgPrint("OpenProcessToken :: returned False\n");	
	}	

	return ret;			
}

/*************************************************************************
 * CreateRestrictedToken [ADVAPI32.@]
 *
 * Create a new more restricted token from an existing token.
 *
 * PARAMS
 *   baseToken       [I] Token to base the new restricted token on
 *   flags           [I] Options
 *   nDisableSids    [I] Length of disableSids array
 *   disableSids     [I] Array of SIDs to disable in the new token
 *   nDeletePrivs    [I] Length of deletePrivs array
 *   deletePrivs     [I] Array of privileges to delete in the new token
 *   nRestrictSids   [I] Length of restrictSids array
 *   restrictSids    [I] Array of SIDs to restrict in the new token
 *   newToken        [O] Address where the new token is stored
 *
 * RETURNS
 *  Success: TRUE
 *  Failure: FALSE
 */
BOOL WINAPI CreateRestrictedTokenInternal(
    HANDLE baseToken,
    DWORD flags,
    DWORD nDisableSids,
    PSID_AND_ATTRIBUTES disableSids,
    DWORD nDeletePrivs,
    PLUID_AND_ATTRIBUTES deletePrivs,
    DWORD nRestrictSids,
    PSID_AND_ATTRIBUTES restrictSids,
    PHANDLE newToken)
{
    TOKEN_TYPE type;
    SECURITY_IMPERSONATION_LEVEL level = SecurityAnonymous;
    DWORD size;

    FIXME("(%p, 0x%x, %u, %p, %u, %p, %u, %p, %p): stub\n",
          baseToken, flags, nDisableSids, disableSids,
          nDeletePrivs, deletePrivs,
          nRestrictSids, restrictSids,
          newToken);

    size = sizeof(type);
    if (!GetTokenInformation( baseToken, TokenType, &type, size, &size )) return FALSE;
    if (type == TokenImpersonation)
    {
        size = sizeof(level);
        if (!GetTokenInformation( baseToken, TokenImpersonationLevel, &level, size, &size ))
            return FALSE;
    }
    return DuplicateTokenEx( baseToken, MAXIMUM_ALLOWED, NULL, level, type, newToken );
}

//DELETE ME

LONG WINAPI RegDeleteTreeW(
  _In_     HKEY    hKey,
  _In_opt_ LPCWSTR lpSubKey
)
{
	return ERROR_SUCCESS;
}

BOOL WINAPI GetKernelObjectSecurityInternal(
  _In_      HANDLE               Handle,
  _In_      SECURITY_INFORMATION RequestedInformation,
  _Out_opt_ PSECURITY_DESCRIPTOR pSecurityDescriptor,
  _In_      DWORD                nLength,
  _Out_     LPDWORD              lpnLengthNeeded
)
{
	//This is a hack, for now is enabled because need a truly implementation of LABEL_SECURITY_INFORMATION (for Chrome and Chromium Framework)
	if(RequestedInformation & LABEL_SECURITY_INFORMATION)
	{
		RequestedInformation = SACL_SECURITY_INFORMATION;
	}
	return GetKernelObjectSecurity(Handle, RequestedInformation, pSecurityDescriptor, nLength, lpnLengthNeeded);
}


BOOL WINAPI SetKernelObjectSecurityInternal(
  _In_ HANDLE               Handle,
  _In_ SECURITY_INFORMATION SecurityInformation,
  _In_ PSECURITY_DESCRIPTOR SecurityDescriptor
)
{
	//This is a hack, for now is enabled because need a truly implementation of LABEL_SECURITY_INFORMATION (for Chrome and Chromium Framework)
	if(SecurityInformation & LABEL_SECURITY_INFORMATION)
	{
		SecurityInformation = SACL_SECURITY_INFORMATION;
	}
	return SetKernelObjectSecurity(Handle, SecurityInformation, SecurityDescriptor);
}