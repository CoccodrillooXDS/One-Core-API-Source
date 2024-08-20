/*++

Copyright (c) 2017 Shorthorn Project

Module Name:

    dllmain.c

Abstract:

    This module initialize Win32 API Base

Author:

    Skulltrail 20-March-2017

Revision History:

--*/


#include "main.h"

static BOOL DllInitialized = FALSE;
PPEB Peb;
HMODULE kernel32_handle = NULL;
ULONG BaseDllTag;

extern BOOL RegInitialize(VOID);
extern BOOL RegCleanup(VOID);
void InitializeCriticalForLocaleInfo();
void init_locale(void);

BOOL
WINAPI
BaseDllInitialize(
	HANDLE hDll,
    DWORD dwReason,
    LPVOID lpReserved)
{
    /* Cache the PEB and Session ID */
    //Peb = NtCurrentPeb();

    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
			int i;
			LPACVAHASHTABLEENTRY lpHashTableEntry;
            /* Insert more dll attach stuff here! */
			kernel32_handle = GetModuleHandleW(L"kernel32");
			InitializeCriticalForLocaleInfo();
			//RegInitialize();
			
			//Initialize Locale
			init_locale();
			
			BaseDllTag = RtlCreateTagHeap( RtlProcessHeap(),
                                       0,
                                       L"BASEDLL!",
                                       L"TMP\0"
                                       L"BACKUP\0"
                                       L"INI\0"
                                       L"FIND\0"
                                       L"GMEM\0"
                                       L"LMEM\0"
                                       L"ENV\0"
                                       L"RES\0"
                                       L"VDM\0"
                                     );			
			
            DllInitialized = TRUE;

			for (i = 0; i < ARRAYSIZE(WaitOnAddressHashTable); ++i) {
				lpHashTableEntry = &WaitOnAddressHashTable[i];
				InitializeCriticalSection(&lpHashTableEntry->Lock);
				InitializeListHead(&lpHashTableEntry->Addresses);
			}			
            break;
        }

        case DLL_PROCESS_DETACH:
        {
            if (DllInitialized == TRUE)
            {
				DllInitialized = FALSE;
            }
            break;
        }
		
        case DLL_THREAD_ATTACH:
        {

        }

        default:
            break;
    }

    return TRUE;
}

/***********************************************************************
 *          QuirkIsEnabled3 (kernelex.@)
 */
BOOL WINAPI QuirkIsEnabled3(void *unk1, void *unk2)
{
    static int once;

    if (!once++)
        DbgPrint("(%p, %p) stub!\n", unk1, unk2);
	
    return FALSE;
}