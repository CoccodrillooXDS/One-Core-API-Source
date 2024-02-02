/*++

Copyright (c) 2018 Shorthorn Project

Module Name:

    main.c

Abstract:

    main file

Author:

    Skulltrail 17-March-2018

Revision History:

--*/

#include <main.h>

VOID RtlpInitializeKeyedEvent(VOID);
VOID RtlpCloseKeyedEvent(VOID);
VOID NTAPI RtlpInitDeferredCriticalSection(VOID);
void load_global_options(void);
void init_locale();
void NTAPI RtlpInitSRWLock();
VOID InitializeGlobalKeyedEventHandle();

/*****************************************************
 *      DllMain
 */
BOOL 
WINAPI 
LdrInitialize(
	HANDLE hDll, 
	DWORD dwReason, 
	LPVOID reserved
)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
		RtlInitializeCriticalSection(&time_tz_section);
		RtlInitializeCriticalSection(&localeCritSection);
		RtlInitializeCriticalSection(&loader_section);
		//RtlInitializeCriticalSection(&dlldir_section);
		load_global_options();		
		init_locale();
        // LdrDisableThreadCalloutsForDll(hDll);
        //RtlpInitializeKeyedEvent();
        RtlpInitDeferredCriticalSection();
		RtlpInitSRWLock(NtCurrentTeb()->ProcessEnvironmentBlock);
		RtlpInitConditionVariable(NtCurrentTeb()->ProcessEnvironmentBlock);
		InitializeGlobalKeyedEventHandle();
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
       //RtlpCloseKeyedEvent();
    }	
	
    return TRUE;
}

struct _TEB * _NtCurrentTeb(void)
{
    return (struct _TEB *)__readfsdword(0x18);
}