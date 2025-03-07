/*++

Copyright (c) 2017 Shorthorn Project

Module Name:

    module.c

Abstract:

    This module contains the Win32 Module Management APIs

Author:

    Skulltrail 15-October-2017

Revision History:

--*/

#include "main.h"
#include "wine/list.h"
#include <ldrfuncs.h>
#include <umfuncs.h>
#include <stdint.h>

WINE_DEFAULT_DEBUG_CHANNEL(kernel32file);

static BOOL oem_file_apis;

static BOOL (WINAPI *pSetSearchPathMode)(DWORD);

/* to keep track of LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE file handles */
struct exclusive_datafile
{
    struct list entry;
    HMODULE     module;
    HANDLE      file;
};
static struct list exclusive_datafile_list = LIST_INIT( exclusive_datafile_list );

#ifdef _M_IX86
typedef struct _PEB32
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    DWORD   Mutant;
    DWORD   ImageBaseAddress;
    DWORD   LdrData;
} PEB32;
#endif

typedef struct _PEB_LDR_DATA32
{
    ULONG        Length;
    BOOLEAN      Initialized;
    DWORD        SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
} PEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32        InLoadOrderModuleList;
    LIST_ENTRY32        InMemoryOrderModuleList;
    LIST_ENTRY32        InInitializationOrderModuleList;
    DWORD               BaseAddress;
    DWORD               EntryPoint;
    ULONG               SizeOfImage;
    UNICODE_STRING32    FullDllName;
    UNICODE_STRING32    BaseDllName;
} LDR_DATA_TABLE_ENTRY32;

struct module_iterator
{
    HANDLE                 process;
    LIST_ENTRY            *head;
    LIST_ENTRY            *current;
    BOOL                   wow64;
    LDR_DATA_TABLE_ENTRY   ldr_module;
    LDR_DATA_TABLE_ENTRY32 ldr_module32;
};

/******************************************************************
 *      load_library_as_datafile
 */
static BOOL load_library_as_datafile( LPCWSTR load_path, DWORD flags, LPCWSTR name, HMODULE *mod_ret )
{
    WCHAR filenameW[MAX_PATH];
    HANDLE mapping, file = INVALID_HANDLE_VALUE;
    HMODULE module = 0;
    DWORD protect = PAGE_READONLY;

    *mod_ret = 0;

    if (flags & LOAD_LIBRARY_AS_IMAGE_RESOURCE) protect |= SEC_IMAGE;

    if (SearchPathW( NULL, name, L".dll", ARRAY_SIZE( filenameW ), filenameW, NULL ))
    {
        file = CreateFileW( filenameW, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING, 0, 0 );
    }
    if (file == INVALID_HANDLE_VALUE) return FALSE;

    mapping = CreateFileMappingW( file, NULL, protect, 0, 0, NULL );
    if (!mapping) goto failed;

    module = MapViewOfFile( mapping, FILE_MAP_READ, 0, 0, 0 );
    CloseHandle( mapping );
    if (!module) goto failed;

    if (!(flags & LOAD_LIBRARY_AS_IMAGE_RESOURCE))
    {
        /* make sure it's a valid PE file */
        if (!RtlImageNtHeader( module )) goto failed;
        *mod_ret = (HMODULE)((char *)module + 1); /* set bit 0 for data file module */

        if (flags & LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE)
        {
            struct exclusive_datafile *datafile = HeapAlloc( GetProcessHeap(), 0, sizeof(*datafile) );
            if (!datafile) goto failed;
            datafile->module = *mod_ret;
            datafile->file   = file;
            list_add_head( &exclusive_datafile_list, &datafile->entry );
            TRACE( "delaying close %p for module %p\n", datafile->file, datafile->module );
            return TRUE;
        }
    }
    else *mod_ret = (HMODULE)((char *)module + 2); /* set bit 1 for image resource module */

    CloseHandle( file );
    return TRUE;

failed:
    if (module) UnmapViewOfFile( module );
    CloseHandle( file );
    return FALSE;
}

/******************************************************************
 *      load_library
 */
static HMODULE load_library( const UNICODE_STRING *libname, DWORD flags )
{
    const DWORD unsupported_flags = LOAD_IGNORE_CODE_AUTHZ_LEVEL | LOAD_LIBRARY_REQUIRE_SIGNED_TARGET;
    NTSTATUS status;
    HMODULE module;
    WCHAR *load_path, *dummy;

    if (flags & unsupported_flags) DbgPrint( "load_library :: unsupported flag(s) used %#08x\n", flags );

	status = LdrGetDllPath( libname->Buffer, flags, &load_path, &dummy );
	
	if(!NT_SUCCESS(status)){
		SetLastError(status);
		return 0;
	}

    if (flags & (LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE |
                 LOAD_LIBRARY_AS_IMAGE_RESOURCE))
    {
        ULONG_PTR magic;

        LdrLockLoaderLock( 0, NULL, &magic );
        if (!LdrGetDllHandle( load_path, NULL, (PUNICODE_STRING)libname, &module ))
        {
            LdrAddRefDll( 0, module );
            LdrUnlockLoaderLock( 0, magic );
            goto done;
        }
        if (load_library_as_datafile( load_path, flags, libname->Buffer, &module ))
        {
            LdrUnlockLoaderLock( 0, magic );
            goto done;
        }
        LdrUnlockLoaderLock( 0, magic );
        flags |= DONT_RESOLVE_DLL_REFERENCES; /* Just in case */
        /* Fallback to normal behaviour */
    }

    status = LdrLoadDll( load_path, NULL, libname, &module );
    if (status != STATUS_SUCCESS)
    {
        module = 0;
        if (status == STATUS_DLL_NOT_FOUND && (GetVersion() & 0x80000000))
            SetLastError( ERROR_DLL_NOT_FOUND );
        else
            SetLastError( RtlNtStatusToDosError( status ) );
    }
done:
    RtlReleasePath( load_path );
    return module;
}

/***********************************************************************
 *           LoadLibraryExW       (KERNEL32.@)
 *
 * Unicode version of LoadLibraryExA.
 */
HMODULE 
WINAPI 
DECLSPEC_HOTPATCH
LoadLibraryExInternalW(
	LPCWSTR libnameW, 
	HANDLE hfile, 
	DWORD flags
)
{
    UNICODE_STRING      wstr;
    HMODULE             res;
	
	//DbgPrint("LoadLibraryExInternalW:: Module Name: %ws\n",libnameW);
	
	switch(flags){
		case LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE:
		case LOAD_LIBRARY_AS_IMAGE_RESOURCE:
		case LOAD_LIBRARY_SEARCH_APPLICATION_DIR:
		case LOAD_LIBRARY_SEARCH_DEFAULT_DIRS:
		case LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR:
		case LOAD_LIBRARY_SEARCH_SYSTEM32:
		case LOAD_LIBRARY_SEARCH_USER_DIRS:
			if (!libnameW)
			{
				SetLastError(ERROR_INVALID_PARAMETER);
				return 0;
			}
			RtlInitUnicodeString( &wstr, libnameW );
			if (wstr.Buffer[wstr.Length/sizeof(WCHAR) - 1] != ' ')
				return load_library( &wstr, flags );

			/* Library name has trailing spaces */
			RtlCreateUnicodeString( &wstr, libnameW );
			while (wstr.Length > sizeof(WCHAR) &&
				   wstr.Buffer[wstr.Length/sizeof(WCHAR) - 1] == ' ')
			{
				wstr.Length -= sizeof(WCHAR);
			}
			wstr.Buffer[wstr.Length/sizeof(WCHAR)] = '\0';
			res = load_library( &wstr, flags );
			RtlFreeUnicodeString( &wstr );
			break;
		default:
			return LoadLibraryExW(libnameW, hfile, flags);
			
	}
	return res;
}

       // HMODULE __fastcall ForwardDll(_In_z_ const Char* _szLibFileName)
        // {
// #if defined(__ENABLE_WORKAROUND_1_GetProcAddress_ProcessPrng) && (YY_Thunks_Target < __WindowsNT6_1)
            // if (_szLibFileName == nullptr || *_szLibFileName == L'\0')
                // return nullptr;

            // auto _szFileName = _szLibFileName;
            // for (; *_szLibFileName; )
            // {
                // if (*_szLibFileName == Char('\\') || *_szLibFileName == Char('/'))
                // {
                    // ++_szLibFileName;
                    // _szFileName = _szLibFileName;
                // }
                // else
                // {
                    // ++_szLibFileName;
                // }
            // }

// #if defined(__ENABLE_WORKAROUND_1_GetProcAddress_ProcessPrng) && (YY_Thunks_Target < __WindowsNT6_1)
            // if (internal::GetSystemVersion() < internal::MakeVersion(6, 1)
                // && StringCompareIgnoreCaseByAscii(_szFileName, L"bcryptprimitives", 16) == 0)
            // {
                // _szFileName += 16;
                // if (*_szFileName == L'\0' || StringCompareIgnoreCaseByAscii(_szFileName, ".dll", -1) == 0)
                // {
                    // // Windows 7以下平台没有这个DLL，用进程模块句柄伪装一下。
                    // return __FORWARD_DLL_MODULE;
                // }
            // }
// #endif
// #endif 
            // return nullptr;
        // }

// HMODULE
// WINAPI
// LoadLibraryExW
   // _In_ LPCWSTR lpLibFileName,
   // _Reserved_ HANDLE hFile,
   // _In_ DWORD dwFlags
   // )
// {
	// wchar_t szFilePathBuffer[1024];
	// PPEB pPeb;
	// DWORD dwLoadLibrarySearchFlags;
	// ULONG PathType;
	// DWORD nSize;
	// LPCWSTR Str;
	// DWORD nBufferMax;
	// ULONG nBuffer;
	// UNICODE_STRING ModuleFileName;
        // // const auto pLoadLibraryExW = try_get_LoadLibraryExW();

        // // if (!pLoadLibraryExW)
        // // {
            // // SetLastError(ERROR_FUNCTION_FAILED);
            // // return NULL;
        // // }


        // // if (dwFlags == 0 || try_get_AddDllDirectory() != NULL)
        // // {
            // // //存在AddDllDirectory说明支持 LOAD_LIBRARY_SEARCH_SYSTEM32 等功能，直接调用pLoadLibraryExW即可。

            // // auto _hModule = pLoadLibraryExW(lpLibFileName, hFile, dwFlags);
            // // if (_hModule)
                // // return _hModule;

            // // return Fallback::ForwardDll(lpLibFileName);
        // // }

// //#if (YY_Thunks_Target < __WindowsNT6)
        // //Windows Vista开始才支持 LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE，对于不支持的系统我们只能Fallblack到 LOAD_LIBRARY_AS_DATAFILE
        // if (dwFlags & (LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        // {
            // pPeb = ((TEB*)NtCurrentTeb())->ProcessEnvironmentBlock;

            // if (pPeb->OSMajorVersion < 6)
            // {
                // dwFlags &= ~(LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
                // dwFlags |= LOAD_LIBRARY_AS_DATAFILE;
            // }
        // }
// //#endif
        

        // do
        // {
            // dwLoadLibrarySearchFlags = dwFlags & 0xFFFFFF00;

            // if (dwLoadLibrarySearchFlags == 0)
            // {
                // break;
            // }

            // if (((LOAD_WITH_ALTERED_SEARCH_PATH | 0xFFFFE000 | 0x00000004) & dwFlags) || lpLibFileName == NULL || hFile)
            // {
                // //LOAD_WITH_ALTERED_SEARCH_PATH 标记不允许跟其他标记组合使用
                // //0xFFFFE000 为 其他不支持的数值
                // //LOAD_PACKAGED_LIBRARY: 0x00000004 Windows 8以上平台才支持
                // SetLastError(ERROR_INVALID_PARAMETER);
                // return NULL;
            // }

            // dwFlags &= 0xFF;

            // //LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_USER_DIRS | LOAD_LIBRARY_SEARCH_SYSTEM32 等价于 LOAD_LIBRARY_SEARCH_DEFAULT_DIRS标记
            // if (dwLoadLibrarySearchFlags & LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)
                // dwLoadLibrarySearchFlags = (dwLoadLibrarySearchFlags & ~LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) | (LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_USER_DIRS | LOAD_LIBRARY_SEARCH_SYSTEM32);



            // if (dwLoadLibrarySearchFlags == (LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_USER_DIRS | LOAD_LIBRARY_SEARCH_SYSTEM32))
            // {
                // //如果确定是调用默认体系，则直接调用原始 LoadLibraryExW

                // break;
            // }
			
			// PathType = RtlDetermineDosPathNameType_U(lpLibFileName);

            // if (dwLoadLibrarySearchFlags & LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR)
            // {
                // //必须是一个完整路径！
                // if (PathType == RtlPathTypeUnknown || PathType == RtlPathTypeDriveRelative || PathType == RtlPathTypeRelative)
                // {
                    // SetLastError(ERROR_INVALID_PARAMETER);
                    // return NULL;
                // }

                // if (dwLoadLibrarySearchFlags == (LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_USER_DIRS | LOAD_LIBRARY_SEARCH_SYSTEM32))
                // {
                    // //LOAD_WITH_ALTERED_SEARCH_PATH参数能模拟 LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_USER_DIRS | LOAD_LIBRARY_SEARCH_SYSTEM32 组合效果。
                    // dwFlags |= LOAD_WITH_ALTERED_SEARCH_PATH;
                    // break;
                // }
            // }		


            // if (LOAD_LIBRARY_SEARCH_USER_DIRS & dwLoadLibrarySearchFlags)
            // {
                // //LOAD_LIBRARY_SEARCH_USER_DIRS 无法顺利实现，索性无效参数处理
                // SetLastError(ERROR_INVALID_PARAMETER);
                // return NULL;
            // }




            // if (dwFlags & (LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE))
            // {
                // //以资源方式加载

                // //判断路径是一个绝对路径还是一个相对路径，如果是绝对路径，那么可以直接无视 LOAD_LIBRARY_SEARCH_ 系列参数。
                // if ((PathType == RtlPathTypeUnknown || PathType == RtlPathTypeDriveRelative || PathType == RtlPathTypeRelative) == FALSE)
                // {
                    // //是一个绝对路径，我们直接传递给 pLoadLibraryExW 即可

                    // break;
                // }

                // if (dwLoadLibrarySearchFlags & LOAD_LIBRARY_SEARCH_APPLICATION_DIR)
                // {
                    // nSize = GetModuleFileNameW(NULL, szFilePathBuffer, _countof(szFilePathBuffer));

                    // if (nSize == 0 || nSize >= _countof(szFilePathBuffer))
                    // {
                        // SetLastError(ERROR_FUNCTION_FAILED);
                        // return NULL;
                    // }

                    // for (;;)
                    // {
                        // if (szFilePathBuffer[nSize] == L'\\' || szFilePathBuffer[nSize] == L'/')
                        // {
                            // ++nSize;
                            // break;
                        // }

                        // if (nSize == 0)
                        // {
                            // SetLastError(ERROR_FUNCTION_FAILED);
                            // return NULL;
                        // }

                        // --nSize;
                    // }


                    // for (Str = lpLibFileName; *Str; ++Str, ++nSize)
                    // {
                        // if (nSize >= _countof(szFilePathBuffer))
                        // {
                            // SetLastError(ERROR_FUNCTION_FAILED);
                            // return NULL;
                        // }

                        // szFilePathBuffer[nSize] = *Str;
                    // }

                    // szFilePathBuffer[nSize] = L'\0';


                    // if (GetFileAttributesW(szFilePathBuffer) != -1)
                    // {
                        // lpLibFileName = szFilePathBuffer;
                        // break;
                    // }
                // }

                // if (dwLoadLibrarySearchFlags & LOAD_LIBRARY_SEARCH_SYSTEM32)
                // {
                    // nSize = GetSystemDirectoryW(szFilePathBuffer, _countof(szFilePathBuffer));

                    // if (nSize == 0 || nSize >= _countof(szFilePathBuffer))
                    // {
                        // SetLastError(ERROR_FUNCTION_FAILED);
                        // return NULL;
                    // }

                    // if (szFilePathBuffer[nSize] != L'\\')
                    // {
                        // if (nSize >= _countof(szFilePathBuffer))
                        // {
                            // SetLastError(ERROR_FUNCTION_FAILED);
                            // return NULL;
                        // }

                        // szFilePathBuffer[++nSize] = L'\\';
                    // }

                    // for (Str = lpLibFileName; *Str; ++Str, ++nSize)
                    // {
                        // if (nSize >= _countof(szFilePathBuffer))
                        // {
                            // SetLastError(ERROR_FUNCTION_FAILED);
                            // return NULL;
                        // }

                        // szFilePathBuffer[nSize] = *Str;
                    // }

                    // szFilePathBuffer[nSize] = L'\0';

                    // if (GetFileAttributesW(szFilePathBuffer) != -1)
                    // {
                        // lpLibFileName = szFilePathBuffer;
                        // break;
                    // }
                // }

                // SetLastError(ERROR_MOD_NOT_FOUND);
                // return NULL;
            // }


            // // //以模块方式加载
// // #if !defined(__USING_NTDLL_LIB)
            // // const auto LdrLoadDll = try_get_LdrLoadDll();
            // // if (!LdrLoadDll)
            // // {
                // // SetLastError(ERROR_FUNCTION_FAILED);
                // // return NULL;
            // // }
// // #endif

            // nSize = 0;

            // if (dwLoadLibrarySearchFlags & LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR)
            // {
                // for (Str = lpLibFileName; *Str; ++Str, ++nSize)
                // {
                    // if (nSize >= _countof(szFilePathBuffer))
                    // {
                        // SetLastError(ERROR_FUNCTION_FAILED);
                        // return NULL;
                    // }

                    // szFilePathBuffer[nSize] = *Str;
                // }

                // if (nSize == 0)
                // {
                    // SetLastError(ERROR_FUNCTION_FAILED);
                    // return NULL;
                // }

                // --nSize;
                // //反向剔除文件名
                // for (;;)
                // {
                    // if (szFilePathBuffer[nSize] == L'\\' || szFilePathBuffer[nSize] == L'/')
                    // {
                        // break;
                    // }

                    // if (nSize == 0)
                    // {
                        // SetLastError(ERROR_FUNCTION_FAILED);
                        // return NULL;
                    // }

                    // --nSize;
                // }

                // ++nSize;
                // szFilePathBuffer[nSize] = L';';
                // ++nSize;
            // }

            // if (dwLoadLibrarySearchFlags & LOAD_LIBRARY_SEARCH_APPLICATION_DIR)
            // {
                // nBufferMax = _countof(szFilePathBuffer) - nSize;

                // nBuffer = GetModuleFileNameW(NULL, szFilePathBuffer + nSize, nBufferMax);

                // if (nBuffer == 0 || nBuffer >= nBufferMax)
                // {
                    // SetLastError(ERROR_FUNCTION_FAILED);
                    // return NULL;
                // }

                // nSize += nBuffer - 1;

                // for (;;)
                // {
                    // if (szFilePathBuffer[nSize] == L'\\' || szFilePathBuffer[nSize] == L'/')
                    // {
                        // break;
                    // }

                    // if (nSize == 0)
                    // {
                        // SetLastError(ERROR_FUNCTION_FAILED);
                        // return NULL;
                    // }

                    // --nSize;
                // }

                // ++nSize;
                // szFilePathBuffer[nSize] = L';';
                // ++nSize;
            // }

            // if (dwLoadLibrarySearchFlags & LOAD_LIBRARY_SEARCH_SYSTEM32)
            // {
                // nBufferMax = _countof(szFilePathBuffer) - nSize;

                // nBuffer = GetSystemDirectoryW(szFilePathBuffer + nSize, nBufferMax);

                // if (nBuffer == 0 || nBuffer >= nBufferMax)
                // {
                    // SetLastError(ERROR_FUNCTION_FAILED);
                    // return NULL;
                // }

                // nSize += nBuffer;
            // }

            // szFilePathBuffer[nSize] = L'\0';
            
            // ModuleFileName.Buffer = (PWSTR)lpLibFileName;

            // for (; *lpLibFileName; ++lpLibFileName);
            // const auto _uNewLength = (lpLibFileName - ModuleFileName.Buffer) * sizeof(lpLibFileName[0]);
            // if (_uNewLength + sizeof(lpLibFileName[0]) > MAXUINT16)
            // {
                // SetLastError(ERROR_INVALID_PARAMETER);
                // return NULL;
            // }

            // ModuleFileName.Length = static_cast<USHORT>(_uNewLength);
            // ModuleFileName.MaximumLength = ModuleFileName.Length + sizeof(lpLibFileName[0]);

            // HMODULE hModule = NULL;

            // ULONG dwLdrLoadDllFlags = 0;

            // if (dwFlags & DONT_RESOLVE_DLL_REFERENCES)
            // {
                // dwLdrLoadDllFlags |= 0x2;
            // }

            // if (dwFlags & LOAD_IGNORE_CODE_AUTHZ_LEVEL)
            // {
                // dwLdrLoadDllFlags |= 0x1000;
            // }

            // if (dwFlags & LOAD_LIBRARY_REQUIRE_SIGNED_TARGET)
            // {
                // dwLdrLoadDllFlags |= 0x800000;
            // }

// #if defined(_M_IX86) && YY_Thunks_Target < __WindowsNT6_1_SP1
            // //我们先关闭重定向，再加载DLL，Windows 7 SP1以前的系统不会关闭重定向，而导致某些线程关闭重定向后DLL加载问题。
            // PVOID OldFsRedirectionLevel;

            // auto pRtlWow64EnableFsRedirectionEx = try_get_RtlWow64EnableFsRedirectionEx();
            // auto StatusFsRedir = pRtlWow64EnableFsRedirectionEx ? pRtlWow64EnableFsRedirectionEx(NULL, &OldFsRedirectionLevel) : 0;
// #endif

            // LONG Status = LdrLoadDll(szFilePathBuffer, &dwLdrLoadDllFlags, &ModuleFileName, &hModule);

// #if defined(_M_IX86) && YY_Thunks_Target < __WindowsNT6_1_SP1
            // if (StatusFsRedir >= 0 && pRtlWow64EnableFsRedirectionEx)
                // pRtlWow64EnableFsRedirectionEx(OldFsRedirectionLevel, &OldFsRedirectionLevel);
// #endif
            // if (Status < 0)
            // {
                // BaseSetLastNTError(Status);
            // }

            // if (hModule)
                // return hModule;

            // return Fallback::ForwardDll(lpLibFileName);
        // } while (FALSE);

// // #if defined(_M_IX86) && YY_Thunks_Target < __WindowsNT6_1_SP1
        // // //我们先关闭重定向，再加载DLL，Windows 7 SP1以前的系统不会关闭重定向，而导致某些线程关闭重定向后DLL加载问题。
        // // PVOID OldFsRedirectionLevel;

        // // auto pRtlWow64EnableFsRedirectionEx = try_get_RtlWow64EnableFsRedirectionEx();
        // // auto StatusFsRedir = pRtlWow64EnableFsRedirectionEx ? pRtlWow64EnableFsRedirectionEx(NULL, &OldFsRedirectionLevel) : 0;
// // #endif

        // // auto hModule = pLoadLibraryExW(lpLibFileName, hFile, dwFlags);

// // #if defined(_M_IX86) && YY_Thunks_Target < __WindowsNT6_1_SP1
        // // if (StatusFsRedir >= 0 && pRtlWow64EnableFsRedirectionEx)
        // // {
            // // LSTATUS lStatus = GetLastError();
            // // pRtlWow64EnableFsRedirectionEx(OldFsRedirectionLevel, &OldFsRedirectionLevel);
            // // SetLastError(lStatus);
        // // }
// // #endif
        // if(hModule)
            // return hModule;

        // return Fallback::ForwardDll(lpLibFileName);
    // }

/***********************************************************************
 *           FILE_name_AtoW
 *
 * Convert a file name to Unicode, taking into account the OEM/Ansi API mode.
 *
 * If alloc is FALSE uses the TEB static buffer, so it can only be used when
 * there is no possibility for the function to do that twice, taking into
 * account any called function.
 */
WCHAR *FILE_name_AtoW( LPCSTR name, BOOL alloc )
{
    ANSI_STRING str;
    UNICODE_STRING strW, *pstrW;
    NTSTATUS status;

    RtlInitAnsiString( &str, name );
    pstrW = alloc ? &strW : &NtCurrentTeb()->StaticUnicodeString;
    if (oem_file_apis)
        status = RtlOemStringToUnicodeString( pstrW, &str, alloc );
    else
        status = RtlAnsiStringToUnicodeString( pstrW, &str, alloc );
    if (status == STATUS_SUCCESS) return pstrW->Buffer;

    if (status == STATUS_BUFFER_OVERFLOW)
        SetLastError( ERROR_FILENAME_EXCED_RANGE );
    else
        SetLastError( RtlNtStatusToDosError(status) );
    return NULL;
}

/******************************************************************
 *		LoadLibraryExA          (KERNEL32.@)
 *
 * Load a dll file into the process address space.
 *
 * PARAMS
 *  libname [I] Name of the file to load
 *  hfile   [I] Reserved, must be 0.
 *  flags   [I] Flags for loading the dll
 *
 * RETURNS
 *  Success: A handle to the loaded dll.
 *  Failure: A NULL handle. Use GetLastError() to determine the cause.
 *
 * NOTES
 * The HFILE parameter is not used and marked reserved in the SDK. I can
 * only guess that it should force a file to be mapped, but I rather
 * ignore the parameter because it would be extremely difficult to
 * integrate this with different types of module representations.
 */
HMODULE 
WINAPI 
DECLSPEC_HOTPATCH 
LoadLibraryExInternalA(
	LPCSTR libname, 
	HANDLE hfile, 
	DWORD flags
)
{
    WCHAR *libnameW;

    if (!(libnameW = FILE_name_AtoW( libname, FALSE ))) return 0;
	
	DbgPrint("LoadLibraryExInternalA:: Module Name: %s\n",libname);	
	
    return LoadLibraryExInternalW( libnameW, hfile, flags );
}

/****************************************************************************
 *              AddDllDirectory   (KERNEL32.@)
 */
DLL_DIRECTORY_COOKIE WINAPI AddDllDirectory( const WCHAR *dir )
{
    UNICODE_STRING str;
    void *cookie;
	NTSTATUS Status;

    RtlInitUnicodeString( &str, dir );
	
	Status = LdrAddDllDirectory( &str, &cookie );

	if(!NT_SUCCESS(Status)){
		return NULL;
	}	
	
    return cookie;
}


/****************************************************************************
 *              RemoveDllDirectory   (KERNEL32.@)
 */
BOOL WINAPI RemoveDllDirectory( DLL_DIRECTORY_COOKIE cookie )
{
	NTSTATUS Status;
	
	Status = LdrRemoveDllDirectory( cookie );
	
	if(NT_SUCCESS(Status)){
		return TRUE;
	}else{
		SetLastError(Status);
		return FALSE;
	}
}

/*************************************************************************
 *	SetDefaultDllDirectories   (kernelex.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH SetDefaultDllDirectories( DWORD flags )
{
	NTSTATUS Status;
	
	Status = LdrSetDefaultDllDirectories( flags );
	
	if(NT_SUCCESS(Status)){
		return TRUE;
	}else{
		SetLastError(Status);
		return FALSE;
	}
}

/*************************************************************************
 *           SetSearchPathMode   (KERNEL32.@)
 */
BOOL WINAPI SetSearchPathMode( DWORD flags )
{
	NTSTATUS Status;
	
	Status = RtlSetSearchPathMode( flags );
		
	if(NT_SUCCESS(Status)){
		return TRUE;
	}else{
		SetLastError(Status);
		return FALSE;
	}	
}

WCHAR szAppInit[KEY_LENGTH];

BOOL
GetDllList()
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Attributes;
    BOOL bRet = FALSE;
    BOOL bLoad;
    HANDLE hKey = NULL;
    DWORD dwSize;
    PKEY_VALUE_PARTIAL_INFORMATION kvpInfo = NULL;

    UNICODE_STRING szKeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows");
    UNICODE_STRING szLoadName = RTL_CONSTANT_STRING(L"LoadAppInit_DLLs");
    UNICODE_STRING szDllsName = RTL_CONSTANT_STRING(L"AppInit_DLLs");

    InitializeObjectAttributes(&Attributes, &szKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenKey(&hKey, KEY_READ, &Attributes);
    if (NT_SUCCESS(Status))
    {
        dwSize = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(DWORD);
        kvpInfo = HeapAlloc(GetProcessHeap(), 0, dwSize);
        if (!kvpInfo)
            goto end;

        Status = NtQueryValueKey(hKey,
                                 &szLoadName,
                                 KeyValuePartialInformation,
                                 kvpInfo,
                                 dwSize,
                                 &dwSize);
        if (!NT_SUCCESS(Status))
            goto end;

        RtlMoveMemory(&bLoad,
                      kvpInfo->Data,
                      kvpInfo->DataLength);

        HeapFree(GetProcessHeap(), 0, kvpInfo);
        kvpInfo = NULL;

        if (bLoad)
        {
            Status = NtQueryValueKey(hKey,
                                     &szDllsName,
                                     KeyValuePartialInformation,
                                     NULL,
                                     0,
                                     &dwSize);
            if (Status != STATUS_BUFFER_TOO_SMALL)
                goto end;

            kvpInfo = HeapAlloc(GetProcessHeap(), 0, dwSize);
            if (!kvpInfo)
                goto end;

            Status = NtQueryValueKey(hKey,
                                     &szDllsName,
                                     KeyValuePartialInformation,
                                     kvpInfo,
                                     dwSize,
                                     &dwSize);
            if (NT_SUCCESS(Status))
            {
                LPWSTR lpBuffer = (LPWSTR)kvpInfo->Data;
                if (*lpBuffer != UNICODE_NULL)
                {
                    INT bytesToCopy, nullPos;

                    bytesToCopy = min(kvpInfo->DataLength, KEY_LENGTH * sizeof(WCHAR));

                    if (bytesToCopy != 0)
                    {
                        RtlMoveMemory(szAppInit,
                                      kvpInfo->Data,
                                      bytesToCopy);

                        nullPos = (bytesToCopy / sizeof(WCHAR)) - 1;

                        /* ensure string is terminated */
                        szAppInit[nullPos] = UNICODE_NULL;

                        bRet = TRUE;
                    }
                }
            }
        }
    }

end:
    if (hKey)
        NtClose(hKey);

    if (kvpInfo)
        HeapFree(GetProcessHeap(), 0, kvpInfo);

    return bRet;
}

VOID
WINAPI
LoadAppInitDlls()
{
    szAppInit[0] = UNICODE_NULL;

    if (GetDllList())
    {
        WCHAR buffer[KEY_LENGTH];
        LPWSTR ptr;
		size_t i;

        RtlCopyMemory(buffer, szAppInit, KEY_LENGTH * sizeof(WCHAR) );

		for (i = 0; i < KEY_LENGTH; ++ i)
		{
			if(buffer[i] == L' ' || buffer[i] == L',')
				buffer[i] = 0;
		}

		for (i = 0; i < KEY_LENGTH; )
		{
			if(buffer[i] == 0)
				++ i;
			else
			{
				ptr = buffer + i;
				i += wcslen(ptr);
				LoadLibraryW(ptr);
			}
		}
    }
}

PVOID 
WINAPI 
BasepMapModuleHandle( 	
	HMODULE  	hModule,
	BOOLEAN  	AsDataFile 
)
{
    /* If no handle is provided - use current image base address */
    if (!hModule) return NtCurrentPeb()->ImageBaseAddress;

    /* Check if it's a normal or a datafile one */
    if (LDR_IS_DATAFILE(hModule) && !AsDataFile)
        return NULL;

    /* It'a a normal DLL, just return its handle */
    return hModule;
}

BOOL 
WINAPI 
EnumResourceNamesExW(
	HMODULE hModule, 
	LPCWSTR lpType, 
	ENUMRESNAMEPROCW lpEnumFunc, 
	LONG_PTR lParam, 
	DWORD dwFlags, 
	LANGID LangId
)
{
	return EnumResourceNamesW(hModule, lpType, lpEnumFunc, lParam);
}	

BOOL 
WINAPI 
EnumResourceNamesExA(
	HMODULE hModule, 
	LPCSTR lpType, 
	ENUMRESNAMEPROCA lpEnumFunc, 
	LONG_PTR lParam, 
	DWORD dwFlags, 
	LANGID LangId)
{
	return EnumResourceNamesA(hModule, lpType, lpEnumFunc, lParam);
}	

BOOL WINAPI EnumResourceTypesExA(
  _In_opt_  HMODULE hModule,
  _In_      ENUMRESTYPEPROCA lpEnumFunc,
  _In_      LONG_PTR lParam,
  _In_      DWORD dwFlags,
  _In_      LANGID LangId
)	
{
	return EnumResourceTypesA(hModule, lpEnumFunc, lParam);
}

BOOL WINAPI EnumResourceTypesExW(
  _In_opt_  HMODULE hModule,
  _In_      ENUMRESTYPEPROCW lpEnumFunc,
  _In_      LONG_PTR lParam,
  _In_      DWORD dwFlags,
  _In_      LANGID LangId
)	
{
	return EnumResourceTypesW(hModule, lpEnumFunc, lParam);
}	

static BOOL init_module_iterator( struct module_iterator *iter, HANDLE process )
{
    PROCESS_BASIC_INFORMATION pbi;
    PPEB_LDR_DATA ldr_data;
	NTSTATUS status;

    if (!IsWow64Process( process, &iter->wow64 )) return FALSE;

	status = NtQueryInformationProcess( process, ProcessBasicInformation,
                                                  &pbi, sizeof(pbi), NULL );

    /* get address of PEB */
    if (!NT_SUCCESS(status))
	{
		RtlNtStatusToDosError(status);
        return FALSE;		
	}

    if (is_win64 && iter->wow64)
    {
        PEB_LDR_DATA32 *ldr_data32_ptr;
        DWORD ldr_data32, first_module;
        PEB32 *peb32;

        peb32 = (PEB32 *)(DWORD_PTR)pbi.PebBaseAddress;
#ifdef _M_IX86		
        if (!ReadProcessMemory( process, &peb32->LdrData, &ldr_data32, sizeof(ldr_data32), NULL ))
#else
        if (!ReadProcessMemory( process, &peb32->Ldr, &ldr_data32, sizeof(ldr_data32), NULL ))	
#endif
            return FALSE;
        ldr_data32_ptr = (PEB_LDR_DATA32 *)(DWORD_PTR) ldr_data32;
        if (!ReadProcessMemory( process, &ldr_data32_ptr->InLoadOrderModuleList.Flink,
                                &first_module, sizeof(first_module), NULL ))
            return FALSE;
        iter->head = (LIST_ENTRY *)&ldr_data32_ptr->InLoadOrderModuleList;
        iter->current = (LIST_ENTRY *)(DWORD_PTR)first_module;
        iter->process = process;
        return TRUE;
    }

    /* read address of LdrData from PEB */
    if (!ReadProcessMemory( process, &pbi.PebBaseAddress->Ldr, &ldr_data, sizeof(ldr_data), NULL ))
        return FALSE;

    /* read address of first module from LdrData */
    if (!ReadProcessMemory( process, &ldr_data->InLoadOrderModuleList.Flink,
                            &iter->current, sizeof(iter->current), NULL ))
        return FALSE;

    iter->head = &ldr_data->InLoadOrderModuleList;
    iter->process = process;
    return TRUE;
}


static int module_iterator_next( struct module_iterator *iter )
{
    if (iter->current == iter->head) return 0;

    if (is_win64 && iter->wow64)
    {
        LIST_ENTRY32 *entry32 = (LIST_ENTRY32 *)iter->current;

        if (!ReadProcessMemory( iter->process,
                                CONTAINING_RECORD(entry32, LDR_DATA_TABLE_ENTRY32, InLoadOrderModuleList),
                                &iter->ldr_module32, sizeof(iter->ldr_module32), NULL ))
            return -1;
        iter->current = (LIST_ENTRY *)(DWORD_PTR)iter->ldr_module32.InLoadOrderModuleList.Flink;
        return 1;
    }

    if (!ReadProcessMemory( iter->process,
                            CONTAINING_RECORD(iter->current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks),
                            &iter->ldr_module, sizeof(iter->ldr_module), NULL ))
         return -1;

    iter->current = iter->ldr_module.InLoadOrderLinks.Flink;
    return 1;
}

/***********************************************************************
 *         K32EnumProcessModules   (kernelex.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH K32EnumProcessModules( HANDLE process, HMODULE *module,
                                                     DWORD count, DWORD *needed )
{
    struct module_iterator iter;
    DWORD size = 0;
    INT ret;

    if (process == GetCurrentProcess())
    {
        PPEB_LDR_DATA ldr_data = NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;
        PLIST_ENTRY head = &ldr_data->InLoadOrderModuleList;
        PLIST_ENTRY entry = head->Flink;

        if (count && !module)
        {
            SetLastError( ERROR_NOACCESS );
            return FALSE;
        }
        while (entry != head)
        {
            LDR_DATA_TABLE_ENTRY *ldr = CONTAINING_RECORD( entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
            if (count >= sizeof(HMODULE))
            {
                *module++ = ldr->DllBase;
                count -= sizeof(HMODULE);
            }
            size += sizeof(HMODULE);
            entry = entry->Flink;
        }
        if (!needed)
        {
            SetLastError( ERROR_NOACCESS );
            return FALSE;
        }
        *needed = size;
        return TRUE;
    }

    if (!init_module_iterator( &iter, process )) return FALSE;

    if (count && !module)
    {
        SetLastError( ERROR_NOACCESS );
        return FALSE;
    }

    while ((ret = module_iterator_next( &iter )) > 0)
    {
        if (count >= sizeof(HMODULE))
        {
            if (sizeof(void *) == 8 && iter.wow64)
                *module++ = (HMODULE) (DWORD_PTR)iter.ldr_module32.BaseAddress;
            else
                *module++ = iter.ldr_module.DllBase;
            count -= sizeof(HMODULE);
        }
        size += sizeof(HMODULE);
    }

    if (!needed)
    {
        SetLastError( ERROR_NOACCESS );
        return FALSE;
    }
    *needed = size;
    return ret == 0;
}

/***********************************************************************
 *         K32EnumProcessModulesEx   (kernelex.@)
 */
BOOL WINAPI K32EnumProcessModulesEx( HANDLE process, HMODULE *module, DWORD count,
                                     DWORD *needed, DWORD filter )
{
    FIXME( "(%p, %p, %d, %p, %d) semi-stub\n", process, module, count, needed, filter );
    return K32EnumProcessModules( process, module, count, needed );
}

BOOL
WINAPI
GetWsChangesEx(
     _In_ HANDLE hProcess,
    _Out_writes_bytes_to_(*cb, *cb) PPSAPI_WS_WATCH_INFORMATION_EX lpWatchInfoEx,
    _Inout_ PDWORD cb
    )
{
    // // FIXME( "(%p, %p, %p)\n", process, info, size );
    // // SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    // // return FALSE;

        // PPSAPI_WS_WATCH_INFORMATION pWatchInfo = NULL;
        // PPSAPI_WS_WATCH_INFORMATION pWatchInfoTerminated;
		// PPSAPI_WS_WATCH_INFORMATION pWatchInfoMax;
        // PPSAPI_WS_WATCH_INFORMATION pNewWatchInfo;
        // DWORD cbWatchInfo = 1024 * sizeof(pWatchInfo[0]);
        // HANDLE ProcessHeap = ((TEB*)NtCurrentTeb())->ProcessEnvironmentBlock->ProcessHeap;
        // LSTATUS lStatus = ERROR_SUCCESS;
		// int i ;
		// DWORD ccWatchInfo;
		// DWORD cbWatchInfoExRequest;
		// DWORD cbBuffer;

        // for (;;)
        // {
            // if (pWatchInfo)
            // {
                // cbWatchInfo *= 2;
            
                // pNewWatchInfo = (PPSAPI_WS_WATCH_INFORMATION)HeapReAlloc(ProcessHeap, 0, pWatchInfo, cbWatchInfo);

                // if (!pNewWatchInfo)
                // {
                    // lStatus = ERROR_OUTOFMEMORY;
                    // break;
                // }

                // pWatchInfo = pNewWatchInfo;
            // }
            // else
            // {
                // pWatchInfo = (PPSAPI_WS_WATCH_INFORMATION)HeapAlloc(ProcessHeap, 0, cbWatchInfo);
                // if (!pWatchInfo)
                // {
                    // lStatus = ERROR_OUTOFMEMORY;
                    // break;
                // }
            // }

            // if (!GetWsChanges(hProcess, pWatchInfo, cbWatchInfo))
            // {
                // lStatus = GetLastError();

                // if (lStatus == ERROR_INSUFFICIENT_BUFFER)
                // {
                    // continue;

                // }
                // else
                // {
                    // break;
                // }
            // }

            // //确定实际个数
            // pWatchInfoMax = (PPSAPI_WS_WATCH_INFORMATION)((byte*)pWatchInfo + cbWatchInfo);
            // pWatchInfoTerminated = pWatchInfo;
            // for (; pWatchInfoTerminated < pWatchInfoMax && pWatchInfoTerminated->FaultingPc != NULL; ++pWatchInfoTerminated);

            // ccWatchInfo = pWatchInfoTerminated - pWatchInfo;

            // cbWatchInfoExRequest = (ccWatchInfo + 1) * sizeof(lpWatchInfoEx[0]);
            // if (cbWatchInfoExRequest > UINT32_MAX)
            // {
                // lStatus = ERROR_FUNCTION_FAILED;
                // break;
            // }

            // cbBuffer = *cb;
            // *cb = (cbWatchInfoExRequest);

            // if (cbBuffer < cbWatchInfoExRequest)
            // {
                // lStatus = ERROR_INSUFFICIENT_BUFFER;
                // break;
            // }


            // //复制到新缓冲区
            // for (i = 0; i != ccWatchInfo; ++i)
            // {
                // lpWatchInfoEx[i].BasicInfo = pWatchInfo[i];
                // lpWatchInfoEx[i].FaultingThreadId = 0;
                // lpWatchInfoEx[i].Flags = 0;
            // }
        
            // //插入终止标记
            // memset(&lpWatchInfoEx[ccWatchInfo], 0, sizeof(PSAPI_WS_WATCH_INFORMATION_EX));//lpWatchInfoEx[ccWatchInfo] = {0};

            // lStatus = ERROR_SUCCESS;
            // break;
        // }

        // if (pWatchInfo)
        // {
            // HeapFree(ProcessHeap, 0, pWatchInfo);
        // }
    
        // if (lStatus == ERROR_SUCCESS)
        // {
            // return TRUE;
        // }
        // else
        // {
            // SetLastError(lStatus);
            // return FALSE;
        // }	
	  NTSTATUS Status;

	  Status = NtQueryInformationProcess(hProcess, ProcessWorkingSetWatchEx, lpWatchInfoEx, *cb, cb); //class is number 0x2A
	  if ( Status >= 0 )                                                                              //Also new to XP/2003.
		return TRUE;
	  RtlSetLastWin32Error(RtlNtStatusToDosError(Status));
	  return FALSE;		
}

int WINAPI LoadStringBaseExW( HINSTANCE hInstance, UINT uID, LPWSTR lpBuffer, 
  int nBufferMax, INT unknown ) {
    if (unknown) {
        // add debug print
        unknown = 0;
    }
    return LoadStringW(hInstance, uID, lpBuffer, nBufferMax);
}