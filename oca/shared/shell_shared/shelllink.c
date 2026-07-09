/*++
Copyright (c) 2025  Shorthorn Project

Module Name:

    shelllink.c

Abstract:

    This module implements Interface Functions for Shell Link APIs 

Author:

    Skulltrail 27-October-2025

Revision History:

--*/

#define COBJMACROS
#define NONAMELESSUNION

#include "wine/debug.h"
#include "winerror.h"
#include "windef.h"
#include "winbase.h"
#include "winnls.h"
#include "winreg.h"

#include "winuser.h"
#include "wingdi.h"
#include "shlobj.h"

#include "pidl.h"
#include "main.h"
#include "shlguid.h"
#include "shlwapi.h"
#include "msi.h"
#include "appmgmt.h"

#include "initguid.h"

WINE_DEFAULT_DEBUG_CHANNEL(shell);

DEFINE_GUID( SHELL32_AdvtShortcutProduct,
       0x9db1186f,0x40df,0x11d1,0xaa,0x8c,0x00,0xc0,0x4f,0xb6,0x78,0x63);
DEFINE_GUID( SHELL32_AdvtShortcutComponent,
       0x9db1186e,0x40df,0x11d1,0xaa,0x8c,0x00,0xc0,0x4f,0xb6,0x78,0x63);

/* link file formats */

#include "pshpack1.h"

typedef struct _LINK_HEADER
{
	DWORD    dwSize;	/* 0x00 size of the header - 0x4c */
	GUID     MagicGuid;	/* 0x04 is CLSID_ShellLink */
	DWORD    dwFlags;	/* 0x14 describes elements following */
	DWORD    dwFileAttr;	/* 0x18 attributes of the target file */
	FILETIME CreationTime;	/* 0x1c creation time of target file */
	FILETIME AccessTime;	/* 0x24 access time of target file */
	FILETIME WriteTime;	/* 0x2c write time of target file */
	DWORD    dwFileSize;	/* 0x34 File size of target file */
	DWORD    nIcon;		/* 0x38 icon number or index */
	DWORD	fStartup;	/* 0x3c startup type or window state of application */
	WORD	wHotKey;	/* 0x40 hotkey */
	WORD	Reserved1;	/* 0x42 reserved = 0 */
	DWORD	Reserved2;	/* 0x44 reserved = 0 */
	DWORD	Reserved3;	/* 0x48 reserved = 0 */
} LINK_HEADER, * PLINK_HEADER;

#define SHLINK_LOCAL  0
#define SHLINK_REMOTE 1

typedef struct _LOCATION_INFO
{
    DWORD  dwTotalSize;
    DWORD  dwHeaderSize;
    DWORD  dwFlags;
    DWORD  dwVolTableOfs;
    DWORD  dwLocalPathOfs;
    DWORD  dwNetworkVolTableOfs;
    DWORD  dwFinalPathOfs;
} LOCATION_INFO;

typedef struct _LOCAL_VOLUME_INFO
{
    DWORD dwSize;
    DWORD dwType;
    DWORD dwVolSerial;
    DWORD dwVolLabelOfs;
} LOCAL_VOLUME_INFO;

typedef struct volume_info_t
{
    DWORD type;
    DWORD serial;
    WCHAR label[12];  /* assume 8.3 */
} volume_info;

#include "poppack.h"

/* IShellLink Implementation */

typedef struct
{
        IShellLinkA IShellLinkA_iface;
        IShellLinkW IShellLinkW_iface;
        IPersistFile IPersistFile_iface;
        IPersistStream IPersistStream_iface;
        IShellLinkDataList IShellLinkDataList_iface;
        IShellExtInit IShellExtInit_iface;
        IContextMenu IContextMenu_iface;
        IObjectWithSite IObjectWithSite_iface;
        IPropertyStore IPropertyStore_iface;

	LONG            ref;

	/* data structures according to the information in the link */
	LPITEMIDLIST	pPidl;
	WORD		wHotKey;
	SYSTEMTIME	CreationTime;
	SYSTEMTIME	AccessTime;
	SYSTEMTIME	WriteTime;

	DWORD         iShowCmd;
	LPWSTR        sIcoPath;
	INT           iIcoNdx;
	LPWSTR        sPath;
	LPWSTR        sArgs;
	LPWSTR        sWorkDir;
	LPWSTR        sDescription;
	LPWSTR        sPathRel;
 	LPWSTR        sProduct;
 	LPWSTR        sComponent;
	volume_info   volume;

	BOOL          bDirty;
        INT           iIdOpen;  /* id of the "Open" entry in the context menu */
	IUnknown      *site;

	LPOLESTR      filepath; /* file path returned by IPersistFile::GetCurFile */
	
    /* ponteiros reais para delegação */
    IShellLinkA      *pRealLinkA;
    IShellLinkW      *pRealLinkW;
    IPersistFile     *pRealPersistFile;
    IPersistStream   *pRealPersistStream;
    IShellLinkDataList *pRealDataList;
    IShellExtInit    *pRealShellExtInit;
    IContextMenu     *pRealContextMenu;
    IObjectWithSite  *pRealObjectWithSite;
} IShellLinkImpl;

static inline IShellLinkImpl *impl_from_IShellLinkA(IShellLinkA *iface)
{
    return CONTAINING_RECORD(iface, IShellLinkImpl, IShellLinkA_iface);
}

static inline IShellLinkImpl *impl_from_IShellLinkW(IShellLinkW *iface)
{
    return CONTAINING_RECORD(iface, IShellLinkImpl, IShellLinkW_iface);
}

static inline IShellLinkImpl *impl_from_IPersistFile(IPersistFile *iface)
{
    return CONTAINING_RECORD(iface, IShellLinkImpl, IPersistFile_iface);
}

static inline IShellLinkImpl *impl_from_IPersistStream(IPersistStream *iface)
{
    return CONTAINING_RECORD(iface, IShellLinkImpl, IPersistStream_iface);
}

static inline IShellLinkImpl *impl_from_IShellLinkDataList(IShellLinkDataList *iface)
{
    return CONTAINING_RECORD(iface, IShellLinkImpl, IShellLinkDataList_iface);
}

static inline IShellLinkImpl *impl_from_IShellExtInit(IShellExtInit *iface)
{
    return CONTAINING_RECORD(iface, IShellLinkImpl, IShellExtInit_iface);
}

static inline IShellLinkImpl *impl_from_IContextMenu(IContextMenu *iface)
{
    return CONTAINING_RECORD(iface, IShellLinkImpl, IContextMenu_iface);
}

static inline IShellLinkImpl *impl_from_IObjectWithSite(IObjectWithSite *iface)
{
    return CONTAINING_RECORD(iface, IShellLinkImpl, IObjectWithSite_iface);
}

static inline IShellLinkImpl *impl_from_IPropertyStore(IPropertyStore *iface)
{
    return CONTAINING_RECORD(iface, IShellLinkImpl, IPropertyStore_iface);
}

/* strdup on the process heap */
static inline LPWSTR heap_strdupAtoW( LPCSTR str)
{
    INT len = MultiByteToWideChar( CP_ACP, 0, str, -1, NULL, 0 );
    WCHAR *p = malloc( len * sizeof(WCHAR) );
    if( !p )
        return p;
    MultiByteToWideChar( CP_ACP, 0, str, -1, p, len );
    return p;
}

/**************************************************************************
 *  IPersistFile_QueryInterface
 */
static HRESULT WINAPI IPersistFile_fnQueryInterface(
	IPersistFile* iface,
	REFIID riid,
	LPVOID *ppvObj)
{
    IShellLinkImpl *This = impl_from_IPersistFile(iface);
    return IShellLinkW_QueryInterface(&This->IShellLinkW_iface, riid, ppvObj);
}

/******************************************************************************
 * IPersistFile_AddRef
 */
static ULONG WINAPI IPersistFile_fnAddRef(IPersistFile* iface)
{
    IShellLinkImpl *This = impl_from_IPersistFile(iface);
	IPersistFile_AddRef(This->pRealPersistFile);	
    return IShellLinkW_AddRef(&This->IShellLinkW_iface);
}

/******************************************************************************
 * IPersistFile_Release
 */
static ULONG WINAPI IPersistFile_fnRelease(IPersistFile* iface)
{
    IShellLinkImpl *This = impl_from_IPersistFile(iface);
	IPersistFile_Release(This->pRealPersistFile);	
    return IShellLinkW_Release(&This->IShellLinkW_iface);
}

static HRESULT WINAPI IPersistFile_fnGetClassID(IPersistFile* iface, CLSID *pClassID)
{
	IShellLinkImpl *This = impl_from_IPersistFile(iface);
	HRESULT hr = S_OK;
	hr = IPersistFile_GetClassID(This->pRealPersistFile, pClassID);	
	return hr;	
}

static HRESULT WINAPI IPersistFile_fnIsDirty(IPersistFile* iface)
{
	IShellLinkImpl *This = impl_from_IPersistFile(iface);
	HRESULT hr = S_OK;
	hr = IPersistFile_IsDirty(This->pRealPersistFile);	
	return hr;	
}

static HRESULT WINAPI IPersistFile_fnLoad(IPersistFile* iface, LPCOLESTR pszFileName, DWORD dwMode)
{
	IShellLinkImpl *This = impl_from_IPersistFile(iface);
	HRESULT hr = S_OK;
	hr = IPersistFile_Load(This->pRealPersistFile, pszFileName, dwMode);	
	return hr;	
}

static HRESULT WINAPI IPersistFile_fnSave(IPersistFile* iface, LPCOLESTR pszFileName, BOOL fRemember)
{
	IShellLinkImpl *This = impl_from_IPersistFile(iface);
	HRESULT hr = S_OK;
	hr = IPersistFile_Save(This->pRealPersistFile, pszFileName, fRemember);	
	return hr;	
}

static HRESULT WINAPI IPersistFile_fnSaveCompleted(IPersistFile* iface, LPCOLESTR filename)
{
	IShellLinkImpl *This = impl_from_IPersistFile(iface);
	HRESULT hr = S_OK;
	hr = IPersistFile_SaveCompleted(This->pRealPersistFile, filename);	
	return hr;	
}

static HRESULT WINAPI IPersistFile_fnGetCurFile(IPersistFile* iface, LPOLESTR *filename)
{
	IShellLinkImpl *This = impl_from_IPersistFile(iface);
	HRESULT hr = S_OK;
	hr = IPersistFile_GetCurFile(This->pRealPersistFile, filename);	
	return hr;		
}

static const IPersistFileVtbl pfvt =
{
	IPersistFile_fnQueryInterface,
	IPersistFile_fnAddRef,
	IPersistFile_fnRelease,
	IPersistFile_fnGetClassID,
	IPersistFile_fnIsDirty,
	IPersistFile_fnLoad,
	IPersistFile_fnSave,
	IPersistFile_fnSaveCompleted,
	IPersistFile_fnGetCurFile
};

/************************************************************************
 * IPersistStream_QueryInterface
 */
static HRESULT WINAPI IPersistStream_fnQueryInterface(
	IPersistStream* iface,
	REFIID     riid,
	VOID**     ppvObj)
{
    IShellLinkImpl *This = impl_from_IPersistStream(iface);
    return IShellLinkW_QueryInterface(&This->IShellLinkW_iface, riid, ppvObj);
}

/************************************************************************
 * IPersistStream_Release
 */
static ULONG WINAPI IPersistStream_fnRelease(
	IPersistStream* iface)
{
    IShellLinkImpl *This = impl_from_IPersistStream(iface);
	IPersistStream_Release(This->pRealPersistStream);		
    return IShellLinkW_Release(&This->IShellLinkW_iface);
}

/************************************************************************
 * IPersistStream_AddRef
 */
static ULONG WINAPI IPersistStream_fnAddRef(
	IPersistStream* iface)
{
    IShellLinkImpl *This = impl_from_IPersistStream(iface);
	IPersistStream_AddRef(This->pRealPersistStream);	
    return IShellLinkW_AddRef(&This->IShellLinkW_iface);
}

/************************************************************************
 * IPersistStream_GetClassID
 *
 */
static HRESULT WINAPI IPersistStream_fnGetClassID(
	IPersistStream* iface,
	CLSID* pClassID)
{
	IShellLinkImpl *This = impl_from_IPersistStream(iface);
	HRESULT hr = S_OK;
	hr = IPersistStream_GetClassID(This->pRealPersistStream, pClassID);	
	return hr;	
}

/************************************************************************
 * IPersistStream_IsDirty (IPersistStream)
 */
static HRESULT WINAPI IPersistStream_fnIsDirty(
	IPersistStream*  iface)
{
	IShellLinkImpl *This = impl_from_IPersistStream(iface);
	HRESULT hr = S_OK;
	hr = IPersistStream_IsDirty(This->pRealPersistStream);	
	return hr;		
}

static HRESULT WINAPI IPersistStream_fnLoad(
    IPersistStream*  iface,
    IStream*         stm)
{
	IShellLinkImpl *This = impl_from_IPersistStream(iface);
	HRESULT hr = S_OK;
	hr = IPersistStream_Load(This->pRealPersistStream, stm);	
	return hr;	
}

static HRESULT WINAPI IPersistStream_fnSave(
	IPersistStream*  iface,
	IStream*         stm,
	BOOL             fClearDirty)
{	
	IShellLinkImpl *This = impl_from_IPersistStream(iface);
	HRESULT hr = S_OK;
	hr = IPersistStream_Save(This->pRealPersistStream, stm, fClearDirty);	
	return hr;
}

static HRESULT WINAPI IPersistStream_fnGetSizeMax(
	IPersistStream*  iface,
	ULARGE_INTEGER*  pcbSize)
{
	IShellLinkImpl *This = impl_from_IPersistStream(iface);
	HRESULT hr = S_OK;
	hr = IPersistStream_GetSizeMax(This->pRealPersistStream, pcbSize);	
	return hr;	
}

static const IPersistStreamVtbl psvt =
{
	IPersistStream_fnQueryInterface,
	IPersistStream_fnAddRef,
	IPersistStream_fnRelease,
	IPersistStream_fnGetClassID,
	IPersistStream_fnIsDirty,
	IPersistStream_fnLoad,
	IPersistStream_fnSave,
	IPersistStream_fnGetSizeMax
};

/**************************************************************************
 *  IShellLinkA_QueryInterface
 */
static HRESULT WINAPI IShellLinkA_fnQueryInterface(IShellLinkA *iface, REFIID riid, void **ppvObj)
{
    IShellLinkImpl *This = impl_from_IShellLinkA(iface);
    return IShellLinkW_QueryInterface(&This->IShellLinkW_iface, riid, ppvObj);
}

/******************************************************************************
 * IShellLinkA_AddRef
 */
static ULONG WINAPI IShellLinkA_fnAddRef(IShellLinkA *iface)
{
    IShellLinkImpl *This = impl_from_IShellLinkA(iface);
    return IShellLinkW_AddRef(&This->IShellLinkW_iface);
}

/******************************************************************************
 *	IShellLinkA_Release
 */
static ULONG WINAPI IShellLinkA_fnRelease(IShellLinkA *iface)
{
    IShellLinkImpl *This = impl_from_IShellLinkA(iface);
    return IShellLinkW_Release(&This->IShellLinkW_iface);
}

static HRESULT WINAPI IShellLinkA_fnGetPath(IShellLinkA *iface, LPSTR pszFile, INT cchMaxPath,
        WIN32_FIND_DATAA *pfd, DWORD fFlags)
{
	IShellLinkImpl *This = impl_from_IShellLinkA(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkA_GetPath(This->pRealLinkA, pszFile, cchMaxPath, pfd, fFlags);	
	return hr;	
}

static HRESULT WINAPI IShellLinkA_fnGetIDList(IShellLinkA *iface, LPITEMIDLIST *ppidl)
{
    IShellLinkImpl *This = impl_from_IShellLinkA(iface);
    return IShellLinkW_GetIDList(&This->IShellLinkW_iface, ppidl);
}

static HRESULT WINAPI IShellLinkA_fnSetIDList(IShellLinkA *iface, LPCITEMIDLIST pidl)
{
    IShellLinkImpl *This = impl_from_IShellLinkA(iface);
    return IShellLinkW_SetIDList(&This->IShellLinkW_iface, pidl);
}

static HRESULT WINAPI IShellLinkA_fnGetDescription(IShellLinkA *iface, LPSTR pszName,
        INT cchMaxName)
{
	IShellLinkImpl *This = impl_from_IShellLinkA(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkA_GetDescription(This->pRealLinkA, pszName, cchMaxName);	
	return hr;	
}

static HRESULT WINAPI IShellLinkA_fnSetDescription(IShellLinkA *iface, LPCSTR pszName)
{
	IShellLinkImpl *This = impl_from_IShellLinkA(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkA_SetDescription(This->pRealLinkA, pszName);	
	return hr;	
}

static HRESULT WINAPI IShellLinkA_fnGetWorkingDirectory(IShellLinkA *iface, LPSTR pszDir,
        INT cchMaxPath)
{
	IShellLinkImpl *This = impl_from_IShellLinkA(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkA_GetWorkingDirectory(This->pRealLinkA, pszDir, cchMaxPath);	
	return hr;	
}

static HRESULT WINAPI IShellLinkA_fnSetWorkingDirectory(IShellLinkA *iface, LPCSTR pszDir)
{
	IShellLinkImpl *This = impl_from_IShellLinkA(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkA_SetWorkingDirectory(This->pRealLinkA, pszDir);	
	return hr;	
}

static HRESULT WINAPI IShellLinkA_fnGetArguments(IShellLinkA *iface, LPSTR pszArgs, INT cchMaxPath)
{
	IShellLinkImpl *This = impl_from_IShellLinkA(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkA_GetArguments(This->pRealLinkA, pszArgs, cchMaxPath);	
	return hr;	
}

static HRESULT WINAPI IShellLinkA_fnSetArguments(IShellLinkA *iface, LPCSTR pszArgs)
{
	IShellLinkImpl *This = impl_from_IShellLinkA(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkA_SetArguments(This->pRealLinkA, pszArgs);	
	return hr;	
}

static HRESULT WINAPI IShellLinkA_fnGetHotkey(IShellLinkA *iface, WORD *pwHotkey)
{
    IShellLinkImpl *This = impl_from_IShellLinkA(iface);
    return IShellLinkW_GetHotkey(&This->IShellLinkW_iface, pwHotkey);
}

static HRESULT WINAPI IShellLinkA_fnSetHotkey(IShellLinkA *iface, WORD wHotkey)
{
    IShellLinkImpl *This = impl_from_IShellLinkA(iface);
    return IShellLinkW_SetHotkey(&This->IShellLinkW_iface, wHotkey);
}

static HRESULT WINAPI IShellLinkA_fnGetShowCmd(IShellLinkA *iface, INT *piShowCmd)
{
    IShellLinkImpl *This = impl_from_IShellLinkA(iface);
    return IShellLinkW_GetShowCmd(&This->IShellLinkW_iface, piShowCmd);
}

static HRESULT WINAPI IShellLinkA_fnSetShowCmd(IShellLinkA *iface, INT iShowCmd)
{
    IShellLinkImpl *This = impl_from_IShellLinkA(iface);
    return IShellLinkW_SetShowCmd(&This->IShellLinkW_iface, iShowCmd);
}

static HRESULT WINAPI IShellLinkA_fnGetIconLocation(IShellLinkA *iface, LPSTR pszIconPath,
        INT cchIconPath, INT *piIcon)
{
	IShellLinkImpl *This = impl_from_IShellLinkA(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkA_GetIconLocation(This->pRealLinkA, pszIconPath, cchIconPath, piIcon);	
	return hr;	
}

static HRESULT WINAPI IShellLinkA_fnSetIconLocation(IShellLinkA *iface, LPCSTR path, INT icon)
{
	IShellLinkImpl *This = impl_from_IShellLinkA(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkA_SetIconLocation(This->pRealLinkA, path, icon);	
	return hr;	
}

static HRESULT WINAPI IShellLinkA_fnSetRelativePath(IShellLinkA *iface, LPCSTR pszPathRel,
        DWORD dwReserved)
{
	IShellLinkImpl *This = impl_from_IShellLinkA(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkA_SetRelativePath(This->pRealLinkA, pszPathRel, dwReserved);	
	return hr;	
}

static HRESULT WINAPI IShellLinkA_fnResolve(IShellLinkA *iface, HWND hwnd, DWORD fFlags)
{
	IShellLinkImpl *This = impl_from_IShellLinkA(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkA_Resolve(This->pRealLinkA, hwnd, fFlags);	
	return hr;	
}

static HRESULT WINAPI IShellLinkA_fnSetPath(IShellLinkA *iface, LPCSTR pszFile)
{
	IShellLinkImpl *This = impl_from_IShellLinkA(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkA_SetPath(This->pRealLinkA, pszFile);	
	return hr;	
}

static const IShellLinkAVtbl slvt =
{
    IShellLinkA_fnQueryInterface,
    IShellLinkA_fnAddRef,
    IShellLinkA_fnRelease,
    IShellLinkA_fnGetPath,
    IShellLinkA_fnGetIDList,
    IShellLinkA_fnSetIDList,
    IShellLinkA_fnGetDescription,
    IShellLinkA_fnSetDescription,
    IShellLinkA_fnGetWorkingDirectory,
    IShellLinkA_fnSetWorkingDirectory,
    IShellLinkA_fnGetArguments,
    IShellLinkA_fnSetArguments,
    IShellLinkA_fnGetHotkey,
    IShellLinkA_fnSetHotkey,
    IShellLinkA_fnGetShowCmd,
    IShellLinkA_fnSetShowCmd,
    IShellLinkA_fnGetIconLocation,
    IShellLinkA_fnSetIconLocation,
    IShellLinkA_fnSetRelativePath,
    IShellLinkA_fnResolve,
    IShellLinkA_fnSetPath
};

/**************************************************************************
 *  IShellLinkW_fnQueryInterface
 */
/**************************************************************************
 *  IShellLinkW_fnQueryInterface
 */
static HRESULT WINAPI IShellLinkW_fnQueryInterface(
  IShellLinkW * iface, REFIID riid, LPVOID *ppvObj)
{
    IShellLinkImpl *This = impl_from_IShellLinkW(iface);

    TRACE("(%p)->(%s)\n", This, debugstr_guid(riid));

    *ppvObj = NULL;

    if(IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IShellLinkA))
    {
        *ppvObj = &This->IShellLinkA_iface;
    }
    else if(IsEqualIID(riid, &IID_IShellLinkW))
    {
        *ppvObj = &This->IShellLinkW_iface;
    }
    else if(IsEqualIID(riid, &IID_IPersistFile))
    {
        *ppvObj = &This->IPersistFile_iface;
    }
    else if(IsEqualIID(riid, &IID_IPersistStream))
    {
        *ppvObj = &This->IPersistStream_iface;
    }
    else if(IsEqualIID(riid, &IID_IShellLinkDataList))
    {
        *ppvObj = &This->IShellLinkDataList_iface;
    }
    else if(IsEqualIID(riid, &IID_IShellExtInit))
    {
        *ppvObj = &This->IShellExtInit_iface;
    }
    else if(IsEqualIID(riid, &IID_IContextMenu))
    {
        *ppvObj = &This->IContextMenu_iface;
    }
    else if(IsEqualIID(riid, &IID_IObjectWithSite))
    {
        *ppvObj = &This->IObjectWithSite_iface;
    }
    else if(IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IPropertyStore))
    {
        *ppvObj = &This->IPropertyStore_iface;
    }	
	else
    {
        return IShellLinkW_QueryInterface(This->pRealLinkW, riid, ppvObj);
    }

    if(*ppvObj)
    {
        IUnknown_AddRef((IUnknown*)*ppvObj);
        TRACE("-- Interface: (%p)->(%p)\n", ppvObj, *ppvObj);
        return S_OK;
    }
    ERR("-- Interface: E_NOINTERFACE\n");
    return E_NOINTERFACE;
}

static ULONG WINAPI IShellLinkW_fnAddRef(IShellLinkW * iface)
{
    IShellLinkImpl *This = impl_from_IShellLinkW(iface);
    ULONG ref = InterlockedIncrement(&This->ref);
	IShellLinkW_AddRef(This->pRealLinkW);		
    return ref;
}

static ULONG WINAPI IShellLinkW_fnRelease(IShellLinkW * iface)
{
    IShellLinkImpl *This = impl_from_IShellLinkW(iface);
    ULONG refCount = InterlockedDecrement(&This->ref);

    if (refCount)
        return refCount;

    /* cleanup local resources */
    free(This->sIcoPath);
    free(This->sArgs);
    free(This->sWorkDir);
    free(This->sDescription);
    free(This->sPath);
    free(This->sPathRel);
    free(This->sProduct);
    free(This->sComponent);
    free(This->filepath);

    if (This->site)
        IUnknown_Release( This->site );

    if (This->pPidl)
        ILFree(This->pPidl);
	
	IShellLinkW_Release(This->pRealLinkW);	

    LocalFree(This);
    return 0;
}

static HRESULT WINAPI IShellLinkW_fnGetPath(IShellLinkW * iface, LPWSTR pszFile,INT cchMaxPath, WIN32_FIND_DATAW *pfd, DWORD fFlags)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_GetPath(This->pRealLinkW, pszFile, cchMaxPath, pfd, fFlags);	
	return hr;		
}

static HRESULT WINAPI IShellLinkW_fnGetIDList(IShellLinkW * iface, LPITEMIDLIST * ppidl)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_GetIDList(This->pRealLinkW, ppidl);	
	return hr;	
}

static HRESULT WINAPI IShellLinkW_fnSetIDList(IShellLinkW * iface, LPCITEMIDLIST pidl)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_SetIDList(This->pRealLinkW, pidl);	
	return hr;		
}

static HRESULT WINAPI IShellLinkW_fnGetDescription(IShellLinkW * iface, LPWSTR pszName,INT cchMaxName)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_GetDescription(This->pRealLinkW, pszName, cchMaxName);	
	return hr;		
}

static HRESULT WINAPI IShellLinkW_fnSetDescription(IShellLinkW * iface, LPCWSTR pszName)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_SetDescription(This->pRealLinkW, pszName);	
	return hr;		
}

static HRESULT WINAPI IShellLinkW_fnGetWorkingDirectory(IShellLinkW * iface, LPWSTR pszDir,INT cchMaxPath)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_GetWorkingDirectory(This->pRealLinkW, pszDir, cchMaxPath);	
	return hr;		
}

static HRESULT WINAPI IShellLinkW_fnSetWorkingDirectory(IShellLinkW * iface, LPCWSTR pszDir)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_SetWorkingDirectory(This->pRealLinkW, pszDir);	
	return hr;		
}

static HRESULT WINAPI IShellLinkW_fnGetArguments(IShellLinkW * iface, LPWSTR pszArgs,INT cchMaxPath)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_GetArguments(This->pRealLinkW, pszArgs, cchMaxPath);	
	return hr;		
}

static HRESULT WINAPI IShellLinkW_fnSetArguments(IShellLinkW * iface, LPCWSTR pszArgs)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_SetArguments(This->pRealLinkW, pszArgs);	
	return hr;	
}

static HRESULT WINAPI IShellLinkW_fnGetHotkey(IShellLinkW * iface, WORD *pwHotkey)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_GetHotkey(This->pRealLinkW, pwHotkey);	
	return hr;	
}

static HRESULT WINAPI IShellLinkW_fnSetHotkey(IShellLinkW * iface, WORD wHotkey)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_SetHotkey(This->pRealLinkW, wHotkey);	
	return hr;	
}

static HRESULT WINAPI IShellLinkW_fnGetShowCmd(IShellLinkW * iface, INT *piShowCmd)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_GetShowCmd(This->pRealLinkW, piShowCmd);	
	return hr;		
}

static HRESULT WINAPI IShellLinkW_fnSetShowCmd(IShellLinkW * iface, INT iShowCmd)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_SetShowCmd(This->pRealLinkW, iShowCmd);	
	return hr;		
}

static HRESULT WINAPI IShellLinkW_fnGetIconLocation(IShellLinkW * iface, LPWSTR pszIconPath,INT cchIconPath,INT *piIcon)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_GetIconLocation(This->pRealLinkW, pszIconPath, cchIconPath, piIcon);	
	return hr;	
}

static HRESULT WINAPI IShellLinkW_fnSetIconLocation(IShellLinkW * iface, const WCHAR *path, INT icon)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_SetIconLocation(This->pRealLinkW, path, icon);	
	return hr;	
}

static HRESULT WINAPI IShellLinkW_fnSetRelativePath(IShellLinkW * iface, LPCWSTR pszPathRel, DWORD dwReserved)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_SetRelativePath(This->pRealLinkW, pszPathRel, dwReserved);	
	return hr;
}

static HRESULT WINAPI IShellLinkW_fnResolve(IShellLinkW * iface, HWND hwnd, DWORD fFlags)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_Resolve(This->pRealLinkW, hwnd, fFlags);	
	return hr;	
}

static HRESULT WINAPI IShellLinkW_fnSetPath(IShellLinkW * iface, LPCWSTR pszFile)
{
	IShellLinkImpl *This = impl_from_IShellLinkW(iface);
	HRESULT hr = S_OK;
	hr = IShellLinkW_SetPath(This->pRealLinkW, pszFile);	
	return hr;	
}

static const IShellLinkWVtbl slvtw =
{
    IShellLinkW_fnQueryInterface,
    IShellLinkW_fnAddRef,
    IShellLinkW_fnRelease,
    IShellLinkW_fnGetPath,
    IShellLinkW_fnGetIDList,
    IShellLinkW_fnSetIDList,
    IShellLinkW_fnGetDescription,
    IShellLinkW_fnSetDescription,
    IShellLinkW_fnGetWorkingDirectory,
    IShellLinkW_fnSetWorkingDirectory,
    IShellLinkW_fnGetArguments,
    IShellLinkW_fnSetArguments,
    IShellLinkW_fnGetHotkey,
    IShellLinkW_fnSetHotkey,
    IShellLinkW_fnGetShowCmd,
    IShellLinkW_fnSetShowCmd,
    IShellLinkW_fnGetIconLocation,
    IShellLinkW_fnSetIconLocation,
    IShellLinkW_fnSetRelativePath,
    IShellLinkW_fnResolve,
    IShellLinkW_fnSetPath
};

static HRESULT WINAPI
ShellLink_DataList_QueryInterface( IShellLinkDataList* iface, REFIID riid, void** ppvObject)
{
    IShellLinkImpl *This = impl_from_IShellLinkDataList(iface);
    return IShellLinkW_QueryInterface(&This->IShellLinkW_iface, riid, ppvObject);
}

static ULONG WINAPI
ShellLink_DataList_AddRef( IShellLinkDataList* iface )
{
    IShellLinkImpl *This = impl_from_IShellLinkDataList(iface);
	IShellLinkDataList_AddRef(This->pRealDataList);
    return IShellLinkW_AddRef(&This->IShellLinkW_iface);
}

static ULONG WINAPI
ShellLink_DataList_Release( IShellLinkDataList* iface )
{
    IShellLinkImpl *This = impl_from_IShellLinkDataList(iface);
	IShellLinkDataList_Release(This->pRealDataList);
    return IShellLinkW_Release(&This->IShellLinkW_iface);
}

static HRESULT WINAPI
ShellLink_AddDataBlock( IShellLinkDataList* iface, void* pDataBlock )
{
    IShellLinkImpl *This = impl_from_IShellLinkDataList(iface);
	HRESULT hr = S_OK;
    hr = IShellLinkDataList_AddDataBlock(This->pRealDataList, pDataBlock);
	return hr;	
}

static HRESULT WINAPI
ShellLink_CopyDataBlock( IShellLinkDataList* iface, DWORD dwSig, void** ppDataBlock )
{
    IShellLinkImpl *This = impl_from_IShellLinkDataList(iface);
	HRESULT hr = S_OK;
    hr = IShellLinkDataList_CopyDataBlock(This->pRealDataList, dwSig, ppDataBlock);
	return hr;	
}

static HRESULT WINAPI
ShellLink_RemoveDataBlock( IShellLinkDataList* iface, DWORD dwSig )
{
    IShellLinkImpl *This = impl_from_IShellLinkDataList(iface);
	HRESULT hr = S_OK;
    hr = IShellLinkDataList_RemoveDataBlock(This->pRealDataList, dwSig);
	return hr;	
}

static HRESULT WINAPI
ShellLink_GetFlags( IShellLinkDataList* iface, DWORD* pdwFlags )
{
    IShellLinkImpl *This = impl_from_IShellLinkDataList(iface);
	HRESULT hr = S_OK;
    hr = IShellLinkDataList_GetFlags(This->pRealDataList, pdwFlags);
	return hr;	
}

static HRESULT WINAPI
ShellLink_SetFlags( IShellLinkDataList* iface, DWORD dwFlags )
{
    IShellLinkImpl *This = impl_from_IShellLinkDataList(iface);
	HRESULT hr = S_OK;
    hr = IShellLinkDataList_SetFlags(This->pRealDataList, dwFlags);
	return hr;
}

static const IShellLinkDataListVtbl dlvt =
{
    ShellLink_DataList_QueryInterface,
    ShellLink_DataList_AddRef,
    ShellLink_DataList_Release,
    ShellLink_AddDataBlock,
    ShellLink_CopyDataBlock,
    ShellLink_RemoveDataBlock,
    ShellLink_GetFlags,
    ShellLink_SetFlags
};

static HRESULT WINAPI
ShellLink_ExtInit_QueryInterface( IShellExtInit* iface, REFIID riid, void** ppvObject )
{
    IShellLinkImpl *This = impl_from_IShellExtInit(iface);
    return IShellLinkW_QueryInterface(&This->IShellLinkW_iface, riid, ppvObject);
}

static ULONG WINAPI
ShellLink_ExtInit_AddRef( IShellExtInit* iface )
{
    IShellLinkImpl *This = impl_from_IShellExtInit(iface);
	IShellExtInit_AddRef(This->pRealShellExtInit);	
    return IShellLinkW_AddRef(&This->IShellLinkW_iface);
}

static ULONG WINAPI
ShellLink_ExtInit_Release( IShellExtInit* iface )
{
    IShellLinkImpl *This = impl_from_IShellExtInit(iface);
	IShellExtInit_Release(This->pRealShellExtInit);
    return IShellLinkW_Release(&This->IShellLinkW_iface);
}

static HRESULT WINAPI
ShellLink_ExtInit_Initialize( IShellExtInit* iface, LPCITEMIDLIST pidlFolder,
                              IDataObject *pdtobj, HKEY hkeyProgID )
{
	IShellLinkImpl *This = impl_from_IShellExtInit(iface);
	HRESULT hr = S_OK;
	hr = IShellExtInit_Initialize(This->pRealShellExtInit, pidlFolder, pdtobj, hkeyProgID);	
	return hr;	
}

static const IShellExtInitVtbl eivt =
{
    ShellLink_ExtInit_QueryInterface,
    ShellLink_ExtInit_AddRef,
    ShellLink_ExtInit_Release,
    ShellLink_ExtInit_Initialize
};

static HRESULT WINAPI
ShellLink_ContextMenu_QueryInterface( IContextMenu* iface, REFIID riid, void** ppvObject )
{
    IShellLinkImpl *This = impl_from_IContextMenu(iface);
    return IShellLinkW_QueryInterface(&This->IShellLinkW_iface, riid, ppvObject);
}

static ULONG WINAPI
ShellLink_ContextMenu_AddRef( IContextMenu* iface )
{
    IShellLinkImpl *This = impl_from_IContextMenu(iface);
	IContextMenu_AddRef(This->pRealContextMenu);
    return IShellLinkW_AddRef(&This->IShellLinkW_iface);
}

static ULONG WINAPI
ShellLink_ContextMenu_Release( IContextMenu* iface )
{
    IShellLinkImpl *This = impl_from_IContextMenu(iface);
	IContextMenu_Release(This->pRealContextMenu);	
    return IShellLinkW_Release(&This->IShellLinkW_iface);
}

static HRESULT WINAPI
ShellLink_QueryContextMenu( IContextMenu* iface, HMENU hmenu, UINT indexMenu,
                            UINT idCmdFirst, UINT idCmdLast, UINT uFlags )
{
	IShellLinkImpl *This = impl_from_IContextMenu(iface);
	HRESULT hr = S_OK;
	hr = IContextMenu_QueryContextMenu(This->pRealContextMenu, hmenu, indexMenu, idCmdFirst, idCmdLast, uFlags);	
	return hr;	
}

static HRESULT WINAPI
ShellLink_InvokeCommand( IContextMenu* iface, LPCMINVOKECOMMANDINFO lpici )
{
	IShellLinkImpl *This = impl_from_IContextMenu(iface);
	HRESULT hr = S_OK;
	hr = IContextMenu_InvokeCommand(This->pRealContextMenu, lpici);	
	return hr;		
}

static HRESULT WINAPI
ShellLink_GetCommandString( IContextMenu* iface, UINT_PTR idCmd, UINT uType,
                            UINT* pwReserved, LPSTR pszName, UINT cchMax )
{
	IShellLinkImpl *This = impl_from_IContextMenu(iface);
	HRESULT hr = S_OK;
	hr = IContextMenu_GetCommandString(This->pRealContextMenu, idCmd, uType, pwReserved, pszName, cchMax);	
	return hr;		
}

static const IContextMenuVtbl cmvt =
{
    ShellLink_ContextMenu_QueryInterface,
    ShellLink_ContextMenu_AddRef,
    ShellLink_ContextMenu_Release,
    ShellLink_QueryContextMenu,
    ShellLink_InvokeCommand,
    ShellLink_GetCommandString
};

static HRESULT WINAPI
ShellLink_ObjectWithSite_QueryInterface( IObjectWithSite* iface, REFIID riid, void** ppvObject )
{
    IShellLinkImpl *This = impl_from_IObjectWithSite(iface);
    return IShellLinkW_QueryInterface(&This->IShellLinkW_iface, riid, ppvObject );
}

static ULONG WINAPI
ShellLink_ObjectWithSite_AddRef( IObjectWithSite* iface )
{
    IShellLinkImpl *This = impl_from_IObjectWithSite(iface);
	IObjectWithSite_AddRef(This->pRealObjectWithSite);	
    return IShellLinkW_AddRef(&This->IShellLinkW_iface);
}

static ULONG WINAPI
ShellLink_ObjectWithSite_Release( IObjectWithSite* iface )
{
    IShellLinkImpl *This = impl_from_IObjectWithSite(iface);
	IObjectWithSite_Release(This->pRealObjectWithSite);	
    return IShellLinkW_Release(&This->IShellLinkW_iface);
}

static HRESULT WINAPI
ShellLink_GetSite( IObjectWithSite *iface, REFIID iid, void ** ppvSite )
{
	IShellLinkImpl *This = impl_from_IObjectWithSite(iface);
	HRESULT hr = S_OK;
	hr = IObjectWithSite_GetSite(This->pRealObjectWithSite, iid, ppvSite);	
	return hr;		
}

static HRESULT WINAPI
ShellLink_SetSite( IObjectWithSite *iface, IUnknown *punk )
{
	IShellLinkImpl *This = impl_from_IObjectWithSite(iface);
	HRESULT hr = S_OK;
	hr = IObjectWithSite_SetSite(This->pRealObjectWithSite, punk);	
	return hr;		
}

static const IObjectWithSiteVtbl owsvt =
{
    ShellLink_ObjectWithSite_QueryInterface,
    ShellLink_ObjectWithSite_AddRef,
    ShellLink_ObjectWithSite_Release,
    ShellLink_SetSite,
    ShellLink_GetSite,
};

static HRESULT WINAPI propertystore_QueryInterface(IPropertyStore *iface, REFIID riid, void **obj)
{
    IShellLinkImpl *This = impl_from_IPropertyStore(iface);
    return IShellLinkW_QueryInterface(&This->IShellLinkW_iface, riid, obj);
}

static ULONG WINAPI propertystore_AddRef(IPropertyStore *iface)
{
    IShellLinkImpl *This = impl_from_IPropertyStore(iface);
    return IShellLinkW_AddRef(&This->IShellLinkW_iface);
}

static ULONG WINAPI propertystore_Release(IPropertyStore *iface)
{
    IShellLinkImpl *This = impl_from_IPropertyStore(iface);
    return IShellLinkW_Release(&This->IShellLinkW_iface);
}

static HRESULT WINAPI propertystore_GetCount(IPropertyStore *iface, DWORD *props)
{
    IShellLinkImpl *This = impl_from_IPropertyStore(iface);
    FIXME("(%p)->(%p): stub\n", This, props);
    return E_NOTIMPL;
}

static HRESULT WINAPI propertystore_GetAt(IPropertyStore *iface, DWORD propid, PROPERTYKEY *key)
{
    IShellLinkImpl *This = impl_from_IPropertyStore(iface);
    FIXME("(%p)->(%ld %p): stub\n", This, propid, key);
    return E_NOTIMPL;
}

static HRESULT WINAPI propertystore_GetValue(IPropertyStore *iface, REFPROPERTYKEY key, PROPVARIANT *value)
{
    IShellLinkImpl *This = impl_from_IPropertyStore(iface);
    FIXME("(%p)->(%p %p): stub\n", This, key, value);
    return E_NOTIMPL;
}

static HRESULT WINAPI propertystore_SetValue(IPropertyStore *iface, REFPROPERTYKEY key, REFPROPVARIANT value)
{
    IShellLinkImpl *This = impl_from_IPropertyStore(iface);
    FIXME("(%p)->(%p %p): stub\n", This, key, value);
    return S_OK;
}

static HRESULT WINAPI propertystore_Commit(IPropertyStore *iface)
{
    IShellLinkImpl *This = impl_from_IPropertyStore(iface);
    FIXME("(%p): stub\n", This);
    return S_OK;
}

static const IPropertyStoreVtbl propertystorevtbl = {
    propertystore_QueryInterface,
    propertystore_AddRef,
    propertystore_Release,
    propertystore_GetCount,
    propertystore_GetAt,
    propertystore_GetValue,
    propertystore_SetValue,
    propertystore_Commit
};

HRESULT WINAPI IShellLink_Constructor(IUnknown *outer, REFIID riid, void **obj)
{
    IShellLinkImpl * sl;
    HRESULT hr;
    IClassFactory *pFactory = NULL;
    IShellLinkW *pShellLinkReal = NULL;	

    TRACE("outer=%p riid=%s\n", outer, debugstr_guid(riid));

    *obj = NULL;

    if (outer)
        return CLASS_E_NOAGGREGATION;

    sl = LocalAlloc(LMEM_ZEROINIT,sizeof(IShellLinkImpl));
    if (!sl)
        return E_OUTOFMEMORY;

    sl->ref = 1;
    sl->iShowCmd = SW_SHOWNORMAL;
    sl->bDirty = FALSE;
    sl->iIdOpen = -1;
    sl->site = NULL;
    sl->filepath = NULL;	

    hr = DllGetClassObject(&CLSID_ShellLink, &IID_IClassFactory, (void**)&pFactory);
    if (FAILED(hr))
    {
        LocalFree(sl);
        return hr;
    }

    hr = IClassFactory_CreateInstance(pFactory, NULL, &IID_IShellLinkW, (void**)&pShellLinkReal);
    IClassFactory_Release(pFactory);
    if (FAILED(hr))
    {
        LocalFree(sl);
        return hr;
    }

    /* === 4. Obtém todas as interfaces reais === */
    IShellLinkW_QueryInterface(pShellLinkReal, &IID_IShellLinkW, (void**)&sl->pRealLinkW);
    IShellLinkW_QueryInterface(pShellLinkReal, &IID_IShellLinkA, (void**)&sl->pRealLinkA);
    IShellLinkW_QueryInterface(pShellLinkReal, &IID_IPersistFile, (void**)&sl->pRealPersistFile);
    IShellLinkW_QueryInterface(pShellLinkReal, &IID_IPersistStream, (void**)&sl->pRealPersistStream);
    IShellLinkW_QueryInterface(pShellLinkReal, &IID_IShellLinkDataList, (void**)&sl->pRealDataList);
    IShellLinkW_QueryInterface(pShellLinkReal, &IID_IShellExtInit, (void**)&sl->pRealShellExtInit);
    IShellLinkW_QueryInterface(pShellLinkReal, &IID_IContextMenu, (void**)&sl->pRealContextMenu);
    IShellLinkW_QueryInterface(pShellLinkReal, &IID_IObjectWithSite, (void**)&sl->pRealObjectWithSite);	
	
    sl->IShellLinkA_iface.lpVtbl = &slvt;
    sl->IShellLinkW_iface.lpVtbl = &slvtw;
    sl->IPersistFile_iface.lpVtbl = &pfvt;
    sl->IPersistStream_iface.lpVtbl = &psvt;
    sl->IShellLinkDataList_iface.lpVtbl = &dlvt;
    sl->IShellExtInit_iface.lpVtbl = &eivt;
    sl->IContextMenu_iface.lpVtbl = &cmvt;
    sl->IObjectWithSite_iface.lpVtbl = &owsvt;
    sl->IPropertyStore_iface.lpVtbl = &propertystorevtbl;	

    TRACE("(%p)\n", sl);

    hr = IShellLinkW_QueryInterface( &sl->IShellLinkW_iface, riid, obj );
    IShellLinkW_Release( &sl->IShellLinkW_iface );
    IShellLinkW_Release( pShellLinkReal );
    return hr;
}