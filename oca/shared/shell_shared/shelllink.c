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
	//volume_info   volume;

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

/**************************************************************************
 *  IShellLinkW_fnQueryInterface
 */
static HRESULT WINAPI IShellLinkW_fnQueryInterface(
  IShellLinkW * iface, REFIID riid, LPVOID *ppvObj)
{
    IShellLinkImpl *This = impl_from_IShellLinkW(iface);

    TRACE("(%p)->(%s)\n", This, debugstr_guid(riid));

    *ppvObj = NULL;

    // if(IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IShellLinkA))
    // {
        // *ppvObj = &This->IShellLinkA_iface;
    // }
    // else if(IsEqualIID(riid, &IID_IShellLinkW))
    // {
        // *ppvObj = &This->IShellLinkW_iface;
    // }
    // else if(IsEqualIID(riid, &IID_IPersistFile))
    // {
        // *ppvObj = &This->IPersistFile_iface;
    // }
    // else if(IsEqualIID(riid, &IID_IPersistStream))
    // {
        // *ppvObj = &This->IPersistStream_iface;
    // }
    // else if(IsEqualIID(riid, &IID_IShellLinkDataList))
    // {
        // *ppvObj = &This->IShellLinkDataList_iface;
    // }
    // else if(IsEqualIID(riid, &IID_IShellExtInit))
    // {
        // *ppvObj = &This->IShellExtInit_iface;
    // }
    // else if(IsEqualIID(riid, &IID_IContextMenu))
    // {
        // *ppvObj = &This->IContextMenu_iface;
    // }
    // else if(IsEqualIID(riid, &IID_IObjectWithSite))
    // {
        // *ppvObj = &This->IObjectWithSite_iface;
    // }
    if(IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IPropertyStore))
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
	
    sl->IShellLinkA_iface.lpVtbl = sl->pRealLinkA->lpVtbl;
    sl->IShellLinkW_iface.lpVtbl = &slvtw;
    sl->IPersistFile_iface.lpVtbl = sl->pRealPersistFile->lpVtbl;
    sl->IPersistStream_iface.lpVtbl = sl->pRealPersistStream->lpVtbl;
    sl->IShellLinkDataList_iface.lpVtbl = sl->pRealDataList->lpVtbl;
    sl->IShellExtInit_iface.lpVtbl = sl->pRealShellExtInit->lpVtbl;
    sl->IContextMenu_iface.lpVtbl = sl->pRealContextMenu->lpVtbl;
    sl->IObjectWithSite_iface.lpVtbl = sl->pRealObjectWithSite->lpVtbl;
    sl->IPropertyStore_iface.lpVtbl = &propertystorevtbl;	

    TRACE("(%p)\n", sl);

    hr = IShellLinkW_QueryInterface( &sl->IShellLinkW_iface, riid, obj );
    IShellLinkW_Release( &sl->IShellLinkW_iface );
    IShellLinkW_Release( pShellLinkReal );
    return hr;
}