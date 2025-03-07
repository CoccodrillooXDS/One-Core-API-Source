/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS ReactX
 * FILE:            dll/directx/d3d9/d3d9_impl.c
 * PURPOSE:         IDirect3D9 implementation
 * PROGRAMERS:      Gregor Brunmar <gregor (dot) brunmar (at) home (dot) se>
 */

#include "d3d9_common.h"
#include <d3d9.h>
#include <debug.h>
#include "d3d9_helpers.h"
#include "adapter.h"
#include "device.h"
#include "format.h"
#include <reactos/debug.h>

WINE_DEFAULT_DEBUG_CHANNEL(d3d9_impl);

#define D3DENUM_WHQL_LEVEL 0x00000002L  //TODO: need be moved to d3d9types.h
#define D3DUSAGE_TEXTAPI                         (0x10000000L)  //TODO: need be moved to d3d9types.h
#define LOCK_D3D9()     EnterCriticalSection(&This->d3d9_cs);
#define UNLOCK_D3D9()   LeaveCriticalSection(&This->d3d9_cs);

// Maps D3DMULTISAMPLE_TYPE into the bit to use for the flags.
// Maps each of the multisampling values (2 to 16) to the bits[1] to bits[15]
// of wBltMSTypes and wFlipMSTypes
#define DDI_MULTISAMPLE_TYPE(x) (1 << ((x)-1))

/* Convert a IDirect3D9 pointer safely to the internal implementation struct */
static LPDIRECT3D9_INT IDirect3D9ToImpl(LPDIRECT3D9EX iface)
{
    if (NULL == iface)
        return NULL;

    return (LPDIRECT3D9_INT)((ULONG_PTR)iface - FIELD_OFFSET(DIRECT3D9_INT, lpVtbl));
}

/* IDirect3D9: IUnknown implementation */
static HRESULT WINAPI IDirect3D9Impl_QueryInterface(LPDIRECT3D9EX iface, REFIID riid, LPVOID* ppvObject)
{
    // LPDIRECT3D9_INT This = IDirect3D9ToImpl(iface);

    // if (IsEqualGUID(riid, &IID_IUnknown) || IsEqualGUID(riid, &IID_IDirect3D9))
    // {
        // IUnknown_AddRef(iface);
        // *ppvObject = &This->lpVtbl;
        // return S_OK;
    // }

   // *ppvObject = NULL;
    return IDirect3D9_QueryInterface(ProxyInterface, riid, ppvObject);
}

static ULONG WINAPI IDirect3D9Impl_AddRef(LPDIRECT3D9EX iface)
{
    // LPDIRECT3D9_INT This = IDirect3D9ToImpl(iface);
    // ULONG ref = InterlockedIncrement(&This->lRefCnt);

    return IDirect3D9_AddRef(ProxyInterface);
}

static ULONG WINAPI IDirect3D9Impl_Release(LPDIRECT3D9EX iface)
{
    // LPDIRECT3D9_INT This = IDirect3D9ToImpl(iface);
    // ULONG ref = InterlockedDecrement(&This->lRefCnt);

    // if (ref == 0)
    // {
        // EnterCriticalSection(&This->d3d9_cs);
        // /* TODO: Free resources here */
        // LeaveCriticalSection(&This->d3d9_cs);
        // AlignedFree(This);
    // }

    return IDirect3D9_Release(ProxyInterface);
}

/* IDirect3D9 interface */
static HRESULT WINAPI IDirect3D9Impl_RegisterSoftwareDevice(LPDIRECT3D9EX iface, void* pInitializeFunction)
{
    return IDirect3D9_RegisterSoftwareDevice(ProxyInterface, pInitializeFunction);
}

/*++
* @name IDirect3D9::GetAdapterCount
* @implemented
*
* The function IDirect3D9Impl_GetAdapterCount returns the number of adapters
*
* @param LPDIRECT3D iface
* Pointer to the IDirect3D9 object returned from Direct3DCreate9()
*
* @return UINT
* The number of display adapters on the system when Direct3DCreate9() was called.
*
*/
static UINT WINAPI IDirect3D9Impl_GetAdapterCount(LPDIRECT3D9EX iface)
{
    // UINT NumDisplayAdapters;

    // LPDIRECT3D9_INT This = IDirect3D9ToImpl(iface);
    // LOCK_D3D9();

    // NumDisplayAdapters = This->NumDisplayAdapters;

    // UNLOCK_D3D9();
    // return NumDisplayAdapters;
	return IDirect3D9_GetAdapterCount(ProxyInterface);	
}

/*++
* @name IDirect3D9::GetAdapterIdentifier
* @implemented
*
* The function IDirect3D9Impl_GetAdapterIdentifier gathers information about
* a specified display adapter and fills the pIdentifier argument with the available information.
*
* @param LPDIRECT3D iface
* Pointer to the IDirect3D9 object returned from Direct3DCreate9()
*
* @param UINT Adapter
* Adapter index to get information about. D3DADAPTER_DEFAULT is the primary display.
* The maximum value for this is the value returned by IDirect3D::GetAdapterCount() - 1.
*
* @param DWORD Flags
* Ignored at the moment, but the only valid flag is D3DENUM_WHQL_LEVEL
*
* @param D3DADAPTER_IDENTIFIER9* pIdentifier
* Pointer to a D3DADAPTER_IDENTIFIER9 structure to be filled with the available information
* about the display adapter.
*
* @return HRESULT
* If the method successfully fills the pIdentified structure, the return value is D3D_OK.
* If Adapter is out of range, Flags is invalid or pIdentifier is a bad pointer, the return value
* will be D3DERR_INVALIDCALL.
*
*/
HRESULT WINAPI IDirect3D9Impl_GetAdapterIdentifier(LPDIRECT3D9EX iface, UINT Adapter, DWORD Flags,
                                                          D3DADAPTER_IDENTIFIER9* pIdentifier)
{
    // LPDIRECT3D9_INT This = IDirect3D9ToImpl(iface);
    // LOCK_D3D9();

    // if (Adapter >= This->NumDisplayAdapters)
    // {
        // DPRINT1("Invalid Adapter number specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (Flags & ~D3DENUM_WHQL_LEVEL)
    // {
        // DPRINT1("Invalid Flags specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (NULL == pIdentifier)
    // {
        // DPRINT1("Invalid pIdentifier parameter specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // memset(pIdentifier, 0, sizeof(D3DADAPTER_IDENTIFIER9));

    // if (FALSE == GetAdapterInfo(This->DisplayAdapters[Adapter].szDeviceName, pIdentifier))
    // {
        // DPRINT1("Internal error: Couldn't get the adapter info for device (%d): %s", Adapter, This->DisplayAdapters[Adapter].szDeviceName);
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // UNLOCK_D3D9();
    // return D3D_OK;
	return IDirect3D9_GetAdapterIdentifier(ProxyInterface, Adapter, Flags, pIdentifier);	
}

/*++
* @name IDirect3D9::GetAdapterModeCount
* @implemented
*
* The function IDirect3D9Impl_GetAdapterModeCount looks if the specified display adapter supports
* a specific pixel format and counts the available display modes for that format.
*
* @param LPDIRECT3D iface
* Pointer to the IDirect3D9 object returned from Direct3DCreate9()
*
* @param UINT Adapter
* Adapter index to get information about. D3DADAPTER_DEFAULT is the primary display.
* The maximum value for this is the value returned by IDirect3D9::GetAdapterCount() - 1.
*
* @param D3DFORMAT Format
* The pixel format to search for
*
* @return HRESULT
* If the method is successful it returns the number of display modes with the specified Format.
* If Adapter is out of range, the return value will be 0.
*
*/
static UINT WINAPI IDirect3D9Impl_GetAdapterModeCount(LPDIRECT3D9EX iface, UINT Adapter, D3DFORMAT Format)
{
    // UINT AdapterModeCount;

    // LPDIRECT3D9_INT This = IDirect3D9ToImpl(iface);
    // LOCK_D3D9();

    // if (Adapter >= This->NumDisplayAdapters)
    // {
        // DPRINT1("Invalid Adapter number specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (Format != D3DFMT_A2R10G10B10)
    // {
        // AdapterModeCount = GetDisplayFormatCount(
            // Format,
            // This->DisplayAdapters[Adapter].pSupportedD3DFormats,
            // This->DisplayAdapters[Adapter].NumSupportedD3DFormats);
    // }
    // else
    // {
        // AdapterModeCount = GetDisplayFormatCount(
            // Format,
            // This->DisplayAdapters[Adapter].pSupportedD3DExtendedFormats,
            // This->DisplayAdapters[Adapter].NumSupportedD3DExtendedFormats);
    // }

    // UNLOCK_D3D9();
    // return AdapterModeCount;
	return IDirect3D9_GetAdapterModeCount(ProxyInterface, Adapter, Format);
}

/*++
* @name IDirect3D9::EnumAdapterModes
* @implemented
*
* The function IDirect3D9Impl_EnumAdapterModes looks if the specified display adapter supports
* a specific pixel format and fills the pMode argument with the available display modes for that format.
* This function is often used in a loop to enumerate all the display modes the adapter supports.
*
* @param LPDIRECT3D iface
* Pointer to the IDirect3D9 object returned from Direct3DCreate9()
*
* @param UINT Adapter
* Adapter index to get information about. D3DADAPTER_DEFAULT is the primary display.
* The maximum value for this is the value returned by IDirect3D9::GetAdapterCount() - 1.
*
* @param D3DFORMAT Format
* The pixel format to search for
*
* @param UINT Mode
* Index within the pixel format to be returned.
* The maximum value for this is the value returned by IDirect3D9::GetAdapterModeCount() - 1.
*
* @param D3DDISPLAYMODE* pMode
* Pointer to a D3DDISPLAYMODE structure to be filled with the display mode information
* for the specified format.
*
* @return HRESULT
* If the method successfully fills the pMode structure, the return value is D3D_OK.
* If Adapter is out of range, pMode is a bad pointer or, no modes for the specified
* format was found or the mode parameter was invalid - the return value will be D3DERR_INVALIDCALL.
*
*/
static HRESULT WINAPI IDirect3D9Impl_EnumAdapterModes(LPDIRECT3D9EX iface, UINT Adapter, D3DFORMAT Format,
                                                      UINT Mode, D3DDISPLAYMODE* pMode)
{
    // const D3DDISPLAYMODE* pMatchingDisplayFormat;
    // LPDIRECT3D9_INT This = IDirect3D9ToImpl(iface);
    // LOCK_D3D9();

    // if (Adapter >= This->NumDisplayAdapters)
    // {
        // DPRINT1("Invalid Adapter number specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (NULL == pMode)
    // {
        // DPRINT1("Invalid pMode parameter specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (Format != D3DFMT_A2R10G10B10)
    // {
        // pMatchingDisplayFormat = FindDisplayFormat(
            // Format,
            // Mode,
            // This->DisplayAdapters[Adapter].pSupportedD3DFormats,
            // This->DisplayAdapters[Adapter].NumSupportedD3DFormats);
    // }
    // else
    // {
        // pMatchingDisplayFormat = FindDisplayFormat(
            // Format,
            // Mode,
            // This->DisplayAdapters[Adapter].pSupportedD3DExtendedFormats,
            // This->DisplayAdapters[Adapter].NumSupportedD3DExtendedFormats);
    // }

    // if (pMatchingDisplayFormat != NULL)
    // {
        // *pMode = *pMatchingDisplayFormat;
    // }
    // UNLOCK_D3D9();


    // if (pMatchingDisplayFormat == NULL)
        // return D3DERR_INVALIDCALL;

    // return D3D_OK;
	return IDirect3D9_EnumAdapterModes(ProxyInterface, Adapter, Format, Mode, pMode);
}

/*++
* @name IDirect3D9::GetAdapterDisplayMode
* @implemented
*
* The function IDirect3D9Impl_GetAdapterDisplayMode fills the pMode argument with the
* currently set display mode.
*
* @param LPDIRECT3D iface
* Pointer to the IDirect3D9 object returned from Direct3DCreate9()
*
* @param UINT Adapter
* Adapter index to get information about. D3DADAPTER_DEFAULT is the primary display.
* The maximum value for this is the value returned by IDirect3D9::GetAdapterCount() - 1.
*
* @param D3DDISPLAYMODE* pMode
* Pointer to a D3DDISPLAYMODE structure to be filled with the current display mode information.
*
* @return HRESULT
* If the method successfully fills the pMode structure, the return value is D3D_OK.
* If Adapter is out of range or pMode is a bad pointer, the return value will be D3DERR_INVALIDCALL.
*
*/
static HRESULT WINAPI IDirect3D9Impl_GetAdapterDisplayMode(LPDIRECT3D9EX iface, UINT Adapter, D3DDISPLAYMODE* pMode)
{
    // LPDIRECT3D9_INT This = IDirect3D9ToImpl(iface);
    // LOCK_D3D9();

    // if (Adapter >= This->NumDisplayAdapters)
    // {
        // DPRINT1("Invalid Adapter number specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (NULL == pMode)
    // {
        // DPRINT1("Invalid pMode parameter specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // /* TODO: Handle (This->DisplayAdapters[Adapter].bInUseFlag == FALSE) */
    // if (FALSE == GetAdapterMode(This->DisplayAdapters[Adapter].szDeviceName, pMode))
        // DPRINT1("Internal error, GetAdapterMode() failed.");

    // UNLOCK_D3D9();
    // return D3D_OK;
	return IDirect3D9_GetAdapterDisplayMode(ProxyInterface, Adapter, pMode);
}


/*++
* @name IDirect3D9::CheckDeviceType
* @implemented
*
* The function IDirect3D9Impl_CheckDeviceType checks if a specific D3DFORMAT is hardware accelerated
* on the specified display adapter.
*
* @param LPDIRECT3D iface
* Pointer to the IDirect3D9 object returned from Direct3DCreate9()
*
* @param UINT Adapter
* Adapter index to get information about. D3DADAPTER_DEFAULT is the primary display.
* The maximum value for this is the value returned by IDirect3D9::GetAdapterCount() - 1.
*
* @param D3DDEVTYPE DeviceType
* One of the D3DDEVTYPE enum members.
*
* @param D3DFORMAT DisplayFormat
* One of the D3DFORMAT enum members except D3DFMT_UNKNOWN for the display adapter mode to be checked.
*
* @param D3DFORMAT BackBufferFormat
* One of the D3DFORMAT enum members for the render target mode to be checked. D3DFMT_UNKNOWN is only allowed in windowed mode.
*
* @param BOOL Windowed
* If this value is TRUE, the D3DFORMAT check will be done for windowed mode and FALSE equals fullscreen mode.
*
* @return HRESULT
* If the format is hardware accelerated, the method returns D3D_OK.
* If the format isn't hardware accelerated or unsupported - the return value will be D3DERR_NOTAVAILABLE.
* If Adapter is out of range, DeviceType is invalid,
* DisplayFormat or BackBufferFormat is invalid - the return value will be D3DERR_INVALIDCALL.
*
*/
static HRESULT WINAPI IDirect3D9Impl_CheckDeviceType(LPDIRECT3D9EX iface, UINT Adapter, D3DDEVTYPE DeviceType,
                                                     D3DFORMAT DisplayFormat, D3DFORMAT BackBufferFormat, BOOL Windowed)
{
    // HRESULT hResult;

    // LPDIRECT3D9_INT This = IDirect3D9ToImpl(iface);
    // LOCK_D3D9();

    // if (Adapter >= This->NumDisplayAdapters)
    // {
        // DPRINT1("Invalid Adapter number specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (DeviceType != D3DDEVTYPE_HAL &&
        // DeviceType != D3DDEVTYPE_REF &&
        // DeviceType != D3DDEVTYPE_SW)
    // {
        // DPRINT1("Invalid DeviceType specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if ((BackBufferFormat == D3DFMT_UNKNOWN) &&
        // (Windowed != FALSE))
    // {
        // BackBufferFormat = DisplayFormat;
    // }

    // if (DisplayFormat == D3DFMT_UNKNOWN && BackBufferFormat == D3DFMT_UNKNOWN)
    // {
        // DPRINT1("Invalid D3DFORMAT specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (FALSE == IsBackBufferFormat(BackBufferFormat))
    // {
        // DPRINT1("Invalid D3DFORMAT specified");
        // UNLOCK_D3D9();
        // return D3DERR_NOTAVAILABLE;
    // }

    // if (TRUE == Windowed && TRUE == IsExtendedFormat(DisplayFormat))
    // {
        // DPRINT1("Extended display modes can only be used in fullscreen mode");
        // UNLOCK_D3D9();
        // return D3DERR_NOTAVAILABLE;
    // }

    // hResult = CheckDeviceType(&This->DisplayAdapters[Adapter].DriverCaps, DisplayFormat, BackBufferFormat, Windowed);

    // UNLOCK_D3D9();
    // return hResult;
	return IDirect3D9_CheckDeviceType(ProxyInterface, Adapter, DeviceType, DisplayFormat, BackBufferFormat, Windowed);
}


/*++
* @name IDirect3D9::CheckDeviceFormat
* @implemented
*
* The function IDirect3D9Impl_CheckDeviceFormat checks if a specific D3DFORMAT
* can be used for a specific purpose like texture, depth/stencil buffer or as a render target
* on the specified display adapter.
*
* @param LPDIRECT3D iface
* Pointer to the IDirect3D9 object returned from Direct3DCreate9()
*
* @param UINT Adapter
* Adapter index to get information about. D3DADAPTER_DEFAULT is the primary display.
* The maximum value for this is the value returned by IDirect3D9::GetAdapterCount() - 1.
*
* @param D3DDEVTYPE DeviceType
* One of the D3DDEVTYPE enum members.
*
* @param D3DFORMAT AdapterFormat
* One of the D3DFORMAT enum members except D3DFMT_UNKNOWN for the display adapter mode to be checked.
*
* @param DWORD Usage
* Valid values are any of the D3DUSAGE_QUERY constants or any of these D3DUSAGE constants:
* D3DUSAGE_AUTOGENMIPMAP, D3DUSAGE_DEPTHSTENCIL, D3DUSAGE_DMAP, D3DUSAGE_DYNAMIC,
* D3DUSAGE_NONSECURE, D3DUSAGE_RENDERTARGET and D3DUSAGE_SOFTWAREPROCESSING.
*
* @param D3DRESOURCETYPE RType
* One of the D3DRESOURCETYPE enum members. Specifies what format will be used for.
*
* @param D3DFORMAT CheckFormat
* One of the D3DFORMAT enum members for the surface format to be checked.
*
* @return HRESULT
* If the format is compatible with the specified usage and resource type, the method returns D3D_OK.
* If the format isn't compatible with the specified usage and resource type - the return value will be D3DERR_NOTAVAILABLE.
* If Adapter is out of range, DeviceType is invalid, AdapterFormat or CheckFormat is invalid,
* Usage and RType isn't compatible - the return value will be D3DERR_INVALIDCALL.
*
*/
static HRESULT WINAPI IDirect3D9Impl_CheckDeviceFormat(LPDIRECT3D9EX iface, UINT Adapter, D3DDEVTYPE DeviceType,
                                                       D3DFORMAT AdapterFormat, DWORD Usage, D3DRESOURCETYPE RType,
                                                       D3DFORMAT CheckFormat)
{
    // LPD3D9_DRIVERCAPS pDriverCaps;
    // BOOL bIsTextureRType = FALSE;
    // HRESULT hResult;

    // LPDIRECT3D9_INT This = IDirect3D9ToImpl(iface);
    // LOCK_D3D9();

    // if (Adapter >= This->NumDisplayAdapters)
    // {
        // DPRINT1("Invalid Adapter number specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (DeviceType != D3DDEVTYPE_HAL &&
        // DeviceType != D3DDEVTYPE_REF &&
        // DeviceType != D3DDEVTYPE_SW)
    // {
        // DPRINT1("Invalid DeviceType specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (AdapterFormat == D3DFMT_UNKNOWN ||
        // CheckFormat == D3DFMT_UNKNOWN)
    // {
        // DPRINT1("Invalid D3DFORMAT specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if ((Usage & (D3DUSAGE_DONOTCLIP | D3DUSAGE_NPATCHES | D3DUSAGE_POINTS | D3DUSAGE_RTPATCHES | D3DUSAGE_TEXTAPI | D3DUSAGE_WRITEONLY)) != 0) //TO be removed to support Directx9EX
    // {
        // DPRINT1("Invalid Usage specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (RType == D3DRTYPE_TEXTURE ||
        // RType == D3DRTYPE_VOLUMETEXTURE ||
        // RType == D3DRTYPE_CUBETEXTURE)
    // {
        // bIsTextureRType = TRUE;
    // }
    // else if (RType == D3DRTYPE_SURFACE &&
            // (Usage & (D3DUSAGE_DEPTHSTENCIL | D3DUSAGE_RENDERTARGET)) == 0 &&
            // Usage != 0)
    // {
        // DPRINT1("When RType is set to D3DRTYPE_SURFACE, Usage must be 0 or have set D3DUSAGE_DEPTHSTENCIL or D3DUSAGE_RENDERTARGET");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if ((Usage & D3DUSAGE_DEPTHSTENCIL) != 0)
    // {
        // if (FALSE == IsZBufferFormat(CheckFormat))
        // {
            // DPRINT1("Invalid CheckFormat Z-Buffer format");
            // UNLOCK_D3D9();
            // return D3DERR_INVALIDCALL;
        // }

        // if ((Usage & D3DUSAGE_AUTOGENMIPMAP) != 0)
        // {
            // DPRINT1("Invalid Usage specified, D3DUSAGE_DEPTHSTENCIL and D3DUSAGE_AUTOGENMIPMAP can't be combined.");
            // UNLOCK_D3D9();
            // return D3DERR_INVALIDCALL;
        // }
    // }

    // if (FALSE == bIsTextureRType &&
        // RType != D3DRTYPE_SURFACE &&
        // RType != D3DRTYPE_VOLUME)
    // {
        // DPRINT1("Invalid RType specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if ((Usage & (D3DUSAGE_AUTOGENMIPMAP | D3DUSAGE_DEPTHSTENCIL | D3DUSAGE_RENDERTARGET)) != 0)
    // {
        // if (RType == D3DRTYPE_VOLUME || RType == D3DRTYPE_VOLUMETEXTURE)
        // {
            // DPRINT1("Invalid Usage specified, D3DUSAGE_AUTOGENMIPMAP, D3DUSAGE_DEPTHSTENCIL and D3DUSAGE_RENDERTARGET can't be combined with RType D3DRTYPE_VOLUME or D3DRTYPE_VOLUMETEXTURE");
            // UNLOCK_D3D9();
            // return D3DERR_INVALIDCALL;
        // }
    // }

    // if (FALSE == bIsTextureRType &&
        // (Usage & D3DUSAGE_QUERY_VERTEXTEXTURE) != 0)
    // {
        // DPRINT1("Invalid Usage specified, D3DUSAGE_QUERY_VERTEXTEXTURE can only be used with a texture RType");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if ((Usage & D3DUSAGE_AUTOGENMIPMAP) != 0 &&
        // TRUE == IsMultiElementFormat(CheckFormat))
    // {
        // DPRINT1("Invalid Usage specified, D3DUSAGE_AUTOGENMIPMAP can't be used with a multi-element format");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // pDriverCaps = &This->DisplayAdapters[Adapter].DriverCaps;
    // if (((Usage & D3DUSAGE_DYNAMIC) != 0) && (bIsTextureRType != FALSE))
    // {
        // if ((pDriverCaps->DriverCaps9.Caps2 & D3DCAPS2_DYNAMICTEXTURES) == 0)
        // {
            // DPRINT1("Driver doesn't support dynamic textures");
            // UNLOCK_D3D9();
            // return D3DERR_NOTAVAILABLE;
        // }

        // if ((Usage & (D3DUSAGE_DEPTHSTENCIL | D3DUSAGE_RENDERTARGET)) != 0)
        // {
            // DPRINT1("Invalid Usage specified, D3DUSAGE_DEPTHSTENCIL and D3DUSAGE_RENDERTARGET can't be combined with D3DUSAGE_DYNAMIC and a texture RType");
            // UNLOCK_D3D9();
            // return D3DERR_INVALIDCALL;
        // }
    // }

    // if ((Usage & D3DUSAGE_DMAP) != 0)
    // {
        // if ((pDriverCaps->DriverCaps9.DevCaps2 & (D3DDEVCAPS2_PRESAMPLEDDMAPNPATCH | D3DDEVCAPS2_DMAPNPATCH)) == 0)
        // {
            // DPRINT1("Driver doesn't support displacement mapping");
            // UNLOCK_D3D9();
            // return D3DERR_NOTAVAILABLE;
        // }

        // if (RType != D3DRTYPE_TEXTURE)
        // {
            // DPRINT1("Invalid Usage specified, D3DUSAGE_DMAP must be combined with RType D3DRTYPE_TEXTURE");
            // UNLOCK_D3D9();
            // return D3DERR_INVALIDCALL;
        // }
    // }

    // hResult = CheckDeviceFormat(pDriverCaps, AdapterFormat, Usage, RType, CheckFormat);

    // UNLOCK_D3D9();
    // return hResult;
	return IDirect3D9_CheckDeviceFormat(ProxyInterface, Adapter, DeviceType, AdapterFormat, Usage, RType, CheckFormat);
}

static 
HRESULT 
WINAPI 
IDirect3D9Impl_CheckDeviceMultiSampleType(
	LPDIRECT3D9EX iface, 
	UINT Adapter, 
	D3DDEVTYPE DeviceType,
    D3DFORMAT SurfaceFormat,
	BOOL Windowed,
    D3DMULTISAMPLE_TYPE MultiSampleType, 
	DWORD* pQualityLevels)
{
    // HRESULT hr;
	// D3DCAPS9* pAdapterCaps = NULL;
	// DDSURFACEDESC * pSupportedFormatOps;
	// LPD3D9_DRIVERCAPS pDriverCaps;
	// UINT i;

    // LPDIRECT3D9_INT This = IDirect3D9ToImpl(iface);
    // LOCK_D3D9();

    // if (Adapter >= This->NumDisplayAdapters)
    // {
        // DbgPrint("Invalid Adapter number specified.\n");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // // Check Device Type
    // if (DeviceType != D3DDEVTYPE_REF &&
        // DeviceType != D3DDEVTYPE_HAL &&
        // DeviceType != D3DDEVTYPE_SW)
    // {
        // DbgPrint("Invalid device specified to CheckDeviceMultiSampleType.\n");
        // return D3DERR_INVALIDCALL;
    // }

    // if (SurfaceFormat == D3DFMT_UNKNOWN)
    // {
        // DbgPrint("D3DFMT_UNKNOWN is not a valid format. CheckDeviceMultiSampleType fails.\n");
        // return D3DERR_INVALIDCALL;
    // }    

    // hr = GetAdapterCaps(&This->DisplayAdapters[Adapter],
                        // DeviceType,
                        // pAdapterCaps);
    // if (FAILED(hr))
    // {
		// DbgPrint("CheckDeviceMultiSampleType::GetAdapterCaps failed\n");
        // return hr;
    // }

    // if (MultiSampleType == D3DMULTISAMPLE_NONE)
    // {
        // return D3D_OK;
    // }
    // else if (MultiSampleType == 1)
    // {
        // DbgPrint("Invalid sample type specified. Only enumerated values are supported. CheckDeviceMultiSampleType fails.\n");
        // return D3DERR_INVALIDCALL;
    // }
    // else if (MultiSampleType > D3DMULTISAMPLE_16_SAMPLES)
    // {
        // DbgPrint("Invalid sample type specified. CheckDeviceMultiSampleType fails.\n");
        // return D3DERR_INVALIDCALL;
    // }
	
	// DbgPrint("CheckDeviceMultiSampleType get windowed\n");

    // // Treat Ref/SW Fullscreen the same as Windowed.
    // if (DeviceType == D3DDEVTYPE_REF ||
        // DeviceType == D3DDEVTYPE_SW)
    // {
        // Windowed = TRUE;
    // }
	
	// DbgPrint("CheckDeviceMultiSampleType getting SurfaceFormat\n");

    // // If it's a depth/stencil, make sure it's a format that the driver understands
    // SurfaceFormat = MapDepthStencilFormat(&This->DisplayAdapters[Adapter].DriverCaps,
										  // Adapter,
										  // DeviceType, 
										  // SurfaceFormat);
										  
    // DbgPrint("CheckDeviceMultiSampleType getting SurfaceFormat sucessful\n");											
    
	// pDriverCaps = &This->DisplayAdapters[Adapter].DriverCaps;
	// pSupportedFormatOps = pDriverCaps->pSupportedFormatOps;
	
	// DbgPrint("CheckDeviceMultiSampleType looping pSupportedFormatOps\n");
	
    // // let's run through the driver's list and see if it can do it.
    // for (i = 0; i < pDriverCaps->NumSupportedFormatOps; i++)
    // {
        // //We need a match for format, plus all either blt or flip caps
        // if (SurfaceFormat == (D3DFORMAT) pSupportedFormatOps[i].ddpfPixelFormat.dwFourCC)
        // {
            // // Found the format in question... do we have the MS caps?
            // WORD wMSOps = Windowed ?
                // pSupportedFormatOps[i].ddpfPixelFormat.MultiSampleCaps.wBltMSTypes :
                // pSupportedFormatOps[i].ddpfPixelFormat.MultiSampleCaps.wFlipMSTypes;

            // // To determine the bit to use, we map the set of sample-types [2-16] to
            // // a particular (bit 1 to bit 15) of the WORD.
            // ASSERT(MultiSampleType > 1);
            // ASSERT(MultiSampleType <= 16);
            // if (wMSOps & DDI_MULTISAMPLE_TYPE(MultiSampleType))
            // {
                // return D3D_OK;
            // }
        // }
    // }

    return IDirect3D9_CheckDeviceMultiSampleType(ProxyInterface, Adapter, DeviceType, SurfaceFormat, Windowed, MultiSampleType, pQualityLevels);
}


/*++
* @name IDirect3D9::CheckDepthStencilMatch
* @implemented
*
* The function IDirect3D9Impl_CheckDepthStencilMatch checks if a specific combination
* of a render target D3DFORMAT and a depth-stencil D3DFORMAT can be used with a specified
* D3DFORMAT on the specified display adapter.
*
* @param LPDIRECT3D iface
* Pointer to the IDirect3D9 object returned from Direct3DCreate9()
*
* @param UINT Adapter
* Adapter index to get information about. D3DADAPTER_DEFAULT is the primary display.
* The maximum value for this is the value returned by IDirect3D9::GetAdapterCount() - 1.
*
* @param D3DDEVTYPE DeviceType
* One of the D3DDEVTYPE enum members.
*
* @param D3DFORMAT AdapterFormat
* One of the D3DFORMAT enum members except D3DFMT_UNKNOWN that the display adapter mode where the test should occur.
*
* @param D3DFORMAT RenderTargetFormat
* One of the D3DFORMAT enum members except D3DFMT_UNKNOWN for the display adapter mode's render target format to be tested.
*
* @param D3DFORMAT DepthStencilFormat
* One of the D3DFORMAT enum members except D3DFMT_UNKNOWN for the display adapter mode's depth-stencil format to be tested.
*
* @return HRESULT
* If the DepthStencilFormat can be used with the RenderTargetFormat under the specified AdapterFormat,
* the method returns D3D_OK.
* If the DepthStencilFormat can NOT used with the RenderTargetFormat under the specified AdapterFormat,
* the method returns D3DERR_NOTAVAILABLE.
* If Adapter is out of range, DeviceType is invalid,
* AdapterFormat, RenderTargetFormat or DepthStencilFormat is invalid, the method returns D3DERR_INVALIDCALL.
*
*/
static HRESULT WINAPI IDirect3D9Impl_CheckDepthStencilMatch(LPDIRECT3D9EX iface, UINT Adapter, D3DDEVTYPE DeviceType,
                                                            D3DFORMAT AdapterFormat, D3DFORMAT RenderTargetFormat,
                                                            D3DFORMAT DepthStencilFormat)
{
    // HRESULT hResult;

    // LPDIRECT3D9_INT This = IDirect3D9ToImpl(iface);
    // LOCK_D3D9();

    // if (Adapter >= This->NumDisplayAdapters)
    // {
        // DPRINT1("Invalid Adapter number specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (DeviceType != D3DDEVTYPE_HAL &&
        // DeviceType != D3DDEVTYPE_REF &&
        // DeviceType != D3DDEVTYPE_SW)
    // {
        // DPRINT1("Invalid DeviceType specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (AdapterFormat == D3DFMT_UNKNOWN ||
        // RenderTargetFormat == D3DFMT_UNKNOWN ||
        // DepthStencilFormat == D3DFMT_UNKNOWN)
    // {
        // DPRINT1("Invalid D3DFORMAT specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // hResult = CheckDepthStencilMatch(&This->DisplayAdapters[Adapter].DriverCaps, AdapterFormat, RenderTargetFormat, DepthStencilFormat);

    // UNLOCK_D3D9();
    // return hResult;
	return IDirect3D9_CheckDepthStencilMatch(ProxyInterface, Adapter, DeviceType, AdapterFormat, RenderTargetFormat, DepthStencilFormat);
}


/*++
* @name IDirect3D9::CheckDeviceFormatConversion
* @implemented
*
* The function IDirect3D9Impl_CheckDeviceFormatConversion checks if a specific D3DFORMAT
* can be converted to another on the specified display adapter.
*
* @param LPDIRECT3D iface
* Pointer to the IDirect3D9 object returned from Direct3DCreate9()
*
* @param UINT Adapter
* Adapter index to get information about. D3DADAPTER_DEFAULT is the primary display.
* The maximum value for this is the value returned by IDirect3D9::GetAdapterCount() - 1.
*
* @param D3DDEVTYPE DeviceType
* One of the D3DDEVTYPE enum members. Only D3DDEVTYPE_HAL can potentially return D3D_OK.
*
* @param D3DFORMAT SourceFormat
* One of the D3DFORMAT enum members except D3DFMT_UNKNOWN for the display adapter mode to be converted from.
*
* @param D3DFORMAT TargetFormat
* One of the D3DFORMAT enum members except D3DFMT_UNKNOWN for the display adapter mode to be converted to.
*
* @return HRESULT
* If the SourceFormat can be converted to the TargetFormat, the method returns D3D_OK.
* If the SourceFormat can NOT be converted to the TargetFormat, the method returns D3DERR_NOTAVAILABLE.
* If Adapter is out of range, DeviceType is invalid,
* SourceFormat or TargetFormat is invalid, the method returns D3DERR_INVALIDCALL.
*
*/
static HRESULT WINAPI IDirect3D9Impl_CheckDeviceFormatConversion(LPDIRECT3D9EX iface, UINT Adapter, D3DDEVTYPE DeviceType,
                                                                 D3DFORMAT SourceFormat, D3DFORMAT TargetFormat)
{
    // HRESULT hResult;
    // LPDIRECT3D9_INT This = IDirect3D9ToImpl(iface);
    // LOCK_D3D9();

    // if (Adapter >= This->NumDisplayAdapters)
    // {
        // DPRINT1("Invalid Adapter number specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (DeviceType != D3DDEVTYPE_HAL &&
        // DeviceType != D3DDEVTYPE_REF &&
        // DeviceType != D3DDEVTYPE_SW)
    // {
        // DPRINT1("Invalid DeviceType specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (SourceFormat == D3DFMT_UNKNOWN ||
        // TargetFormat == D3DFMT_UNKNOWN)
    // {
        // DPRINT1("Invalid D3DFORMAT specified");
        // UNLOCK_D3D9();
        // return D3DERR_NOTAVAILABLE;
    // }

    // if (DeviceType == D3DDEVTYPE_HAL)
    // {
        // hResult = CheckDeviceFormatConversion(&This->DisplayAdapters[Adapter].DriverCaps, SourceFormat, TargetFormat);
    // }
    // else
    // {
        // hResult = D3DERR_NOTAVAILABLE;
    // }

    // UNLOCK_D3D9();
    // return hResult;
	return IDirect3D9_CheckDeviceFormatConversion(ProxyInterface, Adapter, DeviceType, SourceFormat, TargetFormat);
}


/*++
* @name IDirect3D9::GetDeviceCaps
* @implemented
*
* The function IDirect3D9Impl_GetDeviceCaps fills the pCaps argument with the
* capabilities of the specified adapter and device type.
*
* @param LPDIRECT3D iface
* Pointer to the IDirect3D9 object returned from Direct3DCreate9()
*
* @param UINT Adapter
* Adapter index to get information about. D3DADAPTER_DEFAULT is the primary display.
* The maximum value for this is the value returned by IDirect3D9::GetAdapterCount() - 1.
*
* @param D3DDEVTYPE DeviceType
* One of the D3DDEVTYPE enum members.
* NOTE: Currently only D3DDEVTYPE_HAL is implemented.
*
* @param D3DCAPS9* pCaps
* Pointer to a D3DCAPS9 structure to be filled with the adapter's device type capabilities.
*
* @return HRESULT
* If the method successfully fills the pCaps structure, the return value is D3D_OK.
* If Adapter is out of range or pCaps is a bad pointer, the return value will be D3DERR_INVALIDCALL.
* If DeviceType is invalid, the return value will be D3DERR_INVALIDDEVICE.
*
*/
static HRESULT WINAPI IDirect3D9Impl_GetDeviceCaps(LPDIRECT3D9EX iface, UINT Adapter, D3DDEVTYPE DeviceType, D3DCAPS9* pCaps)
{
    // HRESULT hResult;
    // LPDIRECT3D9_INT This = IDirect3D9ToImpl(iface);
    // LOCK_D3D9();

    // if (Adapter >= This->NumDisplayAdapters)
    // {
        // DPRINT1("Invalid Adapter number specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (NULL == pCaps)
    // {
        // DPRINT1("Invalid pCaps parameter specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // hResult = GetAdapterCaps(&This->DisplayAdapters[Adapter], DeviceType, pCaps);

    // UNLOCK_D3D9();
    // return hResult;
	return IDirect3D9_GetDeviceCaps(ProxyInterface, Adapter, DeviceType, pCaps);
}

/*++
* @name IDirect3D9::GetAdapterMonitor
* @implemented
*
* The function IDirect3D9Impl_GetAdapterMonitor returns the monitor associated
* with the specified display adapter.
*
* @param LPDIRECT3D iface
* Pointer to the IDirect3D9 object returned from Direct3DCreate9()
*
* @param UINT Adapter
* Adapter index to get information about. D3DADAPTER_DEFAULT is the primary display.
* The maximum value for this is the value returned by IDirect3D9::GetAdapterCount() - 1.
*
* @return HMONITOR
* If the method successfully it returns the HMONITOR belonging to the specified adapter.
* If the method fails, the return value is NULL.
*
*/
static HMONITOR WINAPI IDirect3D9Impl_GetAdapterMonitor(LPDIRECT3D9EX iface, UINT Adapter)
{
    // HMONITOR hAdapterMonitor = NULL;

    // LPDIRECT3D9_INT This = IDirect3D9ToImpl(iface);
    // LOCK_D3D9();

    // if (Adapter < This->NumDisplayAdapters)
    // {
        // hAdapterMonitor = GetAdapterMonitor(This->DisplayAdapters[Adapter].szDeviceName);
    // }
    // else
    // {
        // DPRINT1("Invalid Adapter number specified");
    // }

    // UNLOCK_D3D9();
    // return hAdapterMonitor;
	return IDirect3D9_GetAdapterMonitor(ProxyInterface, Adapter);
}

HRESULT CreateD3D9DeviceEx(OUT LPDIRECT3DDEVICE9 *ppDirect3D9)
{
    LPDIRECT3DDEVICE9_INT pThisBaseDevice;
	
    if (ppDirect3D9 == 0)
        return DDERR_INVALIDPARAMS;

    if (AlignedAlloc((LPVOID *)&pThisBaseDevice, sizeof(DIRECT3DDEVICE9_INT)) != S_OK)
        return DDERR_OUTOFMEMORY;

    if (pThisBaseDevice == 0)
        return DDERR_OUTOFMEMORY;	

    pThisBaseDevice->lpVtbl = &Direct3DDevice9Ex_Vtbl;
    pThisBaseDevice->dwProcessId = GetCurrentThreadId();
    pThisBaseDevice->lRefCnt = 1;

    InitializeCriticalSection(&pThisBaseDevice->CriticalSection);

    *ppDirect3D9 = (LPDIRECT3DDEVICE9)&pThisBaseDevice->lpVtbl;

    return D3D_OK;
}

/*++
* @name IDirect3D9::CreateDevice
* @implemented
*
* The function IDirect3D9Impl_CreateDevice creates an IDirect3DDevice9 object
* that represents the display adapter.
*
* @param LPDIRECT3D iface
* Pointer to the IDirect3D9 object returned from Direct3DCreate9()
*
* @param UINT Adapter
* Adapter index to get information about. D3DADAPTER_DEFAULT is the primary display.
* The maximum value for this is the value returned by IDirect3D::GetAdapterCount() - 1.
*
* @param D3DDEVTYPE DeviceType
* One of the D3DDEVTYPE enum members.
*
* @param HWND hFocusWindow
* A window handle that is used as a reference when Direct3D should switch between
* foreground mode and background mode.
*
* @param DWORD BehaviourFlags
* Any valid combination of the D3DCREATE constants.
*
* @param D3DPRESENT_PARAMETERS* pPresentationParameters
* Pointer to a D3DPRESENT_PARAMETERS structure describing the parameters for the device
* to be created. If D3DCREATE_ADAPTERGROUP_DEVICE is specified in the BehaviourFlags parameter,
* the pPresentationParameters is treated as an array.
*
* @param IDirect3DDevice9** ppReturnedDeviceInterface
* Return object that represents the created device.
*
* @return HRESULT
* If the method successfully creates a device and returns a valid ppReturnedDeviceInterface object,
* the return value is D3D_OK.
* If Adapter is out of range, DeviceType is invalid, hFocusWindow is not a valid, BehaviourFlags is invalid
* pPresentationParameters is invalid or ppReturnedDeviceInterface is a bad pointer, the return value
* will be D3DERR_INVALIDCALL.
*
*/
static HRESULT WINAPI IDirect3D9Impl_CreateDevice(LPDIRECT3D9EX iface, UINT Adapter, D3DDEVTYPE DeviceType,
                                                  HWND hFocusWindow, DWORD BehaviourFlags,
                                                  D3DPRESENT_PARAMETERS* pPresentationParameters,
                                                  struct IDirect3DDevice9** ppReturnedDeviceInterface)
{
    HRESULT Ret;
	
	Ret = IDirect3D9_CreateDevice(ProxyInterface, Adapter, DeviceType, hFocusWindow, BehaviourFlags, pPresentationParameters, &DeviceProxyInterface);

	if(Ret == D3D_OK){
       Ret = CreateD3D9DeviceEx(ppReturnedDeviceInterface);
	}

    return Ret;
}

static UINT WINAPI IDirect3D9Impl_GetAdapterModeCountEx(IDirect3D9Ex *iface,
        UINT adapter, const D3DDISPLAYMODEFILTER *filter)
{
    UINT count; 
	
	if (!filter || filter->Size != sizeof(D3DDISPLAYMODEFILTER)) 
        return 0;
    
    count = IDirect3D9Impl_GetAdapterModeCount(iface, adapter, filter->Format);
    
    return count;	
}

static HRESULT WINAPI IDirect3D9Impl_EnumAdapterModesEx(IDirect3D9Ex *iface,
        UINT adapter, const D3DDISPLAYMODEFILTER *filter, UINT mode_idx, D3DDISPLAYMODEEX *mode)
{
    D3DDISPLAYMODE pMode;
    HRESULT hr;
    
    if (!mode || mode->Size != sizeof(D3DDISPLAYMODEEX)) 
        return D3DERR_INVALIDCALL;
    
    pMode.Width = mode->Width;
    pMode.Height = mode->Height;
    pMode.RefreshRate = mode->RefreshRate;
    pMode.Format = mode->Format;
    
    hr = IDirect3D9Impl_EnumAdapterModes(iface, adapter, filter->Format, mode_idx, &pMode);
    if (SUCCEEDED(hr)) {       
        mode->Width = pMode.Width;
        mode->Height = pMode.Height;
        mode->RefreshRate = pMode.RefreshRate;
        mode->Format = pMode.Format;
        mode->ScanLineOrdering = D3DSCANLINEORDERING_PROGRESSIVE;
    }
    
    return hr;    
}

static HRESULT WINAPI IDirect3D9Impl_GetAdapterDisplayModeEx(IDirect3D9Ex *iface,
        UINT adapter, D3DDISPLAYMODEEX *mode, D3DDISPLAYROTATION *rotation)
{
    D3DDISPLAYMODE pMode;
    HRESULT hr;
    
    if (!mode) {
        if (!rotation)
            return D3DERR_INVALIDCALL;
        *rotation = D3DDISPLAYROTATION_IDENTITY;
        return S_OK;
    } else if (mode->Size != sizeof(D3DDISPLAYMODEEX))
        return D3DERR_INVALIDCALL;
    
    pMode.Width = mode->Width;
    pMode.Height = mode->Height;
    pMode.RefreshRate = mode->RefreshRate;
    pMode.Format = mode->Format;
    
    hr = IDirect3D9Impl_GetAdapterDisplayMode(iface, adapter,  &pMode);
    if (SUCCEEDED(hr)) {
        if (rotation)
            *rotation = D3DDISPLAYROTATION_IDENTITY;
        
        mode->Width = pMode.Width;
        mode->Height = pMode.Height;
        mode->RefreshRate = pMode.RefreshRate;
        mode->Format = pMode.Format;
        mode->ScanLineOrdering = D3DSCANLINEORDERING_PROGRESSIVE;
    }
    
    return hr;
}

static HRESULT WINAPI IDirect3D9Impl_CreateDeviceEx(IDirect3D9Ex *iface,
        UINT Adapter, D3DDEVTYPE DeviceType, HWND hFocusWindow, DWORD BehaviourFlags,
        D3DPRESENT_PARAMETERS *pPresentationParameters, D3DDISPLAYMODEEX *mode, IDirect3DDevice9Ex **ppReturnedDeviceInterface)
{
    // DWORD NumAdaptersToCreate;
    // HRESULT Ret;
    // LPDIRECT3D9_INT This = IDirect3D9ToImpl(iface);
    // LOCK_D3D9();

    // if (Adapter >= This->NumDisplayAdapters)
    // {
        // DPRINT1("Invalid Adapter number specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (DeviceType != D3DDEVTYPE_HAL &&
        // DeviceType != D3DDEVTYPE_REF &&
        // DeviceType != D3DDEVTYPE_SW)
    // {
        // DPRINT1("Invalid DeviceType specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (DeviceType != D3DDEVTYPE_HAL)
    // {
        // UNIMPLEMENTED;
        // DPRINT1("Sorry, only D3DDEVTYPE_HAL is implemented at this time...");
        // return D3DERR_INVALIDCALL;
    // }

    // if (hFocusWindow != NULL && FALSE == IsWindow(hFocusWindow))
    // {
        // DPRINT1("Invalid hFocusWindow parameter specified, expected NULL or a valid HWND");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (NULL == pPresentationParameters)
    // {
        // DPRINT1("Invalid pPresentationParameters parameter specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (pPresentationParameters->hDeviceWindow != NULL && FALSE == IsWindow(pPresentationParameters->hDeviceWindow))
    // {
        // DPRINT1("Invalid pPresentationParameters->hDeviceWindow parameter specified, expected NULL or a valid HWND");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (FALSE == pPresentationParameters->Windowed && hFocusWindow == NULL)
    // {
        // DPRINT1("When pPresentationParameters->Windowed is not set, hFocusWindow must be a valid HWND");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (NULL == hFocusWindow && NULL == pPresentationParameters->hDeviceWindow)
    // {
        // DPRINT1("Any of pPresentationParameters->Windowed and hFocusWindow must be set to a valid HWND");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (Adapter > 0 && NULL == pPresentationParameters->hDeviceWindow)
    // {
        // DPRINT1("Invalid pPresentationParameters->hDeviceWindow, must be set to a valid unique HWND when Adapter is greater than 0");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if (NULL == ppReturnedDeviceInterface)
    // {
        // DPRINT1("Invalid ppReturnedDeviceInterface parameter specified");
        // UNLOCK_D3D9();
        // return D3DERR_INVALIDCALL;
    // }

    // if ((BehaviourFlags & D3DCREATE_ADAPTERGROUP_DEVICE) != 0)
        // NumAdaptersToCreate = This->DisplayAdapters[Adapter].NumAdaptersInGroup;
    // else
        // NumAdaptersToCreate = 1;

    // *ppReturnedDeviceInterface = 0;
	
	// Ret = IDirect3D9_CreateDevice(ProxyInterface, Adapter, DeviceType, hFocusWindow, BehaviourFlags, pPresentationParameters, &DeviceProxyInterface);


	// //ppReturnedDeviceInterface.lpVtbl = &Direct3DDevice9ExHAL_Vtbl;
	// //*ppReturnedDeviceInterface = DeviceProxyInterface;
	// if(Ret == S_OK){
		// Ret = CreateD3D9HalDeviceEx(This, Adapter, hFocusWindow, BehaviourFlags, pPresentationParameters, NumAdaptersToCreate, ppReturnedDeviceInterface);	
	// }

    // UNLOCK_D3D9();
    // return Ret;
    HRESULT Ret;
	
	Ret = IDirect3D9_CreateDevice(ProxyInterface, Adapter, DeviceType, hFocusWindow, BehaviourFlags, pPresentationParameters, &DeviceProxyInterface);

	if(Ret == D3D_OK){
       Ret = CreateD3D9DeviceEx((LPDIRECT3DDEVICE9*)ppReturnedDeviceInterface);
	}

    return Ret;
}

static HRESULT WINAPI IDirect3D9Impl_GetAdapterLUID(IDirect3D9Ex *iface, UINT Adapter, LUID *pLuid)
{
    // struct d3d9 *d3d9 = impl_from_IDirect3D9Ex(iface);
    // struct wined3d_adapter_identifier adapter_id;
    // struct wined3d_adapter *wined3d_adapter;
    // unsigned int output_idx;
    // HRESULT hr;

    // TRACE("iface %p, adapter %u, luid %p.\n", iface, adapter, luid);

    // output_idx = adapter;
    // if (output_idx >= d3d9->wined3d_output_count)
        // return D3DERR_INVALIDCALL;

    // adapter_id.driver_size = 0;
    // adapter_id.description_size = 0;

    // wined3d_adapter = wined3d_output_get_adapter(d3d9->wined3d_outputs[output_idx]);
    // if (SUCCEEDED(hr = wined3d_adapter_get_identifier(wined3d_adapter, 0, &adapter_id)))
        // *luid = adapter_id.adapter_luid;

    D3DADAPTER_IDENTIFIER9 adapterIdentifier;
    HRESULT hr;

    if (!iface || !pLuid)
        return D3DERR_INVALIDCALL;

    // Obtém as informações do adaptador
    hr = IDirect3D9Impl_GetAdapterIdentifier(iface, Adapter, 0, &adapterIdentifier);
    if (FAILED(hr))
        return hr;

    // Gera um LUID baseado nas informações do adaptador
    // Aqui, estamos usando o DeviceId e o VendorId para criar um LUID simples
    // Isso não é um LUID real, mas serve como um identificador único para o adaptador
    pLuid->LowPart = adapterIdentifier.DeviceId;
    pLuid->HighPart = adapterIdentifier.VendorId;

    return hr;
}

IDirect3D9ExVtbl Direct3D9Ex_Vtbl =
{
    /* IUnknown */
    IDirect3D9Impl_QueryInterface,
    IDirect3D9Impl_AddRef,
    IDirect3D9Impl_Release,

    /* IDirect3D9 */
    IDirect3D9Impl_RegisterSoftwareDevice,
    IDirect3D9Impl_GetAdapterCount,
    IDirect3D9Impl_GetAdapterIdentifier,
    IDirect3D9Impl_GetAdapterModeCount,
    IDirect3D9Impl_EnumAdapterModes,
    IDirect3D9Impl_GetAdapterDisplayMode,
    IDirect3D9Impl_CheckDeviceType,
    IDirect3D9Impl_CheckDeviceFormat,
    IDirect3D9Impl_CheckDeviceMultiSampleType,
    IDirect3D9Impl_CheckDepthStencilMatch,
    IDirect3D9Impl_CheckDeviceFormatConversion,
    IDirect3D9Impl_GetDeviceCaps,
    IDirect3D9Impl_GetAdapterMonitor,
    IDirect3D9Impl_CreateDevice,
    /* IDirect3D9Ex */
    IDirect3D9Impl_GetAdapterModeCountEx,
    IDirect3D9Impl_EnumAdapterModesEx,
    IDirect3D9Impl_GetAdapterDisplayModeEx,
    IDirect3D9Impl_CreateDeviceEx,
    IDirect3D9Impl_GetAdapterLUID	
};

// IDirect3D9Vtbl Direct3D9_Vtbl =
// {
    // /* IUnknown */
    // IDirect3D9Impl_QueryInterface,
    // IDirect3D9Impl_AddRef,
    // IDirect3D9Impl_Release,

    // /* IDirect3D9 */
    // IDirect3D9Impl_RegisterSoftwareDevice,
    // IDirect3D9Impl_GetAdapterCount,
    // IDirect3D9Impl_GetAdapterIdentifier,
    // IDirect3D9Impl_GetAdapterModeCount,
    // IDirect3D9Impl_EnumAdapterModes,
    // IDirect3D9Impl_GetAdapterDisplayMode,
    // IDirect3D9Impl_CheckDeviceType,
    // IDirect3D9Impl_CheckDeviceFormat,
    // IDirect3D9Impl_CheckDeviceMultiSampleType,
    // IDirect3D9Impl_CheckDepthStencilMatch,
    // IDirect3D9Impl_CheckDeviceFormatConversion,
    // IDirect3D9Impl_GetDeviceCaps,
    // IDirect3D9Impl_GetAdapterMonitor,
    // IDirect3D9Impl_CreateDevice
// };
