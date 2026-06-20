/*++

Copyright (c) 2025 Shorthorn Project

Module Name:

    exticon.c

Abstract:

        This file implements the NT routines for icons extraction.

Author:

    Skulltrail 01-August-2025

Revision History:

--*/


#include <main.h>
#include <wingdi.h>

/* Start of Hack section */

WINE_DEFAULT_DEBUG_CHANNEL(icon);

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define IMAGE_ICO_SIGNATURE 1
#define IMAGE_CUR_SIGNATURE 2

#define IMAGE_SIZEOF_NT_OPTIONAL32_HEADER    224
#define IMAGE_SIZEOF_NT_OPTIONAL64_HEADER    240

#define __REACTOS__ 1

#ifdef __REACTOS__

#include <pshpack1.h>

typedef struct
{
    BYTE   bWidth;       /* Width, in pixels, of the image */
    BYTE   bHeight;      /* Height, in pixels, of the image */
    BYTE   bColorCount;  /* Number of colors in image (0 if >=8bpp) */
    BYTE   bReserved;    /* Reserved (must be 0) */
    WORD   wPlanes;      /* Color Planes */
    WORD   wBitCount;    /* Bits per pixel */
    DWORD  dwBytesInRes; /* How many bytes in this resource? */
    DWORD  dwImageOffset;/* Where in the file is this image? */
} icoICONDIRENTRY, *LPicoICONDIRENTRY;

typedef struct
{
    WORD            idReserved;   /* Reserved (must be 0) */
    WORD            idType;       /* Resource Type (RES_ICON or RES_CURSOR) */
    WORD            idCount;      /* How many images */
    icoICONDIRENTRY idEntries[1]; /* An entry for each image (idCount of them) */
} icoICONDIR, *LPicoICONDIR;

typedef struct
{
    WORD offset;
    WORD length;
    WORD flags;
    WORD id;
    WORD handle;
    WORD usage;
} NE_NAMEINFO;

typedef struct
{
    WORD  type_id;
    WORD  count;
    DWORD resloader;
} NE_TYPEINFO;

/* From: James Houghtaling
 * https://www.moon-soft.com/program/FORMAT/windows/ani.htm */
typedef struct taganiheader
{
    DWORD cbsizeof;  /* num bytes in aniheader (36 bytes) */
    DWORD cframes;   /* number of unique icons in this cursor */
    DWORD csteps;    /* number of blits before the animation cycles */
    DWORD cx;        /* reserved, must be zero */
    DWORD cy;        /* reserved, must be zero */
    DWORD cbitcount; /* reserved, must be zero */
    DWORD cplanes;   /* reserved, must be zero */
    DWORD jifrate;   /* default jiffies (1/60th sec) if rate chunk not pDataent */
    DWORD flags;     /* animation flag */
} aniheader;
#endif

typedef struct _ICONIMAGE
{
    BITMAPINFOHEADER icHeader;   /* DIB header */
    RGBQUAD          icColors[1];/* Color table */
    BYTE             icXOR[1];   /* DIB bits for XOR mask */
    BYTE             icAND[1];   /* DIB bits for AND mask */
} ICONIMAGE, *LPICONIMAGE;

#define NE_RSCTYPE_ICON        0x8003
#define NE_RSCTYPE_GROUP_ICON  0x800e

#ifndef WINE
DWORD get_best_icon_file_offset(const LPBYTE dir,
                                DWORD dwFileSize,
                                int cxDesired,
                                int cyDesired,
                                BOOL bIcon,
                                DWORD fuLoad,
                                POINT *ptHotSpot);
#endif

/*************************************************************************
 *  USER32_GetResourceTable
 */
static DWORD USER32_GetBinaryType(LPBYTE peimage, DWORD pesize, LPBYTE *retptr)
{
    IMAGE_DOS_HEADER *mz_header;

	_try{
    *retptr = NULL;
		mz_header = (IMAGE_DOS_HEADER*) peimage;

		if (mz_header->e_magic != IMAGE_DOS_SIGNATURE)
		{
			if (mz_header->e_cblp == 1 || mz_header->e_cblp == 2) /* .ICO or .CUR file ? */
			{
				*retptr = (LPBYTE)-1; /* ICONHEADER.idType, must be 1 */
				return mz_header->e_cblp;
			}
			return 0; /* failed */
		}

		if (mz_header->e_lfanew >= pesize)
			return 0; /* failed, happens with PKZIP DOS Exes for instance */

		if (*((DWORD*)(peimage + mz_header->e_lfanew)) == IMAGE_NT_SIGNATURE)
			return IMAGE_NT_SIGNATURE;

		if (*((WORD*)(peimage + mz_header->e_lfanew)) == IMAGE_OS2_SIGNATURE)
		{
			IMAGE_OS2_HEADER *ne_header;
			ne_header = (IMAGE_OS2_HEADER*)(peimage + mz_header->e_lfanew);

			if (ne_header->ne_magic != IMAGE_OS2_SIGNATURE)
				return 0;

			if ((ne_header->ne_restab - ne_header->ne_rsrctab) <= sizeof(NE_TYPEINFO))
				*retptr = (LPBYTE)-1;
			else
				*retptr = peimage + mz_header->e_lfanew + ne_header->ne_rsrctab;

			return IMAGE_OS2_SIGNATURE;
		}
	}_except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
	
    return 0; /* failed */
}

LPVOID RVAtoP(LPVOID pBase, DWORD rva)
{
    IMAGE_DOS_HEADER *pmz;
    IMAGE_NT_HEADERS *ppe;
    IMAGE_SECTION_HEADER *pSection;
    int i;

    pmz = (IMAGE_DOS_HEADER*)pBase;
    ppe = (IMAGE_NT_HEADERS*)((BYTE*)pBase + pmz->e_lfanew);

    pSection = IMAGE_FIRST_SECTION(ppe);

    for (i=0; i<ppe->FileHeader.NumberOfSections; i++)
    {
        DWORD size;

        size = pSection[i].Misc.VirtualSize ?
               pSection[i].Misc.VirtualSize : pSection[i].SizeOfRawData;

        if (rva >= pSection[i].VirtualAddress &&
            rva <  pSection[i].VirtualAddress + size)
        {
            return (LPBYTE)pBase + pSection[i].PointerToRawData + (rva - pSection[i].VirtualAddress);
        }
    }

    return NULL;
}

LPVOID USER32_GetResourceTablePE(
    LPVOID pBase)
{
    IMAGE_DOS_HEADER *pmz;
    IMAGE_NT_HEADERS *ppe;

    pmz = (IMAGE_DOS_HEADER*)pBase;
    ppe = (IMAGE_NT_HEADERS*)((BYTE*)pBase + pmz->e_lfanew);

    if (pmz->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    if (ppe->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    if (ppe->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        IMAGE_NT_HEADERS64* imgNt64 = (IMAGE_NT_HEADERS64*)ppe;

        if (imgNt64->FileHeader.SizeOfOptionalHeader < IMAGE_SIZEOF_NT_OPTIONAL64_HEADER)
        {
            return 0;
        }
        return RVAtoP(pBase, imgNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
    }
    else 
    {		
        IMAGE_NT_HEADERS32* imgNt32 = (IMAGE_NT_HEADERS32*)ppe;

        if (imgNt32->FileHeader.SizeOfOptionalHeader < IMAGE_SIZEOF_NT_OPTIONAL32_HEADER)
        {
            return 0;
        }
        return RVAtoP(pBase, imgNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
    }
}

LPVOID FindResourceFromBin(LPVOID pBase, LPVOID prt, int iResIndex, int ResType, DWORD *pcb)
{
    int i,nOfEntries;
    IMAGE_RESOURCE_DIRECTORY *pdir;
    IMAGE_RESOURCE_DIRECTORY_ENTRY *pData;
    IMAGE_RESOURCE_DATA_ENTRY *pent;

    pdir = (IMAGE_RESOURCE_DIRECTORY *)prt;

    nOfEntries  = pdir->NumberOfIdEntries + pdir->NumberOfNamedEntries;
    pData = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pdir+1);

    for (i=0; i<nOfEntries; i++)
    {
        if (pData[i].Name == (DWORD)ResType)
            break;
    }

    if (i==nOfEntries)
        return 0;

    pdir = (IMAGE_RESOURCE_DIRECTORY*)((LPBYTE)prt +
        (pData[i].OffsetToData & ~IMAGE_RESOURCE_DATA_IS_DIRECTORY));

    nOfEntries  = pdir->NumberOfIdEntries + pdir->NumberOfNamedEntries;
    pData = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pdir+1);

    if (iResIndex == 424242)
        return (LPVOID)nOfEntries;

    if (iResIndex < 0)
    {
        for (i=0; i<nOfEntries; i++)
            if (pData[i].Name == (DWORD)(-iResIndex))
                break;
    }
    else
    {
        i = iResIndex;
    }

    if (i >= nOfEntries)
        return 0;

    if (pData[i].OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY)
    {
        pdir = (IMAGE_RESOURCE_DIRECTORY*)((LPBYTE)prt +
            (pData[i].OffsetToData & ~IMAGE_RESOURCE_DATA_IS_DIRECTORY));
        pData = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pdir+1);
        i = 0;
    }

    if (pData[i].OffsetToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY)
        return 0;

    pent = (IMAGE_RESOURCE_DATA_ENTRY*)((LPBYTE)prt + pData[i].OffsetToData);

    *pcb = pent->Size;
    return RVAtoP(pBase, pent->OffsetToData);
}

UINT ICO_ExtractIconFromExeDll(
	LPBYTE	peimage,
	LONG fileSize,
	int nIconIndex, 
	int cxIconSize, 
	int cyIconSize, 
	HICON *phicon, 
	UINT *piconid, 
	UINT nIcons, 
	UINT flags
	)
{
    HANDLE hFileMap=INVALID_HANDLE_VALUE;
    LPVOID lpFile=NULL;
    IMAGE_DOS_HEADER *pmz;
    LPVOID pBase;
    LPVOID pData=NULL;
    UINT result=0;
    DWORD cbSize;
    int cxIcon,cyIcon;  
    LPVOID lpIconDir;
    LPVOID lpIcon;
    int idIcon;

    pBase = (LPVOID)peimage;
    pmz = (IMAGE_DOS_HEADER *)pBase;

    _try {
		if (pmz->e_magic != IMAGE_DOS_SIGNATURE)
			goto exit;

		if (pmz->e_lfanew <= 0)
			goto exit;

		if (pmz->e_lfanew >= (LONG)fileSize)
			goto exit;
		
		pData = USER32_GetResourceTablePE(pBase);

		if (pData == NULL)
			goto exit;

		if (phicon == NULL)
		{
			result = (UINT)FindResourceFromBin(pBase, pData, 424242, (int)RT_GROUP_ICON, &cbSize);
			goto exit;
		}

		while (result < nIcons)
		{
			cxIcon = cxIconSize;
			cyIcon = cyIconSize;

			lpIconDir = FindResourceFromBin(pBase, pData, nIconIndex, (int)RT_GROUP_ICON, &cbSize);

			if (lpIconDir == NULL)
				goto exit;
			
	tryAgain:
			idIcon = LookupIconIdFromDirectoryEx((LPBYTE)lpIconDir,TRUE,
				LOWORD(cxIcon),LOWORD(cyIcon),flags);
			lpIcon = FindResourceFromBin(pBase, pData, -idIcon, (int)RT_ICON, &cbSize);

			if (lpIcon == NULL)
				goto exit;

			if (piconid)
				piconid[result] = idIcon;

			phicon[result++] = CreateIconFromResourceExHook((LPBYTE)lpIcon, cbSize,
				TRUE, 0x00030000, LOWORD(cxIcon), LOWORD(cyIcon), flags);

			if (HIWORD(cxIcon))
			{
				cxIcon = HIWORD(cxIcon);
				cyIcon = HIWORD(cyIcon);
				goto tryAgain;
			}

			nIconIndex++;
		}
    }
    _except (EXCEPTION_EXECUTE_HANDLER)
    {
        result = 0;
    }

exit:
    if (lpFile)
        UnmapViewOfFile(lpFile);
    if (hFileMap!=INVALID_HANDLE_VALUE)
        CloseHandle(hFileMap);

    return result;
}

UINT ICO_ExtractIconFroICO(
	LPBYTE pData, 
	UINT cxDesired, 
	UINT cyDesired,
	LPBYTE peimage, 
	LONG fileSize, 
	DWORD	sig, 
	UINT flags, 
	BOOL fIconEx,
	HICON * RetPtr)
{
	UINT cx1, cx2, cy1, cy2;
	DWORD		iconCount = 0;
	
	cx1 = LOWORD(cxDesired);
	cx2 = HIWORD(cxDesired);
	cy1 = LOWORD(cyDesired);
	cy2 = HIWORD(cyDesired);
	
	if (pData == (BYTE*)-1)
	{
		INT cx[2] = { (INT)cx1, (INT)cx2 }, cy[2] = { (INT)cy1, (INT)cy2 };
		INT index;

		for(index = 0; index < (cx2 || cy2 ? 2 : 1); index++)
		{
			DWORD dataOffset = 0;
			LPBYTE imageData;
			POINT hotSpot;
#ifndef __REACTOS__
			LPICONIMAGE entry;
#endif

			dataOffset = get_best_icon_file_offset(peimage, fileSize, cx[index], cy[index], sig == 1, flags, sig == 1 ? NULL : &hotSpot);

			if (dataOffset)
			{
				HICON icon;
				WORD *cursorData = NULL;
#ifdef __REACTOS__
				BITMAPINFOHEADER bi;
				DWORD cbColorTable = 0, cbTotal;
#endif

				/* safe pointer arithmetic: dataOffset is DWORD so cast to DWORD_PTR */
				imageData = peimage + (DWORD_PTR)dataOffset;
#ifdef __REACTOS__
				/* Calculate the size of color table */
				ZeroMemory(&bi, sizeof(bi));
				CopyMemory(&bi, imageData, sizeof(BITMAPCOREHEADER));
				if (bi.biBitCount <= 8)
				{
					if (bi.biSize >= sizeof(BITMAPINFOHEADER))
					{
						CopyMemory(&bi, imageData, sizeof(BITMAPINFOHEADER));
						if (bi.biClrUsed)
							cbColorTable = bi.biClrUsed * sizeof(RGBQUAD);
						else
							cbColorTable = (1 << bi.biBitCount) * sizeof(RGBQUAD);
					}else if (bi.biSize == sizeof(BITMAPCOREHEADER))
					{
						cbColorTable = (1 << bi.biBitCount) * sizeof(RGBTRIPLE);
					}
				}

				/* biSizeImage is the size of the raw bitmap data.
				* https://en.wikipedia.org/wiki/BMP_file_format */
				if (bi.biSizeImage == 0)
				{
					/* Calculate image size */
#define WIDTHBYTES(width, bits) (((width) * (bits) + 31) / 32 * 4)
					bi.biSizeImage = WIDTHBYTES(bi.biWidth, bi.biBitCount) * (bi.biHeight / 2);
					bi.biSizeImage += WIDTHBYTES(bi.biWidth, 1) * (bi.biHeight / 2);
#undef WIDTHBYTES
				}

				/* Calculate total size */
				cbTotal = bi.biSize + cbColorTable + bi.biSizeImage;
#else
				entry = (LPICONIMAGE)(imageData);
#endif

#ifdef __REACTOS__
				icon = CreateIconFromResourceExHook(imageData, cbTotal, sig == 1, 0x00030000, cx[index], cy[index], flags);
				if (fIconEx && sig == 1)
					iconCount = 1;
#else
				icon = CreateIconFromResourceExHook(imageData, entry->icHeader.biSizeImage, sig == 1, 0x00030000, cx[index], cy[index], flags);
#endif

				HeapFree(GetProcessHeap(), 0, cursorData);

				if (icon)
				{
					if (RetPtr)
						RetPtr[index] = icon;
					else
						DestroyIcon(icon);

					iconCount = 1;
					break;
				}
			}
		}
	}

	return iconCount;			
}

/*************************************************************************
 *	ICO_ExtractIconExW		[internal]
 *
 * NOTES
 *  nIcons = 0: returns number of Icons in file
 *
 * returns
 *  invalid file: -1
 *  failure:0;
 *  success: number of icons in file (nIcons = 0) or nr of icons retrieved
 */
static UINT ICO_ExtractIconExW(
	LPCWSTR lpszExeFileName,
	HICON * RetPtr,
	INT nIconIndex,
	UINT nIcons,
	UINT cxDesired,
	UINT cyDesired,
	UINT *pIconId,
#ifdef __REACTOS__
    UINT flags,
    BOOL fIconEx)
#else
	UINT flags)
#endif
{
	UINT		ret = 0;
	LPBYTE		pData;
	DWORD		sig;
	HANDLE		hFile;
	LPBYTE		peimage;
	HANDLE		fmapping;
	LONG		fileSize = 0;
#ifdef __REACTOS__
    WCHAR		szExpandedExePath[MAX_PATH];
#endif
    WCHAR		szExePath[MAX_PATH];
    DWORD		dwSearchReturn;
    DWORD bytesRead;
    BYTE binType[12];	

#ifdef __REACTOS__
    TRACE("%s, %d, %d, %p, 0x%08x, %d\n", debugstr_w(lpszExeFileName), nIconIndex, nIcons, pIconId, flags, fIconEx);
#else
	TRACE("%s, %d, %d %p 0x%08x\n", debugstr_w(lpszExeFileName), nIconIndex, nIcons, pIconId, flags);
#endif

#ifdef __REACTOS__
    if (RetPtr)
        *RetPtr = NULL;

    if (ExpandEnvironmentStringsW(lpszExeFileName, szExpandedExePath, ARRAY_SIZE(szExpandedExePath)))
        lpszExeFileName = szExpandedExePath;
#endif

    dwSearchReturn = SearchPathW(NULL, lpszExeFileName, NULL, ARRAY_SIZE(szExePath), szExePath, NULL);
    if ((dwSearchReturn == 0) || (dwSearchReturn > ARRAY_SIZE(szExePath)))
    {
#ifdef __REACTOS__
        WARN("File %s not found or path too long and fIconEx is '%d'\n",
             debugstr_w(lpszExeFileName), fIconEx);
        if (fIconEx && !RetPtr && !pIconId)
            return 0;
        else
            return -1;
#else
        WARN("File %s not found or path too long\n", debugstr_w(lpszExeFileName));
        return -1;
#endif
    }

	hFile = CreateFileW(szExePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE) return ret;

	/* Get file size safely into ULARGE_INTEGER */
	fileSize = (LONG)GetFileSize(hFile, NULL);
	
#ifdef __REACTOS__
    if (!(fileSize))
    {
        /* Cannot map empty file */
        CloseHandle(hFile);
        return 0; /* No icons */
    }
#endif

	/* Map the file */
	fmapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_COMMIT, 0, 0, NULL);

	if (!fmapping)
	{
          WARN("CreateFileMapping error %ld\n", GetLastError() );
	  return 0xFFFFFFFF;
	}

	if (!(peimage = MapViewOfFile(fmapping, FILE_MAP_READ, 0, 0, 0)))
	{
          WARN("MapViewOfFile error %ld\n", GetLastError() );
	  CloseHandle(fmapping);
	  return 0xFFFFFFFF;
	}
	CloseHandle(fmapping);

	if (pIconId) /* Invalidate first icon identifier */
		*pIconId = (UINT)-1;	

	sig = USER32_GetBinaryType(peimage, fileSize, &pData);
	
    if (ReadFile(hFile, binType, sizeof(binType), &bytesRead, NULL) &&
        bytesRead == sizeof(binType))
    {
        if (binType[0]=='R' && binType[1]=='I' && binType[2]=='F' && binType[3]=='F' &&
            binType[8]=='A' && binType[9]=='C' && binType[10]=='O' && binType[11]=='N')
        {
            return PrivateExtractIconsW(lpszExeFileName, nIconIndex, cxDesired, cyDesired, RetPtr, pIconId, nIcons, flags);
        }
    }

	switch(sig){
		case IMAGE_OS2_SIGNATURE:
			ret = PrivateExtractIconsW(lpszExeFileName, nIconIndex, cxDesired, cyDesired, RetPtr, pIconId, nIcons, flags);
			break;
		case IMAGE_ICO_SIGNATURE:
			ret = ICO_ExtractIconFroICO(pData, cxDesired, cyDesired, peimage, fileSize, sig, flags, fIconEx, RetPtr);
			break;
		case IMAGE_CUR_SIGNATURE:
			ret = PrivateExtractIconsW(lpszExeFileName, nIconIndex, cxDesired, cyDesired, RetPtr, pIconId, nIcons, flags);
		case IMAGE_NT_SIGNATURE:	
			ret = ICO_ExtractIconFromExeDll(peimage, fileSize, nIconIndex, cxDesired, cyDesired, RetPtr, pIconId, nIcons, flags);	  
			break;
		default:
			return PrivateExtractIconsW(lpszExeFileName, nIconIndex, cxDesired, cyDesired, RetPtr, pIconId, nIcons, flags); 
	}
	
	CloseHandle(hFile);

end:
	UnmapViewOfFile(peimage);	/* success */
	return ret;
}

/***********************************************************************
 *           PrivateExtractIconsW			[USER32.@]
 *
 * NOTES
 *  If HIWORD(sizeX) && HIWORD(sizeY) 2 * ((nIcons + 1) MOD 2) icons are
 *  returned, with the LOWORD size icon first and the HIWORD size icon
 *  second.
 *  Also the Windows equivalent does extract icons in a strange way if
 *  nIndex is negative. Our implementation treats a negative nIndex as
 *  looking for that resource identifier for the first icon to retrieve.
 *
 * FIXME:
 *  should also support 16 bit EXE + DLLs, cursor and animated cursor as
 *  well as bitmap files.
 */

UINT WINAPI PrivateExtractIconsWHook (
	LPCWSTR lpwstrFile,
	int nIndex,
	int sizeX,
	int sizeY,
	HICON * phicon, /* [out] pointer to array of nIcons HICON handles */
	UINT* pIconId,  /* [out] pointer to array of nIcons icon identifiers or NULL */
	UINT nIcons,    /* [in] number of icons to retrieve */
	UINT flags )    /* [in] LR_* flags used by LoadImage */
{	
	TRACE("%s %d %dx%d %p %p %d 0x%08x\n",
	      debugstr_w(lpwstrFile), nIndex, sizeX, sizeY, phicon, pIconId, nIcons, flags); 
    
    if(IsNativePNGConversor){
         return PrivateExtractIconsW(lpwstrFile, nIndex, sizeX, sizeY, phicon, pIconId, nIcons, flags);
    }

	if ((nIcons & 1) && HIWORD(sizeX) && HIWORD(sizeY))
	{
	  WARN("Uneven number %d of icons requested for small and large icons!\n", nIcons);
	}
	
#ifdef __REACTOS__
    return ICO_ExtractIconExW(lpwstrFile, phicon, nIndex, nIcons, sizeX, sizeY,
                              pIconId, flags, TRUE);
#else
	return ICO_ExtractIconExW(lpwstrFile, phicon, nIndex, nIcons, sizeX, sizeY, pIconId, flags);
#endif
}

/***********************************************************************
 *           PrivateExtractIconsA			[USER32.@]
 */

UINT WINAPI PrivateExtractIconsAHook (
	LPCSTR lpstrFile,
	int nIndex,
	int sizeX,
	int sizeY,
	HICON * RetPtr, /* [out] pointer to array of nIcons HICON handles */
	UINT* pIconId,  /* [out] pointer to array of nIcons icon identifiers or NULL */
	UINT nIcons,    /* [in] number of icons to retrieve */
	UINT flags )    /* [in] LR_* flags used by LoadImage */
{
    UINT ret;
    INT len = MultiByteToWideChar(CP_ACP, 0, lpstrFile, -1, NULL, 0);
    LPWSTR lpwstrFile = HeapAlloc(GetProcessHeap(), 0, len * sizeof(WCHAR));
	
	if(IsNativePNGConversor){
		return PrivateExtractIconsA(lpstrFile, nIndex, sizeX, sizeY, RetPtr, pIconId, nIcons, flags);
	}
	
#ifdef __REACTOS__
    if (lpwstrFile == NULL)
        return 0;
#endif

    MultiByteToWideChar(CP_ACP, 0, lpstrFile, -1, lpwstrFile, len);
    ret = PrivateExtractIconsWHook(lpwstrFile, nIndex, sizeX, sizeY, RetPtr, pIconId, nIcons, flags);

    HeapFree(GetProcessHeap(), 0, lpwstrFile);
    return ret;
}

/***********************************************************************
 *           PrivateExtractIconExW			[USER32.@]
 * NOTES
 *  if nIndex == -1 it returns the number of icons in any case !!!
 */
 UINT WINAPI  PrivateExtractIconExWHook(
    LPCWSTR szFileName,
    int     nIconIndex,
    HICON   *phiconLarge,
    HICON   *phiconSmall,
    UINT    nIcons)
{
    UINT result = 0;

    if ((nIconIndex == -1) || ((phiconLarge == NULL) && (phiconSmall == NULL)))
        return PrivateExtractIconsWHook(szFileName, 0, 0, 0, NULL, NULL, 0, 0);

    if (phiconLarge && phiconSmall && (nIcons == 1)) {

        HICON ahicon[2];

        ahicon[0] = NULL;
        ahicon[1] = NULL;

        result = PrivateExtractIconsWHook(szFileName,
                                      nIconIndex,
                                      MAKELONG(GetSystemMetrics(SM_CXICON),
                                               GetSystemMetrics(SM_CXSMICON)),
                                      MAKELONG(GetSystemMetrics(SM_CYICON),
                                               GetSystemMetrics(SM_CYSMICON)),
                                      ahicon,
                                      NULL,
                                      2,
                                      0);

        *phiconLarge = ahicon[0];
        *phiconSmall = ahicon[1];

    } else {

        if (phiconLarge)
            result = PrivateExtractIconsWHook(szFileName,
                                          nIconIndex,
                                          GetSystemMetrics(SM_CXICON),
                                          GetSystemMetrics(SM_CYICON),
                                          phiconLarge,
                                          NULL,
                                          nIcons,
                                          0);

        if (phiconSmall)
            result = PrivateExtractIconsWHook(szFileName,
                                          nIconIndex,
                                          GetSystemMetrics(SM_CXSMICON),
                                          GetSystemMetrics(SM_CYSMICON),
                                          phiconSmall,
                                          NULL,
                                          nIcons,
                                          0);
    }

    return result;
}

/***********************************************************************
 *           PrivateExtractIconExA			[USER32.@]
 */
UINT WINAPI PrivateExtractIconExAHook (
	LPCSTR lpstrFile,
	int nIndex,
	HICON * phIconLarge,
	HICON * phIconSmall,
	UINT nIcons )
{
	UINT ret;
	INT len = MultiByteToWideChar(CP_ACP, 0, lpstrFile, -1, NULL, 0);
	LPWSTR lpwstrFile = HeapAlloc(GetProcessHeap(), 0, len * sizeof(WCHAR));
	
	if(IsNativePNGConversor){
		return PrivateExtractIconExA(lpstrFile, nIndex, phIconLarge, phIconSmall, nIcons);
	}	
	
#ifdef __REACTOS__
    if (lpwstrFile == NULL)
        return 0;
#endif

	TRACE("%s %d %p %p %d\n", lpstrFile, nIndex, phIconLarge, phIconSmall, nIcons);

	MultiByteToWideChar(CP_ACP, 0, lpstrFile, -1, lpwstrFile, len);
	ret = PrivateExtractIconExWHook(lpwstrFile, nIndex, phIconLarge, phIconSmall, nIcons);
	HeapFree(GetProcessHeap(), 0, lpwstrFile);
	return ret;
}