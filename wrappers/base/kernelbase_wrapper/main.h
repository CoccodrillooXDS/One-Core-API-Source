/* MAIN INCLUDES **********************************************************/

#include <wine/config.h>

//#include <ntstatus.h>
#define WIN32_NO_STATUS

#include <wine/debug.h>

#include <winbase.h>

/* PSEH for SEH Support */
#include <pseh/pseh2.h>
#define NDEBUG

#include <winuser.h>
#include <cmfuncs.h>
#include <psfuncs.h>
#include <rtlfuncs.h>
#define NTOS_MODE_USER
#include <iofuncs.h>
#include <csr/csr.h>

#include <config.h>
#include <port.h>
#include <ntdllbase.h>
#include <winnls.h>
#include <unicode.h>
#include <base.h>
#include <wincon.h>
#include <strsafe.h>

#define WIN32_NO_STATUS
#include <obfuncs.h>
#include <mmfuncs.h>
#include <exfuncs.h>
#include <kefuncs.h>
#include <sefuncs.h>
#include <dbgktypes.h>
#include <umfuncs.h>

#include <winreg.h>
#include <wingdi.h>

#include "datetime.h"
#include <shlwapi.h>
#include <psapi.h>
#include <timezoneapi.h>
#include <wine/heap.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define FIND_DATA_SIZE 0x4000
#define BASESRV_SERVERDLL_INDEX 1
#define LOCALE_NAME_USER_DEFAULT    NULL
// #define CREATE_EVENT_MANUAL_RESET 1
// #define CREATE_EVENT_INITIAL_SET  2
#define SYMBOLIC_LINK_FLAG_DIRECTORY  0x1
#define REPARSE_DATA_BUFFER_HEADER_SIZE   FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer)
#define APPMODEL_ERROR_NO_PACKAGE                          15700
#define APPMODEL_ERROR_PACKAGE_RUNTIME_CORRUPT             15701
#define APPMODEL_ERROR_PACKAGE_IDENTITY_CORRUPT            15702
#define APPMODEL_ERROR_NO_APPLICATION                      15703

typedef struct _PROC_THREAD_ATTRIBUTE_LIST
*PPROC_THREAD_ATTRIBUTE_LIST, *LPPROC_THREAD_ATTRIBUTE_LIST;

#define PROC_THREAD_ATTRIBUTE_NUMBER   0x0000ffff
#define PROC_THREAD_ATTRIBUTE_THREAD   0x00010000
#define PROC_THREAD_ATTRIBUTE_INPUT    0x00020000
#define PROC_THREAD_ATTRIBUTE_ADDITIVE 0x00040000

typedef enum _PROC_THREAD_ATTRIBUTE_NUM_WIN7
{
    // ProcThreadAttributeParentProcess = 0,
    ProcThreadAttributeExtendedFlags = 1,
    // ProcThreadAttributeHandleList = 2,
    // ProcThreadAttributeGroupAffinity = 3,
    ProcThreadAttributePreferredNode = 4,
    // ProcThreadAttributeIdealProcessor = 5,
    // ProcThreadAttributeUmsThread = 6,
    // ProcThreadAttributeMitigationPolicy = 7,
    // ProcThreadAttributeSecurityCapabilities = 9,
	ProcThreadAttributeConsoleReference = 10,
    // ProcThreadAttributeProtectionLevel = 11,
    // ProcThreadAttributeJobList = 13,
    // ProcThreadAttributeChildProcessPolicy = 14,
    // ProcThreadAttributeAllApplicationPackagesPolicy = 15,
    // ProcThreadAttributeWin32kFilter = 16,
    // ProcThreadAttributeSafeOpenPromptOriginClaim = 17,
    ProcThreadAttributeDesktopAppPolicy = 18,
	ProcThreadAttributePseudoConsole =  22,
	ProcThreadAttributeMax
} PROC_THREAD_ATTRIBUTE_NUM_WIN7;

#define ProcThreadAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PROC_THREAD_ATTRIBUTE_NUMBER) | \
     ((Thread != FALSE) ? PROC_THREAD_ATTRIBUTE_THREAD : 0) | \
     ((Input != FALSE) ? PROC_THREAD_ATTRIBUTE_INPUT : 0) | \
     ((Additive != FALSE) ? PROC_THREAD_ATTRIBUTE_ADDITIVE : 0))

#define PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES (ProcThreadAttributeSecurityCapabilities | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL (ProcThreadAttributeProtectionLevel | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_JOB_LIST (ProcThreadAttributeJobList | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY (ProcThreadAttributeChildProcessPolicy | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY (ProcThreadAttributeAllApplicationPackagesPolicy | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_WIN32K_FILTER (ProcThreadAttributeWin32kFilter | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_DESKTOP_APP_POLICY (ProcThreadAttributeDesktopAppPolicy | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE (ProcThreadAttributePseudoConsole | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_FLAG_REPLACE_EXTENDEDFLAGS	1


#ifndef PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
#define PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES \
	ProcThreadAttributeValue (ProcThreadAttributeSecurityCapabilities, FALSE, TRUE, FALSE)
#endif

// #define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS \
    // ProcThreadAttributeValue (ProcThreadAttributeParentProcess, FALSE, TRUE, FALSE)
#define PROC_THREAD_ATTRIBUTE_EXTENDED_FLAGS \
    ProcThreadAttributeValue (ProcThreadAttributeExtendedFlags, FALSE, TRUE, TRUE)
// #define PROC_THREAD_ATTRIBUTE_HANDLE_LIST \
    // ProcThreadAttributeValue (ProcThreadAttributeHandleList, FALSE, TRUE, FALSE)
#define PROC_THREAD_ATTRIBUTE_GROUP_AFFINITY \
    ProcThreadAttributeValue (ProcThreadAttributeGroupAffinity, TRUE, TRUE, FALSE)
#define PROC_THREAD_ATTRIBUTE_PREFERRED_NODE \
    ProcThreadAttributeValue (ProcThreadAttributePreferredNode, FALSE, TRUE, FALSE)
// #define PROC_THREAD_ATTRIBUTE_IDEAL_PROCESSOR \
    // ProcThreadAttributeValue (ProcThreadAttributeIdealProcessor, TRUE, TRUE, FALSE)
#define PROC_THREAD_ATTRIBUTE_UMS_THREAD \
    ProcThreadAttributeValue (ProcThreadAttributeUmsThread, TRUE, TRUE, FALSE)
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY \
    ProcThreadAttributeValue (ProcThreadAttributeMitigationPolicy, FALSE, TRUE, FALSE)
#define PROC_THREAD_ATTRIBUTE_CONSOLE_REFERENCE \
    ProcThreadAttributeValue(ProcThreadAttributeConsoleReference, FALSE, TRUE, FALSE)

#ifndef PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL
#define PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL \
	ProcThreadAttributeValue (ProcThreadAttributeProtectionLevel, FALSE, TRUE, FALSE)
#endif

typedef struct _UMS_CREATE_THREAD_ATTRIBUTES {
  DWORD UmsVersion;
  PVOID UmsContext;
  PVOID UmsCompletionList;
} UMS_CREATE_THREAD_ATTRIBUTES, *PUMS_CREATE_THREAD_ATTRIBUTES;

#define MAX_RESTART_CMD_LINE 0x800
#define RESTART_CYCLICAL 0x1
#define RESTART_NOTIFY_SOLUTION 0x2
#define RESTART_NOTIFY_FAULT 0x4
#define VOLUME_NAME_DOS 0x0
#define VOLUME_NAME_GUID 0x1
#define VOLUME_NAME_NT 0x2
#define VOLUME_NAME_NONE 0x4
#define FILE_NAME_NORMALIZED 0x0
#define FILE_NAME_OPENED 0x8
#define FILE_SKIP_COMPLETION_PORT_ON_SUCCESS 0x1
#define FILE_SKIP_SET_EVENT_ON_HANDLE 0x2

#define NLS_DEFAULT_LANGID        0x0409

#define CREATE_EVENT_MANUAL_RESET   0x1
#define CREATE_EVENT_INITIAL_SET    0x2
#define CREATE_MUTEX_INITIAL_OWNER  0x1
#define CREATE_WAITABLE_TIMER_MANUAL_RESET  0x1
#define SRWLOCK_INIT    RTL_SRWLOCK_INIT
#define CONDITION_VARIABLE_INIT RTL_CONDITION_VARIABLE_INIT
#define CONDITION_VARIABLE_LOCKMODE_SHARED  RTL_CONDITION_VARIABLE_LOCKMODE_SHARED

/* flags that can be passed to LoadLibraryEx */
#define LOAD_LIBRARY_REQUIRE_SIGNED_TARGET  0x00000080

#define RESOURCE_ENUM_LN          0x0001
#define RESOURCE_ENUM_MUI         0x0002
#define RESOURCE_ENUM_MUI_SYSTEM  0x0004
#define RESOURCE_ENUM_VALIDATE    0x0008

#define LOCALE_ALL                  0x00
#define LOCALE_WINDOWS              0x01
#define LOCALE_SUPPLEMENTAL         0x02
#define LOCALE_ALTERNATE_SORTS      0x04
#define LOCALE_REPLACEMENT          0x08
#define LOCALE_NEUTRALDATA          0x10
#define LOCALE_SPECIFICDATA         0x20
#define LOCALE_SPARENT 0x0000006d

#ifndef FileIdInformation
#define FileIdInformation (enum _FILE_INFORMATION_CLASS)59
#endif

#define SYNCHRONIZATION_BARRIER_FLAGS_SPIN_ONLY		0x01
#define SYNCHRONIZATION_BARRIER_FLAGS_BLOCK_ONLY	0x02
#define SYNCHRONIZATION_BARRIER_FLAGS_NO_DELETE		0x04

#define ARGUMENT_PRESENT(x) ((x) != NULL)

#define NORM_LINGUISTIC_CASING     0x08000000
#define FIND_STARTSWITH            0x00100000
#define FIND_ENDSWITH              0x00200000
#define FIND_FROMSTART             0x00400000
#define FIND_FROMEND               0x00800000

#define EXTENDED_STARTUPINFO_PRESENT 0x00080000

//
// Do not add heap dumps for reports for the process
//
#define WER_FAULT_REPORTING_FLAG_NOHEAP 1

//
// Fault reporting UI should always be shown. This is only applicable for interactive processes
//
#define WER_FAULT_REPORTING_ALWAYS_SHOW_UI          16

#define KEY_LENGTH 1024

#define PATHCCH_MAX_CCH 0x8000

/* Wine-specific exceptions codes */

#define EXCEPTION_WINE_STUB       0x80000100  /* stub entry point called */
#define EXCEPTION_WINE_ASSERTION 0x80000101 /* assertion failed */

#if (_WIN32_WINNT < _WIN32_WINNT_VISTA)
 
#define FileIoCompletionNotificationInformation	41
#define FileIoStatusBlockRangeInformation	 42
#define FileIoPriorityHintInformation	43
#define FileSfioReserveInformation	44
#define FileSfioVolumeInformation	45
#define FileHardLinkInformation	46
#define FileProcessIdsUsingFileInformation	47
#define FileNormalizedNameInformation	48
#define FileNetworkPhysicalNameInformation	49
#define FileIdGlobalTxDirectoryInformation	50
#define FileIsRemoteDeviceInformation	51
#define FileUnusedInformation	52
#define FileNumaNodeInformation	53
#define FileStandardLinkInformation	54
#define FileRemoteProtocolInformation	55
	
#endif	

#ifdef _M_IX86
#define CONTEXT_AMD64   0x00100000
#endif

#define CONTEXT_AMD64_CONTROL   (CONTEXT_AMD64 | 0x0001)
#define CONTEXT_AMD64_INTEGER   (CONTEXT_AMD64 | 0x0002)
#define CONTEXT_AMD64_SEGMENTS  (CONTEXT_AMD64 | 0x0004)
#define CONTEXT_AMD64_FLOATING_POINT  (CONTEXT_AMD64 | 0x0008)
#define CONTEXT_AMD64_DEBUG_REGISTERS (CONTEXT_AMD64 | 0x0010)
#define CONTEXT_AMD64_XSTATE          (CONTEXT_AMD64 | 0x0040)
#define CONTEXT_AMD64_FULL (CONTEXT_AMD64_CONTROL | CONTEXT_AMD64_INTEGER | CONTEXT_AMD64_FLOATING_POINT)
#define CONTEXT_AMD64_ALL (CONTEXT_AMD64_CONTROL | CONTEXT_AMD64_INTEGER | CONTEXT_AMD64_SEGMENTS | CONTEXT_AMD64_FLOATING_POINT | CONTEXT_AMD64_DEBUG_REGISTERS)

static const BOOL is_win64 = (sizeof(void *) > sizeof(int));
volatile long TzSpecificCache;
extern ULONG BaseDllTag;
PBASE_STATIC_SERVER_DATA BaseStaticServerData;
extern BOOL bIsFileApiAnsi;
extern HMODULE kernel32_handle DECLSPEC_HIDDEN;

typedef void *HPCON;

typedef RTL_SRWLOCK SRWLOCK, *PSRWLOCK;

typedef RTL_CONDITION_VARIABLE CONDITION_VARIABLE, *PCONDITION_VARIABLE;

typedef struct _FILE_IO_COMPLETION_NOTIFICATION_INFORMATION {
    ULONG Flags;
} FILE_IO_COMPLETION_NOTIFICATION_INFORMATION, *PFILE_IO_COMPLETION_NOTIFICATION_INFORMATION;


/* TYPE DEFINITIONS **********************************************************/
typedef UINT(WINAPI * PPROCESS_START_ROUTINE)(VOID);
typedef RTL_CONDITION_VARIABLE CONDITION_VARIABLE, *PCONDITION_VARIABLE;
typedef NTSTATUS(NTAPI * PRTL_CONVERT_STRING)(IN PUNICODE_STRING UnicodeString, IN PANSI_STRING AnsiString, IN BOOLEAN AllocateMemory);
typedef DWORD (WINAPI *APPLICATION_RECOVERY_CALLBACK)(PVOID);
typedef VOID (CALLBACK *PTP_WIN32_IO_CALLBACK)(PTP_CALLBACK_INSTANCE,PVOID,PVOID,ULONG,ULONG_PTR,PTP_IO);
typedef INT (WINAPI *MessageBoxA_funcptr)(HWND,LPCSTR,LPCSTR,UINT);
typedef INT (WINAPI *MessageBoxW_funcptr)(HWND,LPCWSTR,LPCWSTR,UINT);

/* STRUCTS DEFINITIONS ******************************************************/

typedef enum AppPolicyProcessTerminationMethod
{
    AppPolicyProcessTerminationMethod_ExitProcess      = 0,
    AppPolicyProcessTerminationMethod_TerminateProcess = 1,
} AppPolicyProcessTerminationMethod;

typedef enum AppPolicyThreadInitializationType
{
    AppPolicyThreadInitializationType_None            = 0,
    AppPolicyThreadInitializationType_InitializeWinRT = 1,
} AppPolicyThreadInitializationType;

typedef enum AppPolicyShowDeveloperDiagnostic
{
    AppPolicyShowDeveloperDiagnostic_None   = 0,
    AppPolicyShowDeveloperDiagnostic_ShowUI = 1,
} AppPolicyShowDeveloperDiagnostic;

typedef enum AppPolicyWindowingModel
{
    AppPolicyWindowingModel_None           = 0,
    AppPolicyWindowingModel_Universal      = 1,
    AppPolicyWindowingModel_ClassicDesktop = 2,
    AppPolicyWindowingModel_ClassicPhone   = 3
} AppPolicyWindowingModel;

typedef enum _FIND_DATA_TYPE
{
    FindFile   = 1,
    FindStream = 2
} FIND_DATA_TYPE;

typedef enum _PIPE_ATTRIBUTE_TYPE {
  PipeAttribute = 0,
  PipeConnectionAttribute = 1,
  PipeHandleAttribute = 2
}PIPE_ATTRIBUTE_TYPE, *PPIPE_ATTRIBUTE_TYPE;

typedef union _DIR_INFORMATION
{
    PVOID DirInfo;
    PFILE_FULL_DIR_INFORMATION FullDirInfo;
    PFILE_BOTH_DIR_INFORMATION BothDirInfo;
} DIR_INFORMATION;

typedef enum _DEP_SYSTEM_POLICY_TYPE {
    AlwaysOff = 0,
    AlwaysOn = 1,
    OptIn = 2,
    OptOut = 3
} DEP_SYSTEM_POLICY_TYPE;

typedef struct _FIND_FILE_DATA
{
    HANDLE Handle;
    FINDEX_INFO_LEVELS InfoLevel;
    FINDEX_SEARCH_OPS SearchOp;

    /*
     * For handling STATUS_BUFFER_OVERFLOW errors emitted by
     * NtQueryDirectoryFile in the FildNextFile function.
     */
    BOOLEAN HasMoreData;

    /*
     * "Pointer" to the next file info structure in the buffer.
     * The type is defined by the 'InfoLevel' parameter.
     */
    DIR_INFORMATION NextDirInfo;

    BYTE Buffer[FIND_DATA_SIZE];
} FIND_FILE_DATA, *PFIND_FILE_DATA;

typedef struct _FIND_STREAM_DATA
{
    STREAM_INFO_LEVELS InfoLevel;
    PFILE_STREAM_INFORMATION FileStreamInfo;
    PFILE_STREAM_INFORMATION CurrentInfo;
} FIND_STREAM_DATA, *PFIND_STREAM_DATA;

typedef struct _FIND_DATA_HANDLE
{
    FIND_DATA_TYPE Type;
    RTL_CRITICAL_SECTION Lock;

    /*
     * Pointer to the following finding data, located at
     * (this + 1). The type is defined by the 'Type' parameter.
     */
    union
    {
        PFIND_FILE_DATA FindFileData;
        PFIND_STREAM_DATA FindStreamData;
    } u;

} FIND_DATA_HANDLE, *PFIND_DATA_HANDLE;

typedef struct _REASON_CONTEXT {
  ULONG Version;
  DWORD Flags;
  union {
    struct {
      HMODULE LocalizedReasonModule;
      ULONG   LocalizedReasonId;
      ULONG   ReasonStringCount;
      LPWSTR  *ReasonStrings;
    } Detailed;
    LPWSTR SimpleReasonString;
  } Reason;
} REASON_CONTEXT, *PREASON_CONTEXT;

typedef struct _PROC_THREAD_ATTRIBUTE
{
	DWORD_PTR Attribute;
	SIZE_T cbSize;
	PVOID lpValue;
} PROC_THREAD_ATTRIBUTE;

typedef struct _PROC_THREAD_ATTRIBUTE_LIST
{
	DWORD AttributeFlags;
	DWORD MaxCount;
	DWORD Count;
	DWORD Pad4B;
	PROC_THREAD_ATTRIBUTE* ExtendedEntry;
	PROC_THREAD_ATTRIBUTE AttributeList[ANYSIZE_ARRAY];
} PROC_THREAD_ATTRIBUTE_LIST;

typedef enum _WER_REGISTER_FILE_TYPE
{
     WerRegFileTypeUserDocument = 1,
     WerRegFileTypeOther = 2,
     WerRegFileTypeMax
} WER_REGISTER_FILE_TYPE;

typedef struct _LOCALE_LCID{
	LPCWSTR localeName;
	LCID lcid;
}LOCALE_LCID;

typedef enum _POWER_REQUEST_TYPE { 
  PowerRequestDisplayRequired,
  PowerRequestSystemRequired,
  PowerRequestAwayModeRequired,
  PowerRequestExecutionRequired
} POWER_REQUEST_TYPE, *PPOWER_REQUEST_TYPE;

//
//  The variable structure contains the offsets to the various pieces of
//  locale information that is of variable length.  It is in the order
//  in which it is given in the file.
//
typedef struct locale_var_s
{
    WORD      SEngLanguage;            // English language name
    WORD      SAbbrevLang;             // abbreviated language name
    WORD      SAbbrevLangISO;          // ISO abbreviated language name
    WORD      SNativeLang;             // native language name
    WORD      SEngCountry;             // English country name
    WORD      SAbbrevCtry;             // abbreviated country name
    WORD      SAbbrevCtryISO;          // ISO abbreviated country name
    WORD      SNativeCtry;             // native country name
    WORD      SList;                   // list separator
    WORD      SDecimal;                // decimal separator
    WORD      SThousand;               // thousands separator
    WORD      SGrouping;               // grouping of digits
    WORD      SNativeDigits;           // native digits 0-9
    WORD      SCurrency;               // local monetary symbol
    WORD      SIntlSymbol;             // international monetary symbol
    WORD      SEngCurrName;            // English currency name
    WORD      SNativeCurrName;         // native currency name
    WORD      SMonDecSep;              // monetary decimal separator
    WORD      SMonThousSep;            // monetary thousands separator
    WORD      SMonGrouping;            // monetary grouping of digits
    WORD      SPositiveSign;           // positive sign
    WORD      SNegativeSign;           // negative sign
    WORD      STimeFormat;             // time format
    WORD      STime;                   // time separator
    WORD      S1159;                   // AM designator
    WORD      S2359;                   // PM designator
    WORD      SShortDate;              // short date format
    WORD      SDate;                   // date separator
    WORD      SYearMonth;              // year month format
    WORD      SLongDate;               // long date format
    WORD      IOptionalCal;            // additional calendar type(s)
    WORD      SDayName1;               // day name 1
    WORD      SDayName2;               // day name 2
    WORD      SDayName3;               // day name 3
    WORD      SDayName4;               // day name 4
    WORD      SDayName5;               // day name 5
    WORD      SDayName6;               // day name 6
    WORD      SDayName7;               // day name 7
    WORD      SAbbrevDayName1;         // abbreviated day name 1
    WORD      SAbbrevDayName2;         // abbreviated day name 2
    WORD      SAbbrevDayName3;         // abbreviated day name 3
    WORD      SAbbrevDayName4;         // abbreviated day name 4
    WORD      SAbbrevDayName5;         // abbreviated day name 5
    WORD      SAbbrevDayName6;         // abbreviated day name 6
    WORD      SAbbrevDayName7;         // abbreviated day name 7
    WORD      SMonthName1;             // month name 1
    WORD      SMonthName2;             // month name 2
    WORD      SMonthName3;             // month name 3
    WORD      SMonthName4;             // month name 4
    WORD      SMonthName5;             // month name 5
    WORD      SMonthName6;             // month name 6
    WORD      SMonthName7;             // month name 7
    WORD      SMonthName8;             // month name 8
    WORD      SMonthName9;             // month name 9
    WORD      SMonthName10;            // month name 10
    WORD      SMonthName11;            // month name 11
    WORD      SMonthName12;            // month name 12
    WORD      SMonthName13;            // month name 13 (if exists)
    WORD      SAbbrevMonthName1;       // abbreviated month name 1
    WORD      SAbbrevMonthName2;       // abbreviated month name 2
    WORD      SAbbrevMonthName3;       // abbreviated month name 3
    WORD      SAbbrevMonthName4;       // abbreviated month name 4
    WORD      SAbbrevMonthName5;       // abbreviated month name 5
    WORD      SAbbrevMonthName6;       // abbreviated month name 6
    WORD      SAbbrevMonthName7;       // abbreviated month name 7
    WORD      SAbbrevMonthName8;       // abbreviated month name 8
    WORD      SAbbrevMonthName9;       // abbreviated month name 9
    WORD      SAbbrevMonthName10;      // abbreviated month name 10
    WORD      SAbbrevMonthName11;      // abbreviated month name 11
    WORD      SAbbrevMonthName12;      // abbreviated month name 12
    WORD      SAbbrevMonthName13;      // abbreviated month name 13 (if exists)
    WORD      SEndOfLocale;            // end of locale information
} LOCALE_VAR, *PLOCALE_VAR;

//
//  Sortkey Structure.
//
typedef struct sortkey_s {

    union {
        struct sm_aw_s {
            BYTE   Alpha;              // alphanumeric weight
            BYTE   Script;             // script member
        } SM_AW;

        WORD  Unicode;                 // unicode weight

    } UW;

    BYTE      Diacritic;               // diacritic weight
    BYTE      Case;                    // case weight (with COMP)

} SORTKEY, *PSORTKEY;

#define MAX_FONTSIGNATURE         16   // length of font signature string

//
//  The fixed structure contains the locale information that is of
//  fixed length and in the order in which it is given in the file.
//
typedef struct locale_fixed_s
{
    WORD      DefaultACP;              // default ACP - integer format
    WORD      szILanguage[5];          // language id
    WORD      szICountry[6];           // country id
    WORD      szIGeoID[8];            // geographical location identifier
    WORD      szIDefaultLang[5];       // default language ID
    WORD      szIDefaultCtry[6];       // default country ID
    WORD      szIDefaultACP[6];        // default ansi code page ID
    WORD      szIDefaultOCP[6];        // default oem code page ID
    WORD      szIDefaultMACCP[6];      // default mac code page ID
    WORD      szIDefaultEBCDICCP[6];   // default ebcdic code page ID
    WORD      szIMeasure[2];           // system of measurement
    WORD      szIPaperSize[2];         // default paper size
    WORD      szIDigits[3];            // number of fractional digits
    WORD      szILZero[2];             // leading zeros for decimal
    WORD      szINegNumber[2];         // negative number format
    WORD      szIDigitSubstitution[2]; // digit substitution
    WORD      szICurrDigits[3];        // # local monetary fractional digits
    WORD      szIIntlCurrDigits[3];    // # intl monetary fractional digits
    WORD      szICurrency[2];          // positive currency format
    WORD      szINegCurr[3];           // negative currency format
    WORD      szIPosSignPosn[2];       // format of positive sign
    WORD      szIPosSymPrecedes[2];    // if mon symbol precedes positive
    WORD      szIPosSepBySpace[2];     // if mon symbol separated by space
    WORD      szINegSignPosn[2];       // format of negative sign
    WORD      szINegSymPrecedes[2];    // if mon symbol precedes negative
    WORD      szINegSepBySpace[2];     // if mon symbol separated by space
    WORD      szITime[2];              // time format
    WORD      szITLZero[2];            // leading zeros for time field
    WORD      szITimeMarkPosn[2];      // time marker position
    WORD      szIDate[2];              // short date order
    WORD      szICentury[2];           // century format (short date)
    WORD      szIDayLZero[2];          // leading zeros for day field (short date)
    WORD      szIMonLZero[2];          // leading zeros for month field (short date)
    WORD      szILDate[2];             // long date order
    WORD      szICalendarType[3];      // type of calendar
    WORD      szIFirstDayOfWk[2];      // first day of week
    WORD      szIFirstWkOfYr[2];       // first week of year
    WORD      szFontSignature[MAX_FONTSIGNATURE];
} LOCALE_FIXED, *PLOCALE_FIXED;

//
//  Constant Types
//
typedef  LPWORD        P844_TABLE;     // ptr to 8:4:4 table

typedef  LPWORD        PMB_TABLE;      // ptr to MB translation table
typedef  PMB_TABLE     PGLYPH_TABLE;   // ptr to GLYPH translation table
typedef  LPWORD        PDBCS_RANGE;    // ptr to DBCS range
typedef  LPWORD        PDBCS_OFFSETS;  // ptr to DBCS offset section
typedef  LPWORD        PDBCS_TABLE;    // ptr to DBCS translation table
typedef  PVOID         PWC_TABLE;      // ptr to WC translation table
typedef  P844_TABLE    PCTYPE;         // ptr to Character Type table
typedef  P844_TABLE    PCASE;          // ptr to Lower or Upper Case table
typedef  P844_TABLE    PADIGIT;        // ptr to Ascii Digits table
typedef  P844_TABLE    PCZONE;         // ptr to Fold Compat. Zone table
typedef  P844_TABLE    PKANA;          // ptr to Hiragana/Katakana table
typedef  P844_TABLE    PHALFWIDTH;     // ptr to Half Width table
typedef  P844_TABLE    PFULLWIDTH;     // ptr to Full Width table
typedef  P844_TABLE    PCHINESE;       // ptr to Traditional/Simplified Chinese table
typedef  P844_TABLE    PPRECOMP;       // ptr to PreComposed table
typedef  LPWORD        PCOMP_GRID;     // ptr to Composite table 2D grid
typedef  LPWORD        PLOC_INFO;      // ptr to locale information
typedef  LPWORD        PCAL_INFO;      // ptr to calendar information

typedef  DWORD         REVERSE_DW;     // reverse diacritic table
typedef  REVERSE_DW   *PREVERSE_DW;    // ptr to reverse diacritic table
typedef  DWORD         DBL_COMPRESS;   // double compression table
typedef  DBL_COMPRESS *PDBL_COMPRESS;  // ptr to double compression table
typedef  LPWORD        PCOMPRESS;      // ptr to compression table (2 or 3)

typedef  DWORD         NLSDEFINED;     // NLS defined codepoint table
typedef  NLSDEFINED   *PNLSDEFINED;    // ptr to NLS defined code point table

//
//  Compression Header Structure.
//  This is the header for the compression tables.
//
typedef struct compress_hdr_s {
    DWORD     Locale;                  // locale id
    DWORD     Offset;                  // offset (in words)
    WORD      Num2;                    // Number of 2 compressions
    WORD      Num3;                    // Number of 3 compressions
} COMPRESS_HDR, *PCOMPRESS_HDR;


//
//  Compression 2 Structure.
//  This is for a 2 code point compression - 2 code points
//  compress to ONE weight.
//
typedef struct compress_2_s {
    WCHAR     UCP1;                    // Unicode code point 1
    WCHAR     UCP2;                    // Unicode code point 2
    SORTKEY   Weights;                 // sortkey weights
} COMPRESS_2, *PCOMPRESS_2;

//
//  Compression 3 Structure.
//  This is for a 3 code point compression - 3 code points
//  compress to ONE weight.
//
typedef struct compress_3_s {
    WCHAR     UCP1;                    // Unicode code point 1
    WCHAR     UCP2;                    // Unicode code point 2
    WCHAR     UCP3;                    // Unicode code point 3
    WCHAR     Reserved;                // dword alignment
    SORTKEY   Weights;                 // sortkey weights
} COMPRESS_3, *PCOMPRESS_3;

//
//  Locale Hash Table Structure.
//
typedef struct loc_hash_s {
    LCID           Locale;             // locale ID
    PLOCALE_VAR    pLocaleHdr;         // ptr to locale header info
    PLOCALE_FIXED  pLocaleFixed;       // ptr to locale fixed size info
    PCASE          pUpperCase;         // ptr to Upper Case table
    PCASE          pLowerCase;         // ptr to Lower Case table
    PCASE          pUpperLinguist;     // ptr to Upper Case Linguistic table
    PCASE          pLowerLinguist;     // ptr to Lower Case Linguistic table
    PSORTKEY       pSortkey;           // ptr to sortkey table
    BOOL           IfReverseDW;        // if DW should go from right to left
    BOOL           IfCompression;      // if compression code points exist
    BOOL           IfDblCompression;   // if double compression exists
    BOOL           IfIdeographFailure; // if ideograph table failed to load
    PCOMPRESS_HDR  pCompHdr;           // ptr to compression header
    PCOMPRESS_2    pCompress2;         // ptr to 2 compression table
    PCOMPRESS_3    pCompress3;         // ptr to 3 compression table
    struct loc_hash_s *pNext;          // ptr to next locale hash node
} LOC_HASH, *PLOC_HASH;

typedef DWORD (*LPFN_CP_PROC)(DWORD, DWORD, LPSTR, int, LPWSTR, int, LPCPINFO);


//
//  CP Information Table Structure (as it is in the data file).
//
typedef struct cp_table_s {
    WORD      CodePage;                // code page number
    WORD      MaxCharSize;             // max length (bytes) of a char
    WORD      wDefaultChar;            // default character (MB)
    WORD      wUniDefaultChar;         // default character (Unicode)
    WORD      wTransDefaultChar;       // translation of wDefaultChar (Unicode)
    WORD      wTransUniDefaultChar;    // translation of wUniDefaultChar (MB)
    BYTE      LeadByte[MAX_LEADBYTES]; // lead byte ranges
} CP_TABLE, *PCP_TABLE;

//
//  Code Page Hash Table Structure.
//
typedef struct cp_hash_s {
    UINT           CodePage;           // codepage ID
    LPFN_CP_PROC   pfnCPProc;          // ptr to code page function proc
    PCP_TABLE      pCPInfo;            // ptr to CPINFO table
    PMB_TABLE      pMBTbl;             // ptr to MB translation table
    PGLYPH_TABLE   pGlyphTbl;          // ptr to GLYPH translation table
    PDBCS_RANGE    pDBCSRanges;        // ptr to DBCS ranges
    PDBCS_OFFSETS  pDBCSOffsets;       // ptr to DBCS offsets
    PWC_TABLE      pWC;                // ptr to WC table
    struct cp_hash_s *pNext;           // ptr to next CP hash node
} CP_HASH, *PCP_HASH;

//
//  Language Exception Header Structure.
//
typedef struct l_except_hdr_s {
    DWORD     Locale;                  // locale id
    DWORD     Offset;                  // offset to exception nodes (words)
    DWORD     NumUpEntries;            // number of upper case entries
    DWORD     NumLoEntries;            // number of lower case entries
} L_EXCEPT_HDR, *PL_EXCEPT_HDR;

//
//  Language Exception Structure.
//
typedef struct l_except_s
{
    WORD      UCP;                     // unicode code point
    WORD      AddAmount;               // amount to add to code point
} L_EXCEPT, *PL_EXCEPT;

//
//  Hash Table Pointers.
//
typedef  PCP_HASH  *PCP_HASH_TBL;      // ptr to a code page hash table
typedef  PLOC_HASH *PLOC_HASH_TBL;     // ptr to a locale hash table

//
//  CType Table Structure (Mapping table structure).
//
typedef struct ct_values_s {
    WORD      CType1;                  // ctype 1 value
    WORD      CType2;                  // ctype 2 value
    WORD      CType3;                  // ctype 3 value
} CT_VALUES, *PCT_VALUES;

//
//  Composite Information Structure.
//
typedef struct comp_info_s {
    BYTE           NumBase;            // number base chars in grid
    BYTE           NumNonSp;           // number non space chars in grid
    P844_TABLE     pBase;              // ptr to base char table
    P844_TABLE     pNonSp;             // ptr to nonspace char table
    PCOMP_GRID     pGrid;              // ptr to 2D grid
} COMP_INFO, *PCOMP_INFO;

//
//  Ideograph Lcid Exception Structure.
//
typedef struct ideograph_lcid_s {
    DWORD     Locale;                  // locale id
    WORD      pFileName[14];           // ptr to file name
} IDEOGRAPH_LCID, *PIDEOGRAPH_LCID;

//
//  Expansion Structure.
//
typedef struct expand_s {
    WCHAR     UCP1;                    // Unicode code point 1
    WCHAR     UCP2;                    // Unicode code point 2
} EXPAND, *PEXPAND;

//
//  Exception Header Structure.
//  This is the header for the exception tables.
//
typedef struct except_hdr_s {
    DWORD     Locale;                  // locale id
    DWORD     Offset;                  // offset to exception nodes (words)
    DWORD     NumEntries;              // number of entries for locale id
} EXCEPT_HDR, *PEXCEPT_HDR;

//
//  Exception Structure.
//
//  NOTE: May also be used for Ideograph Exceptions (4 column tables).
//
typedef struct except_s
{
    WORD      UCP;                     // unicode code point
    WORD      Unicode;                 // unicode weight
    BYTE      Diacritic;               // diacritic weight
    BYTE      Case;                    // case weight
} EXCEPT, *PEXCEPT;

//
//  Multiple Weight Structure.
//
typedef struct multiwt_s {
    BYTE      FirstSM;                 // value of first script member
    BYTE      NumSM;                   // number of script members in range
} MULTI_WT, *PMULTI_WT;

//
//  Jamo Sequence Sorting Info.
//
typedef struct {
    BYTE m_bOld;                  // sequence occurs only in old Hangul flag
    CHAR m_chLeadingIndex;        // indices used to locate prior modern Hangul syllable
    CHAR m_chVowelIndex;
    CHAR m_chTrailingIndex;
    BYTE m_ExtraWeight;           // extra weights that distinguish this from
                                  //   other old Hangul syllables, depending
                                  //   on the jamo, this can be a weight for
                                  //   leading jamo, vowel jamo, or trailing jamo.
} JAMO_SORT_INFO, *PJAMO_SORT_INFO;

//
//  Jamo Combination Table Entry.
//
//  NOTE: Make sure this structure is WORD aligned.  Otherwise, code will
//        fail in GetDefaultSortTable().
//
typedef struct {
    WCHAR m_wcCodePoint;          // Code point value that enters this state
    JAMO_SORT_INFO m_SortInfo;    // Sequence sorting info
    BYTE m_bTransitionCount;      // # of possible transitions from this state
} JAMO_COMPOSE_STATE, *PJAMO_COMPOSE_STATE;

//
//  Jamo Index Table Entry.
//
typedef struct {
    JAMO_SORT_INFO SortInfo;      // sequence sorting info
    BYTE Index;                   // index into the composition array
    BYTE TransitionCount;         // # of possible transitions from this state
    BYTE Reserved;                // word alignment
} JAMO_TABLE, *PJAMO_TABLE;

//
//  Geo Information structure. This structure holds information about
//  a geographical location on earth.
//
typedef struct tagGeoInfo {
    GEOID       GeoId;
    WCHAR       szLatitude[12];
    WCHAR       szLongitude[12];
    GEOCLASS    GeoClass;
    GEOID       ParentGeoId;
    WCHAR       szISO3166Abbrev2[4];
    WCHAR       szISO3166Abbrev3[4];
    WORD        wISO3166;
    WORD        Reserved;              // dword alignment
} GEOINFO, *PGEOINFO;

//
//  GEOID/LCID structure. This structure is used to navigate through
//  the table that maps corresponding Language ID and Geo ID.
//
typedef struct tagGEOIDLCID {
    LCID    lcid;
    GEOID   GeoId;
    LANGID  LangId;
    WORD    Reserved;                  // dword alignment
} GEOLCID, *PGEOLCID;

//
//  Sorting Version Info Structure.
//
typedef  struct _sortverinfo{
    LCID  Locale;       // Locale identifier
    DWORD Version;      // Sort version for this locale
}SORTVERINFO, *PSORTVERINFO;

//
//  Defined Code Point Version Info Structure.
//
typedef  struct _definedverinfo{
    DWORD       Version;          // Version of the Code Point table
    DWORD       dwOffset;         // Offset to the Defined Code Point table.
}DEFVERINFO, *PDEFVERINFO;

//
//  Table Pointers Structure.  This structure contains pointers to
//  the various tables needed for the NLS APIs.  There should be only
//  ONE of these for each process, and the information should be
//  global to the process.
//
#define NUM_SM     256                  // total number of script members
#define NUM_CAL    64                   // total number calendars allowed

typedef struct tbl_ptrs_s {
    PCP_HASH_TBL    pCPHashTbl;         // ptr to Code Page hash table
    PLOC_HASH_TBL   pLocHashTbl;        // ptr to Locale hash table
    PLOC_INFO       pLocaleInfo;        // ptr to locale table (all locales)
    DWORD           NumCalendars;       // number of calendars
    PCAL_INFO       pCalendarInfo;      // ptr to beginning of calendar info
    PCAL_INFO       pCalTbl[NUM_CAL];   // ptr to calendar table array
    P844_TABLE      pDefaultLanguage;   // ptr to default language table
    P844_TABLE      pLinguistLanguage;  // ptr to default linguistic lang table
    LARGE_INTEGER   LinguistLangSize;   // size of linguistic lang table
    int             NumLangException;   // number of language exceptions
    PL_EXCEPT_HDR   pLangExceptHdr;     // ptr to lang exception table header
    PL_EXCEPT       pLangException;     // ptr to lang exception tables
    PCT_VALUES      pCTypeMap;          // ptr to Ctype Mapping table
    PCTYPE          pCType844;          // ptr to Ctype 8:4:4 table
    PADIGIT         pADigit;            // ptr to Ascii Digits table
    PCZONE          pCZone;             // ptr to Compatibility Zone table
    PKANA           pHiragana;          // ptr to Hiragana table
    PKANA           pKatakana;          // ptr to Katakana table
    PHALFWIDTH      pHalfWidth;         // ptr to Half Width table
    PFULLWIDTH      pFullWidth;         // ptr to Full Width table
    PCHINESE        pTraditional;       // ptr to Traditional Chinese table
    PCHINESE        pSimplified;        // ptr to Simplified Chinese table
    PPRECOMP        pPreComposed;       // ptr to PreComposed Table
    PCOMP_INFO      pComposite;         // ptr to Composite info structure
    DWORD           NumReverseDW;       // number of REVERSE DIACRITICS
    DWORD           NumDblCompression;  // number of DOUBLE COMPRESSION locales
    DWORD           NumIdeographLcid;   // number of IDEOGRAPH LCIDs
    DWORD           NumExpansion;       // number of EXPANSIONS
    DWORD           NumCompression;     // number of COMPRESSION locales
    DWORD           NumException;       // number of EXCEPTION locales
    DWORD           NumMultiWeight;     // number of MULTIPLE WEIGHTS
    int             NumJamoIndex;       // number of entires for Jamo Index Table
    int             NumJamoComposition; // number of entires for Jamo Composition Table
    PSORTKEY        pDefaultSortkey;    // ptr to default sortkey table
    LARGE_INTEGER   DefaultSortkeySize; // size of default sortkey section
    PREVERSE_DW     pReverseDW;         // ptr to reverse diacritic table
    PDBL_COMPRESS   pDblCompression;    // ptr to double compression table
    PIDEOGRAPH_LCID pIdeographLcid;     // ptr to ideograph lcid table
    PEXPAND         pExpansion;         // ptr to expansion table
    PCOMPRESS_HDR   pCompressHdr;       // ptr to compression table header
    PCOMPRESS       pCompression;       // ptr to compression tables
    PEXCEPT_HDR     pExceptHdr;         // ptr to exception table header
    PEXCEPT         pException;         // ptr to exception tables
    PMULTI_WT       pMultiWeight;       // ptr to multiple weights table
    BYTE            SMWeight[NUM_SM];   // script member weights
    PJAMO_TABLE     pJamoIndex;         // ptr ot Jamo Index table
    PJAMO_COMPOSE_STATE pJamoComposition;  // ptr to Jamo Composition state machine table
    long            nGeoInfo;           // number of GEOINFO entries
    PGEOINFO        pGeoInfo;           // ptr to gegraphical info location table
    long            nGeoLCID;           // number of GEOID/LCID entries
    PGEOLCID        pGeoLCID;           // ptr to GEOID/LCID mapping table
    DWORD           NumSortVersion;     // number of sorting version
    PSORTVERINFO    pSortVersion;       // ptr sorting version info
    DWORD           NumDefinedVersion;  // number of defined code point version 
    PDEFVERINFO     pDefinedVersion;    // ptr defined code point version
    LPWORD          pSortingTableFileBase;  // The base address of sorting table file
} TBL_PTRS, *PTBL_PTRS;

typedef struct _BASEP_ACTCTX_BLOCK
{
     ULONG Flags;
     PVOID ActivationContext;
     PVOID CompletionContext;
     LPOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine;
} BASEP_ACTCTX_BLOCK, *PBASEP_ACTCTX_BLOCK;

typedef struct _BASE_ACTIVATION_CONTEXT_ACTIVATION_BLOCK {
    DWORD Flags;
    PVOID CallbackFunction;
    PVOID CallbackContext;
    PACTIVATION_CONTEXT ActivationContext;
} BASE_ACTIVATION_CONTEXT_ACTIVATION_BLOCK, *PBASE_ACTIVATION_CONTEXT_ACTIVATION_BLOCK;

extern LCID             gSystemLocale;      // system locale value
extern RTL_CRITICAL_SECTION gcsTblPtrs;     // critical section for tbl ptrs
extern PLOC_HASH        gpInvLocHashN;      // ptr to invariant loc hash node
extern PLOC_HASH        gpSysLocHashN;      // ptr to system loc hash node
extern PTBL_PTRS  pTblPtrs;   // ptr to structure of table ptrs

#define IS_INVALID_LOCALE(Locale)      ( Locale & ~NLS_VALID_LOCALE_MASK )

#define NLS_SECTION_LOCALE         L"\\NLS\\NlsSectionLocale"

//
typedef struct loc_cal_hdr_s
{
    DWORD     NumLocales;              // number of locales
    DWORD     NumCalendars;            // number of calendars
    DWORD     CalOffset;               // offset to calendar info (words)
} LOC_CAL_HDR, *PLOC_CAL_HDR;


typedef struct locale_hdr_s {
    DWORD     Locale;                  // locale ID
    DWORD     Offset;                  // offset to locale information
} LOCALE_HDR, *PLOCALE_HDR;

#define LOCALE_HDR_OFFSET    (sizeof(LOC_CAL_HDR) / sizeof(WORD))

#define RtlProcessHeap() (NtCurrentPeb()->ProcessHeap)

//
//  String Constants.
//
#define MAX_PATH_LEN              512  // max length of path name

//
//  Size of stack buffer for PKEY_VALUE_FULL_INFORMATION pointer.
//
#define MAX_KEY_VALUE_FULLINFO                                             \
    ( FIELD_OFFSET( KEY_VALUE_FULL_INFORMATION, Name ) + MAX_PATH_LEN )
	
ULONG
OpenRegKey(
    PHANDLE phKeyHandle,
    LPWSTR pBaseName,
    LPWSTR pKey,
    ULONG fAccess);	
	
//
//  Paths to registry keys.
//
#define NLS_HKLM_SYSTEM    L"\\Registry\\Machine\\System\\CurrentControlSet\\Control"
#define NLS_HKLM_SOFTWARE  L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion"


//
//  Names of Registry Key Entries.
//
#define NLS_CODEPAGE_KEY           L"\\Nls\\Codepage"
#define NLS_LANGUAGE_GROUPS_KEY    L"\\Nls\\Language Groups"
#define NLS_LOCALE_KEY             L"\\Nls\\Locale"
#define NLS_ALT_SORTS_KEY          L"\\Nls\\Locale\\Alternate Sorts"
#define NLS_MUILANG_KEY            L"\\Nls\\MUILanguages"

//
//  User Info.
//
#define NLS_CTRL_PANEL_KEY         L"Control Panel\\International"
#define NLS_CALENDARS_KEY          L"Control Panel\\International\\Calendars"
#define NLS_TWO_DIGIT_YEAR_KEY     L"Control Panel\\International\\Calendars\\TwoDigitYearMax"
#define NLS_POLICY_TWO_DIGIT_YEAR_KEY L"Software\\Policies\\Microsoft\\Control Panel\\International\\Calendars\\TwoDigitYearMax"

//
//  Get the wide character count from a byte count.
//
#define GET_WC_COUNT(bc)          ((bc) / sizeof(WCHAR))

#define NLS_CHAR_ZERO           L'0'   // digit 0 character	

#define NLS_REG_BUFFER_FREE(pBuffer)        (NLS_FREE_MEM(pBuffer))

#define PATHCCH_NONE                            0x00
#define PATHCCH_ALLOW_LONG_PATHS                0x01
#define PATHCCH_FORCE_ENABLE_LONG_NAME_PROCESS  0x02
#define PATHCCH_FORCE_DISABLE_LONG_NAME_PROCESS 0x04
#define PATHCCH_DO_NOT_NORMALIZE_SEGMENTS       0x08
#define PATHCCH_ENSURE_IS_EXTENDED_LENGTH_PATH  0x10

#define FSCTL_PIPE_GET_CONNECTION_ATTRIBUTE CTL_CODE(FILE_DEVICE_NAMED_PIPE, 12, METHOD_BUFFERED, FILE_ANY_ACCESS)

extern HANDLE           hAltSortsKey;       // handle to Locale\Alternate Sorts key

HRESULT 
WINAPI 
PathCchAddBackslash(
	WCHAR *path, 
	SIZE_T size
);

HRESULT 
WINAPI 
PathCchAddBackslashEx(
	WCHAR *path, 
	SIZE_T size, 
	WCHAR **end, 
	SIZE_T *remaining
);

HRESULT 
WINAPI 
PathCchCombineEx(
	WCHAR *out, 
	SIZE_T size, 
	const WCHAR *path1, 
	const WCHAR *path2, 
	DWORD flags
);

// typedef struct {
  // UINT  cbSize;
  // UINT  HistoryBufferSize;
  // UINT  NumberOfHistoryBuffers;
  // DWORD dwFlags;
// } CONSOLE_HISTORY_INFO, *PCONSOLE_HISTORY_INFO;

// typedef struct _CONSOLE_SCREEN_BUFFER_INFOEX {
  // ULONG      cbSize;
  // COORD      dwSize;
  // COORD      dwCursorPosition;
  // WORD       wAttributes;
  // SMALL_RECT srWindow;
  // COORD      dwMaximumWindowSize;
  // WORD       wPopupAttributes;
  // BOOL       bFullscreenSupported;
  // COLORREF   ColorTable[16];
// } CONSOLE_SCREEN_BUFFER_INFOEX, *PCONSOLE_SCREEN_BUFFER_INFOEX;

// typedef struct _CONSOLE_FONT_INFOEX {
  // ULONG cbSize;
  // DWORD nFont;
  // COORD dwFontSize;
  // UINT  FontFamily;
  // UINT  FontWeight;
  // WCHAR FaceName[LF_FACESIZE];
// } CONSOLE_FONT_INFOEX, *PCONSOLE_FONT_INFOEX;

// typedef struct _CONSOLE_GRAPHICS_BUFFER_INFO {
       // DWORD        dwBitMapInfoLength;
       // LPBITMAPINFO lpBitMapInfo;
       // DWORD        dwUsage;    // DIB_PAL_COLORS or DIB_RGB_COLORS
       // HANDLE       hMutex;
       // PVOID        lpBitMap;
// } CONSOLE_GRAPHICS_BUFFER_INFO, *PCONSOLE_GRAPHICS_BUFFER_INFO;

// typedef enum _FILE_INFO_BY_HANDLE_CLASS {
    // FileBasicInfo,
    // FileStandardInfo,
    // FileNameInfo,
    // FileRenameInfo,
    // FileDispositionInfo,
    // FileAllocationInfo,
    // FileEndOfFileInfo,
    // FileStreamInfo,
    // FileCompressionInfo,
    // FileAttributeTagInfo,
    // FileIdBothDirectoryInfo,
    // FileIdBothDirectoryRestartInfo,
    // FileIoPriorityHintInfo,
    // FileRemoteProtocolInfo,
    // FileFullDirectoryInfo,
    // FileFullDirectoryRestartInfo,
    // FileStorageInfo,
    // FileAlignmentInfo,
    // FileIdInfo,
    // FileIdExtdDirectoryInfo,
    // FileIdExtdDirectoryRestartInfo,
    // MaximumFileInfoByHandlesClass
// } FILE_INFO_BY_HANDLE_CLASS, *PFILE_INFO_BY_HANDLE_CLASS;

typedef struct _RTL_BARRIER
{
	DWORD Reserved1;
	DWORD Reserved2;
	ULONG_PTR Reserved3[2];
	DWORD Reserved4;
	DWORD Reserved5;
} RTL_BARRIER, *PRTL_BARRIER, SYNCHRONIZATION_BARRIER, *PSYNCHRONIZATION_BARRIER, *LPSYNCHRONIZATION_BARRIER;

// typedef struct _FILE_REMOTE_PROTOCOL_INFO {
    // USHORT StructureVersion;
    // USHORT StructureSize;
    // ULONG Protocol;
    // USHORT ProtocolMajorVersion;
    // USHORT ProtocolMinorVersion;
    // USHORT ProtocolRevision;
    // USHORT Reserved;
    // ULONG Flags;
    // struct {
        // ULONG Reserved[8];
    // } GenericReserved;
    // struct {
        // ULONG Reserved[16];
    // } ProtocolSpecificReserved;
// } FILE_REMOTE_PROTOCOL_INFO, *PFILE_REMOTE_PROTOCOL_INFO;

// typedef enum _FILE_ID_TYPE {
    // FileIdType,
    // ObjectIdType,
    // ExtendedFileIdType,
    // MaximumFileIdType
// } FILE_ID_TYPE, *PFILE_ID_TYPE;

// typedef struct _FILE_ID_DESCRIPTOR {
    // DWORD        dwSize;
    // FILE_ID_TYPE Type;
    // union {
        // LARGE_INTEGER FileId;
        // GUID          ObjectId;
    // } DUMMYUNIONNAME;
// } FILE_ID_DESCRIPTOR, *LPFILE_ID_DESCRIPTOR;

typedef enum
{
     INVALID_PATH = 0,
     UNC_PATH,              /* "//foo" */
     ABSOLUTE_DRIVE_PATH,   /* "c:/foo" */
     RELATIVE_DRIVE_PATH,   /* "c:foo" */
     ABSOLUTE_PATH,         /* "/foo" */
     RELATIVE_PATH,         /* "foo" */
     DEVICE_PATH,           /* "//./foo" */
     UNC_DOT_PATH           /* "//." */
} DOS_PATHNAME_TYPE;

typedef struct _STARTUPINFOEX {
  STARTUPINFO                 StartupInfo;
  PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} STARTUPINFOEX, *LPSTARTUPINFOEX;

#ifdef _M_AMD64
typedef struct _FLOATING_SAVE_AREA
{
     ULONG ControlWord;
     ULONG StatusWord;
     ULONG TagWord;
     ULONG ErrorOffset;
     ULONG ErrorSelector;
     ULONG DataOffset;
     ULONG DataSelector;
     UCHAR RegisterArea[80];
     ULONG Cr0NpxState;
} FLOATING_SAVE_AREA, *PFLOATING_SAVE_AREA;
#endif

typedef struct _WOW64_CONTEXT
{
     ULONGLONG ContextFlags;
     ULONGLONG Dr0;
     ULONGLONG Dr1;
     ULONGLONG Dr2;
     ULONGLONG Dr3;
     ULONGLONG Dr6;
     ULONGLONG Dr7;
     FLOATING_SAVE_AREA FloatSave;
     ULONGLONG SegGs;
     ULONGLONG SegFs;
     ULONGLONG SegEs;
     ULONGLONG SegDs;
     ULONGLONG Edi;
     ULONGLONG Esi;
     ULONGLONG Ebx;
     ULONGLONG Edx;
     ULONGLONG Ecx;
     ULONGLONG Eax;
     ULONGLONG Ebp;
     ULONGLONG Eip;
     ULONGLONG SegCs;
     ULONGLONG EFlags;
     ULONGLONG Esp;
     ULONGLONG SegSs;
     UCHAR ExtendedRegisters[512];
} WOW64_CONTEXT, *PWOW64_CONTEXT;

typedef struct _WOW64_LDT_ENTRY {
  WORD  LimitLow;
  WORD  BaseLow;
  union {
    struct {
      BYTE BaseMid;
      BYTE Flags1;
      BYTE Flags2;
      BYTE BaseHi;
    } Bytes;
    struct {
      DWORD BaseMid  :8;
      DWORD Type  :5;
      DWORD Dpl  :2;
      DWORD Pres  :1;
      DWORD LimitHi  :4;
      DWORD Sys  :1;
      DWORD Reserved_0  :1;
      DWORD Default_Big  :1;
      DWORD Granularity  :1;
      DWORD BaseHi  :8;
    } Bits;
  } HighWord;
} WOW64_LDT_ENTRY, *PWOW64_LDT_ENTRY;

typedef struct _CREATEFILE2_EXTENDED_PARAMETERS {
  DWORD                 dwSize;
  DWORD                 dwFileAttributes;
  DWORD                 dwFileFlags;
  DWORD                 dwSecurityQosFlags;
  LPSECURITY_ATTRIBUTES lpSecurityAttributes;
  HANDLE                hTemplateFile;
} CREATEFILE2_EXTENDED_PARAMETERS, *PCREATEFILE2_EXTENDED_PARAMETERS, *LPCREATEFILE2_EXTENDED_PARAMETERS;

typedef struct _PERF_COUNTERSET_INSTANCE {
  GUID  CounterSetGuid;
  ULONG dwSize;
  ULONG InstanceId;
  ULONG InstanceNameOffset;
  ULONG InstanceNameSize;
} PERF_COUNTERSET_INSTANCE, *PPERF_COUNTERSET_INSTANCE;

typedef struct _PERF_COUNTERSET_INFO {
  GUID  CounterSetGuid;
  GUID  ProviderGuid;
  ULONG NumCounters;
  ULONG InstanceType;
} PERF_COUNTERSET_INFO, *PPERF_COUNTERSET_INFO;

typedef LPVOID (CDECL * PERF_MEM_ALLOC)(SIZE_T,LPVOID);
typedef void (CDECL * PERF_MEM_FREE)(LPVOID,LPVOID);
typedef ULONG (WINAPI * PERFLIBREQUEST)(ULONG,PVOID,ULONG);

typedef struct _PROVIDER_CONTEXT {
  DWORD          ContextSize;
  DWORD          Reserved;
  PERFLIBREQUEST ControlCallback;
  PERF_MEM_ALLOC MemAllocRoutine;
  PERF_MEM_FREE  MemFreeRoutine;
  LPVOID         pMemContext;
} PERF_PROVIDER_CONTEXT, *PPERF_PROVIDER_CONTEXT;

typedef DYNAMIC_TIME_ZONE_INFORMATION RTL_DYNAMIC_TIME_ZONE_INFORMATION;

NTSTATUS WINAPI RtlQueryDynamicTimeZoneInformation(RTL_DYNAMIC_TIME_ZONE_INFORMATION*);

/* helper for kernel32->ntdll timeout format conversion */
static inline PLARGE_INTEGER get_nt_timeout( PLARGE_INTEGER pTime, DWORD timeout )
{
    if (timeout == INFINITE) return NULL;
    pTime->QuadPart = (ULONGLONG)timeout * -10000;
    return pTime;
}

int 
wine_compare_string(
	int flags, 
	const WCHAR *str1, 
	int len1,
    const WCHAR *str2, 
	int len2
);

int 
wine_get_sortkey(
	int flags, 
	const WCHAR *src, 
	int srclen, 
	char *dst, 
	int dstlen
);

typedef void *PUMS_CONTEXT;
typedef void *PUMS_COMPLETION_LIST;
typedef PRTL_UMS_SCHEDULER_ENTRY_POINT PUMS_SCHEDULER_ENTRY_POINT;

typedef struct _UMS_SCHEDULER_STARTUP_INFO
{
    ULONG UmsVersion;
    PUMS_COMPLETION_LIST CompletionList;
    PUMS_SCHEDULER_ENTRY_POINT SchedulerProc;
    PVOID SchedulerParam;
} UMS_SCHEDULER_STARTUP_INFO, *PUMS_SCHEDULER_STARTUP_INFO;

typedef enum _RTL_UMS_SCHEDULER_REASON UMS_SCHEDULER_REASON;
typedef enum _RTL_UMS_THREAD_INFO_CLASS UMS_THREAD_INFO_CLASS, *PUMS_THREAD_INFO_CLASS;

typedef struct _PSAPI_WS_WATCH_INFORMATION_EX {
  PSAPI_WS_WATCH_INFORMATION BasicInfo;
  ULONG_PTR FaultingThreadId;
  ULONG_PTR Flags;
} PSAPI_WS_WATCH_INFORMATION_EX, *PPSAPI_WS_WATCH_INFORMATION_EX;

typedef enum AppPolicyMediaFoundationCodecLoading
{
    AppPolicyMediaFoundationCodecLoading_All       = 0,
    AppPolicyMediaFoundationCodecLoading_InboxOnly = 1,
} AppPolicyMediaFoundationCodecLoading;

typedef enum _FIRMWARE_TYPE {
  FirmwareTypeUnknown,
  FirmwareTypeBios,
  FirmwareTypeUefi,
  FirmwareTypeMax
} FIRMWARE_TYPE, *PFIRMWARE_TYPE;

typedef enum _COPYFILE2_MESSAGE_TYPE
{
    COPYFILE2_CALLBACK_NONE = 0,
    COPYFILE2_CALLBACK_CHUNK_STARTED,
    COPYFILE2_CALLBACK_CHUNK_FINISHED,
    COPYFILE2_CALLBACK_STREAM_STARTED,
    COPYFILE2_CALLBACK_STREAM_FINISHED,
    COPYFILE2_CALLBACK_POLL_CONTINUE,
    COPYFILE2_CALLBACK_ERROR,
    COPYFILE2_CALLBACK_MAX,
} COPYFILE2_MESSAGE_TYPE;

typedef enum _COPYFILE2_MESSAGE_ACTION
{
    COPYFILE2_PROGRESS_CONTINUE = 0,
    COPYFILE2_PROGRESS_CANCEL,
    COPYFILE2_PROGRESS_STOP,
    COPYFILE2_PROGRESS_QUIET,
    COPYFILE2_PROGRESS_PAUSE,
} COPYFILE2_MESSAGE_ACTION;

typedef enum _COPYFILE2_COPY_PHASE
{
    COPYFILE2_PHASE_NONE = 0,
    COPYFILE2_PHASE_PREPARE_SOURCE,
    COPYFILE2_PHASE_PREPARE_DEST,
    COPYFILE2_PHASE_READ_SOURCE,
    COPYFILE2_PHASE_WRITE_DESTINATION,
    COPYFILE2_PHASE_SERVER_COPY,
    COPYFILE2_PHASE_NAMEGRAFT_COPY,
    COPYFILE2_PHASE_MAX,
} COPYFILE2_COPY_PHASE;

typedef struct COPYFILE2_MESSAGE
{
    COPYFILE2_MESSAGE_TYPE Type;
    DWORD                  dwPadding;
    union
    {
        struct
        {
            DWORD          dwStreamNumber;
            DWORD          dwReserved;
            HANDLE         hSourceFile;
            HANDLE         hDestinationFile;
            ULARGE_INTEGER uliChunkNumber;
            ULARGE_INTEGER uliChunkSize;
            ULARGE_INTEGER uliStreamSize;
            ULARGE_INTEGER uliTotalFileSize;
        } ChunkStarted;
        struct
        {
            DWORD          dwStreamNumber;
            DWORD          dwFlags;
            HANDLE         hSourceFile;
            HANDLE         hDestinationFile;
            ULARGE_INTEGER uliChunkNumber;
            ULARGE_INTEGER uliChunkSize;
            ULARGE_INTEGER uliStreamSize;
            ULARGE_INTEGER uliStreamBytesTransferred;
            ULARGE_INTEGER uliTotalFileSize;
            ULARGE_INTEGER uliTotalBytesTransferred;
        } ChunkFinished;
        struct
        {
            DWORD          dwStreamNumber;
            DWORD          dwReserved;
            HANDLE         hSourceFile;
            HANDLE         hDestinationFile;
            ULARGE_INTEGER uliStreamSize;
            ULARGE_INTEGER uliTotalFileSize;
        } StreamStarted;
        struct
        {
            DWORD          dwStreamNumber;
            DWORD          dwReserved;
            HANDLE         hSourceFile;
            HANDLE         hDestinationFile;
            ULARGE_INTEGER uliStreamSize;
            ULARGE_INTEGER uliStreamBytesTransferred;
            ULARGE_INTEGER uliTotalFileSize;
            ULARGE_INTEGER uliTotalBytesTransferred;
        } StreamFinished;
        struct
        {
            DWORD dwReserved;
        } PollContinue;
        struct
        {
            COPYFILE2_COPY_PHASE CopyPhase;
            DWORD                dwStreamNumber;
            HRESULT              hrFailure;
            DWORD                dwReserved;
            ULARGE_INTEGER       uliChunkNumber;
            ULARGE_INTEGER       uliStreamSize;
            ULARGE_INTEGER       uliStreamBytesTransferred;
            ULARGE_INTEGER       uliTotalFileSize;
            ULARGE_INTEGER       uliTotalBytesTransferred;
        } Error;
    } Info;
} COPYFILE2_MESSAGE;

typedef COPYFILE2_MESSAGE_ACTION (CALLBACK *PCOPYFILE2_PROGRESS_ROUTINE)(const COPYFILE2_MESSAGE*,PVOID);

typedef struct COPYFILE2_EXTENDED_PARAMETERS {
  DWORD                       dwSize;
  DWORD                       dwCopyFlags;
  BOOL                        *pfCancel;
  PCOPYFILE2_PROGRESS_ROUTINE pProgressRoutine;
  PVOID                       pvCallbackContext;
} COPYFILE2_EXTENDED_PARAMETERS;

typedef enum _OFFER_PRIORITY {
    VmOfferPriorityVeryLow = 1,
    VmOfferPriorityLow,
    VmOfferPriorityBelowNormal,
    VmOfferPriorityNormal
} OFFER_PRIORITY;

/* Undocumented: layout of the locale data in the locale.nls file */

typedef struct
{
    UINT   sname;                  /* 000 LOCALE_SNAME */
    UINT   sopentypelanguagetag;   /* 004 LOCALE_SOPENTYPELANGUAGETAG */
    USHORT ilanguage;              /* 008 LOCALE_ILANGUAGE */
    USHORT unique_lcid;            /* 00a unique id if lcid == 0x1000 */
    USHORT idigits;                /* 00c LOCALE_IDIGITS */
    USHORT inegnumber;             /* 00e LOCALE_INEGNUMBER */
    USHORT icurrdigits;            /* 010 LOCALE_ICURRDIGITS*/
    USHORT icurrency;              /* 012 LOCALE_ICURRENCY */
    USHORT inegcurr;               /* 014 LOCALE_INEGCURR */
    USHORT ilzero;                 /* 016 LOCALE_ILZERO */
    USHORT inotneutral;            /* 018 LOCALE_INEUTRAL (inverted) */
    USHORT ifirstdayofweek;        /* 01a LOCALE_IFIRSTDAYOFWEEK (monday=0) */
    USHORT ifirstweekofyear;       /* 01c LOCALE_IFIRSTWEEKOFYEAR */
    USHORT icountry;               /* 01e LOCALE_ICOUNTRY */
    USHORT imeasure;               /* 020 LOCALE_IMEASURE */
    USHORT idigitsubstitution;     /* 022 LOCALE_IDIGITSUBSTITUTION */
    UINT   sgrouping;              /* 024 LOCALE_SGROUPING (as binary string) */
    UINT   smongrouping;           /* 028 LOCALE_SMONGROUPING  (as binary string) */
    UINT   slist;                  /* 02c LOCALE_SLIST */
    UINT   sdecimal;               /* 030 LOCALE_SDECIMAL */
    UINT   sthousand;              /* 034 LOCALE_STHOUSAND */
    UINT   scurrency;              /* 038 LOCALE_SCURRENCY */
    UINT   smondecimalsep;         /* 03c LOCALE_SMONDECIMALSEP */
    UINT   smonthousandsep;        /* 040 LOCALE_SMONTHOUSANDSEP */
    UINT   spositivesign;          /* 044 LOCALE_SPOSITIVESIGN */
    UINT   snegativesign;          /* 048 LOCALE_SNEGATIVESIGN */
    UINT   s1159;                  /* 04c LOCALE_S1159 */
    UINT   s2359;                  /* 050 LOCALE_S2359 */
    UINT   snativedigits;          /* 054 LOCALE_SNATIVEDIGITS (array of single digits) */
    UINT   stimeformat;            /* 058 LOCALE_STIMEFORMAT (array of formats) */
    UINT   sshortdate;             /* 05c LOCALE_SSHORTDATE (array of formats) */
    UINT   slongdate;              /* 060 LOCALE_SLONGDATE (array of formats) */
    UINT   syearmonth;             /* 064 LOCALE_SYEARMONTH (array of formats) */
    UINT   sduration;              /* 068 LOCALE_SDURATION (array of formats) */
    USHORT idefaultlanguage;       /* 06c LOCALE_IDEFAULTLANGUAGE */
    USHORT idefaultansicodepage;   /* 06e LOCALE_IDEFAULTANSICODEPAGE */
    USHORT idefaultcodepage;       /* 070 LOCALE_IDEFAULTCODEPAGE */
    USHORT idefaultmaccodepage;    /* 072 LOCALE_IDEFAULTMACCODEPAGE */
    USHORT idefaultebcdiccodepage; /* 074 LOCALE_IDEFAULTEBCDICCODEPAGE */
    USHORT old_geoid;              /* 076 LOCALE_IGEOID (older version?) */
    USHORT ipapersize;             /* 078 LOCALE_IPAPERSIZE */
    BYTE   islamic_cal[2];         /* 07a calendar id for islamic calendars (?) */
    UINT   scalendartype;          /* 07c string, first char is LOCALE_ICALENDARTYPE, next chars are LOCALE_IOPTIONALCALENDAR */
    UINT   sabbrevlangname;        /* 080 LOCALE_SABBREVLANGNAME */
    UINT   siso639langname;        /* 084 LOCALE_SISO639LANGNAME */
    UINT   senglanguage;           /* 088 LOCALE_SENGLANGUAGE */
    UINT   snativelangname;        /* 08c LOCALE_SNATIVELANGNAME */
    UINT   sengcountry;            /* 090 LOCALE_SENGCOUNTRY */
    UINT   snativectryname;        /* 094 LOCALE_SNATIVECTRYNAME */
    UINT   sabbrevctryname;        /* 098 LOCALE_SABBREVCTRYNAME */
    UINT   siso3166ctryname;       /* 09c LOCALE_SISO3166CTRYNAME */
    UINT   sintlsymbol;            /* 0a0 LOCALE_SINTLSYMBOL */
    UINT   sengcurrname;           /* 0a4 LOCALE_SENGCURRNAME */
    UINT   snativecurrname;        /* 0a8 LOCALE_SNATIVECURRNAME */
    UINT   fontsignature;          /* 0ac LOCALE_FONTSIGNATURE (binary string) */
    UINT   siso639langname2;       /* 0b0 LOCALE_SISO639LANGNAME2 */
    UINT   siso3166ctryname2;      /* 0b4 LOCALE_SISO3166CTRYNAME2 */
    UINT   sparent;                /* 0b8 LOCALE_SPARENT */
    UINT   sdayname;               /* 0bc LOCALE_SDAYNAME1 (array of days 1..7) */
    UINT   sabbrevdayname;         /* 0c0 LOCALE_SABBREVDAYNAME1  (array of days 1..7) */
    UINT   smonthname;             /* 0c4 LOCALE_SMONTHNAME1 (array of months 1..13) */
    UINT   sabbrevmonthname;       /* 0c8 LOCALE_SABBREVMONTHNAME1 (array of months 1..13) */
    UINT   sgenitivemonth;         /* 0cc equivalent of LOCALE_SMONTHNAME1 for genitive months */
    UINT   sabbrevgenitivemonth;   /* 0d0 equivalent of LOCALE_SABBREVMONTHNAME1 for genitive months */
    UINT   calnames;               /* 0d4 array of calendar names */
    UINT   customsorts;            /* 0d8 array of custom sort names */
    USHORT inegativepercent;       /* 0dc LOCALE_INEGATIVEPERCENT */
    USHORT ipositivepercent;       /* 0de LOCALE_IPOSITIVEPERCENT */
    USHORT unknown1;               /* 0e0 */
    USHORT ireadinglayout;         /* 0e2 LOCALE_IREADINGLAYOUT */
    USHORT unknown2[2];            /* 0e4 */
    UINT   unused1;                /* 0e8 unused? */
    UINT   sengdisplayname;        /* 0ec LOCALE_SENGLISHDISPLAYNAME */
    UINT   snativedisplayname;     /* 0f0 LOCALE_SNATIVEDISPLAYNAME */
    UINT   spercent;               /* 0f4 LOCALE_SPERCENT */
    UINT   snan;                   /* 0f8 LOCALE_SNAN */
    UINT   sposinfinity;           /* 0fc LOCALE_SPOSINFINITY */
    UINT   sneginfinity;           /* 100 LOCALE_SNEGINFINITY */
    UINT   unused2;                /* 104 unused? */
    UINT   serastring;             /* 108 CAL_SERASTRING */
    UINT   sabbreverastring;       /* 10c CAL_SABBREVERASTRING */
    UINT   unused3;                /* 110 unused? */
    UINT   sconsolefallbackname;   /* 114 LOCALE_SCONSOLEFALLBACKNAME */
    UINT   sshorttime;             /* 118 LOCALE_SSHORTTIME (array of formats) */
    UINT   sshortestdayname;       /* 11c LOCALE_SSHORTESTDAYNAME1 (array of days 1..7) */
    UINT   unused4;                /* 120 unused? */
    UINT   ssortlocale;            /* 124 LOCALE_SSORTLOCALE */
    UINT   skeyboardstoinstall;    /* 128 LOCALE_SKEYBOARDSTOINSTALL */
    UINT   sscripts;               /* 12c LOCALE_SSCRIPTS */
    UINT   srelativelongdate;      /* 130 LOCALE_SRELATIVELONGDATE */
    UINT   igeoid;                 /* 134 LOCALE_IGEOID */
    UINT   sshortestam;            /* 138 LOCALE_SSHORTESTAM */
    UINT   sshortestpm;            /* 13c LOCALE_SSHORTESTPM */
    UINT   smonthday;              /* 140 LOCALE_SMONTHDAY (array of formats) */
    UINT   keyboard_layout;        /* 144 keyboard layouts */
} NLS_LOCALE_DATA;

typedef struct
{
    UINT   offset;                 /* 00 offset to version, always 8? */
    UINT   unknown1;               /* 04 */
    UINT   version;                /* 08 file format version */
    UINT   magic;                  /* 0c magic 'NSDS' */
    UINT   unknown2[3];            /* 10 */
    USHORT header_size;            /* 1c size of this header (?) */
    USHORT nb_lcids;               /* 1e number of lcids in index */
    USHORT nb_locales;             /* 20 number of locales in array */
    USHORT locale_size;            /* 22 size of NLS_LOCALE_DATA structure */
    UINT   locales_offset;         /* 24 offset of locales array */
    USHORT nb_lcnames;             /* 28 number of lcnames in index */
    USHORT pad;                    /* 2a */
    UINT   lcids_offset;           /* 2c offset of lcids index */
    UINT   lcnames_offset;         /* 30 offset of lcnames index */
    UINT   unknown3;               /* 34 */
    USHORT nb_calendars;           /* 38 number of calendars in array */
    USHORT calendar_size;          /* 3a size of calendar structure */
    UINT   calendars_offset;       /* 3c offset of calendars array */
    UINT   strings_offset;         /* 40 offset of strings data */
    USHORT unknown4[4];            /* 44 */
} NLS_LOCALE_HEADER;

typedef struct
{
    USHORT name;                   /* 00 locale name */
    USHORT idx;                    /* 02 index in locales array */
    UINT   id;                     /* 04 lcid */
} NLS_LOCALE_LCNAME_INDEX;

ULONG
WINAPI
BaseSetLastNTError(
    IN NTSTATUS Status
);

PUNICODE_STRING
WINAPI
Basep8BitStringToStaticUnicodeString(
	IN LPCSTR String
);

PWCHAR 
FilenameA2W(
	LPCSTR NameA, 
	BOOL alloc
);

LCID 
WINAPI 
LocaleNameToLCID( 
	LPCWSTR name, 
	DWORD flags 
);

INT 
WINAPI 
LCIDToLocaleName( 
	LCID lcid, 
	LPWSTR name, 
	INT count, 
	DWORD flags 
);

POBJECT_ATTRIBUTES 
WINAPI 
BaseFormatObjectAttributes( 	
	OUT POBJECT_ATTRIBUTES  	ObjectAttributes,
	IN PSECURITY_ATTRIBUTES SecurityAttributes  	OPTIONAL,
	IN PUNICODE_STRING  	ObjectName 
);

NTSTATUS 
NTAPI
NtPowerInformation(
  _In_      POWER_INFORMATION_LEVEL InformationLevel,
  _In_opt_  PVOID                   InputBuffer,
  _In_      ULONG                   InputBufferLength,
  _Out_opt_ PVOID                   OutputBuffer,
  _In_      ULONG                   OutputBufferLength
);

HANDLE 
WINAPI 
BaseGetNamedObjectDirectory(VOID);

NTSTATUS 
WINAPI 
RtlGetUserPreferredUILanguages(
	DWORD dwFlags, 
	BOOL verification,
	PULONG pulNumLanguages, 
	PZZWSTR pwszLanguagesBuffer, 
	PULONG pcchLanguagesBuffer
);

NTSTATUS 
WINAPI 
RtlGetThreadPreferredUILanguages(
	_In_       DWORD dwFlags,
	_Out_      PULONG pulNumLanguages,
	_Out_opt_  PZZWSTR pwszLanguagesBuffer,
	_Inout_    PULONG pcchLanguagesBuffer
);

ULONG GetLocaleFileInfo(
    LCID Locale,
    PLOC_HASH *ppNode,
    BOOLEAN fCreateNode);
	
NTSYSAPI 
NTSTATUS 
WINAPI 
NtClose(HANDLE);	

NTSTATUS 
NTAPI
RtlRunOnceExecuteOnce(
  _Inout_ PRTL_RUN_ONCE         RunOnce,
  _In_    PRTL_RUN_ONCE_INIT_FN InitFn,
  _Inout_ PVOID                 Parameter,
  _Out_   PVOID                 *Context
);

NTSTATUS 
NTAPI
RtlRunOnceBeginInitialize(
  _Inout_ PRTL_RUN_ONCE RunOnce,
  _In_    ULONG         Flags,
  _Out_   PVOID         *Context
);

BOOL
WINAPI
SleepConditionVariableCS(
	PCONDITION_VARIABLE ConditionVariable, 
	PCRITICAL_SECTION CriticalSection, 
	DWORD Timeout
);

void 
WINAPI 
TpSetTimer(
	TP_TIMER *, 
	LARGE_INTEGER *,
	LONG,
	LONG
);

void 
WINAPI 
TpSetWait(
	TP_WAIT *,
	HANDLE,
	LARGE_INTEGER *
);

NTSTATUS 
WINAPI 
TpCallbackMayRunLong(
	TP_CALLBACK_INSTANCE *
);

NTSTATUS NTAPI LdrFindResourceDirectory_U 	( 	IN PVOID  	BaseAddress,
		IN PLDR_RESOURCE_INFO  	info,
		IN ULONG  	level,
		OUT PIMAGE_RESOURCE_DIRECTORY *  	addr 
	);
	
BOOL
WINAPI
CreateProcessInternalW(
    HANDLE hUserToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE hRestrictedUserToken
    );	
	
BOOL
WINAPI
CreateProcessInternalA(
    HANDLE hUserToken,
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE hRestrictedUserToken
);	
	
BOOL
WINAPI
GetNumaNodeProcessorMask(
    UCHAR Node,
    PULONGLONG ProcessorMask
    );	
	
BOOL 
WINAPI 
GetNumaAvailableMemoryNode(
	UCHAR Node, 
	PULONGLONG AvailableBytes
);	

PLARGE_INTEGER 
WINAPI 
BaseFormatTimeOut(
	OUT PLARGE_INTEGER  	Timeout,
	IN DWORD  	dwMilliseconds 
);

INT 
WINAPI 
GetUserDefaultLocaleName(
	LPWSTR localename, 
	int buffersize
);

static inline BOOL set_ntstatus( NTSTATUS status )
{
    if (status) SetLastError( RtlNtStatusToDosError( status ));
    return !status;
}

/* FUNCTIONS ****************************************************************/
FORCEINLINE
BOOL
IsHKCRKey(_In_ HKEY hKey)
{
    return ((ULONG_PTR)hKey & 0x2) != 0;
}

FORCEINLINE
void
MakeHKCRKey(_Inout_ HKEY* hKey)
{
    *hKey = (HKEY)((ULONG_PTR)(*hKey) | 0x2);
}

LONG
WINAPI
CreateHKCRKey(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _In_ DWORD Reserved,
    _In_opt_ LPWSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_opt_ LPDWORD lpdwDisposition);

LONG
WINAPI
DeleteHKCRKey(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _In_ REGSAM RegSam,
    _In_ DWORD Reserved);	

LONG
WINAPI
EnumHKCRKey(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_ LPWSTR lpName,
    _Inout_ LPDWORD lpcbName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPWSTR lpClass,
    _Inout_opt_ LPDWORD lpcbClass,
    _Out_opt_ PFILETIME lpftLastWriteTime);

LONG
WINAPI
EnumHKCRValue(
    _In_ HKEY hKey,
    _In_ DWORD index,
    _Out_ LPWSTR value,
    _Inout_ PDWORD val_count,
    _Reserved_ PDWORD reserved,
    _Out_opt_ PDWORD type,
    _Out_opt_ LPBYTE data,
    _Inout_opt_ PDWORD count);
	
LONG
WINAPI
OpenHKCRKey(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _In_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _In_ PHKEY phkResult);		

LONG
WINAPI
QueryHKCRValue(
    _In_ HKEY hKey,
    _In_ LPCWSTR Name,
    _In_ LPDWORD Reserved,
    _In_ LPDWORD Type,
    _In_ LPBYTE Data,
    _In_ LPDWORD Count);	
	
LONG
WINAPI
SetHKCRValue(
    _In_ HKEY hKey,
    _In_ LPCWSTR Name,
    _In_ DWORD Reserved,
    _In_ DWORD Type,
    _In_ CONST BYTE* Data,
    _In_ DWORD DataSize);	
	
INT 
WINAPI 
CompareStringOrdinal(
	const WCHAR *str1, 
	INT len1, 
	const WCHAR *str2, 
	INT len2, 
	BOOL ignore_case
);	

HRESULT 
WINAPI 
PathMatchSpecExW(
	const WCHAR *path, 
	const WCHAR *mask, 
	DWORD flags
);

BOOL
WINAPI
GetNumaProcessorNode(
	IN UCHAR Processor,
    OUT PUCHAR NodeNumber
);