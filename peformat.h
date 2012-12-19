#ifndef __windows_image_formats_h__
#define __windows_image_formats_h__

#if defined( WIN32 ) && !defined( KERNEL_MODE )
# include <windows.h>
#else

//#include <cpprt.h>


/*
typedef int 					BOOLEAN;
typedef wchar_t					WCHAR;
typedef short 					SHORT;
typedef char 					CHAR;
typedef long 					LONG;
typedef unsigned long       	ULONG;
typedef int                 	BOOL;
typedef unsigned char       	BYTE;
typedef unsigned short      	USHORT;
typedef float               	FLOAT;
typedef FLOAT			*PFLOAT;
typedef BOOL	            	*PBOOL;
typedef BOOL			*LPBOOL;
typedef uint8_t            	*Puint8_t;
typedef uint8_t             	*LPuint8_t;
typedef int          		*PINT;
typedef int              	*LPINT;
typedef uint16_t          		*Puint16_t;
typedef uint16_t          		*LPuint16_t;
typedef long          		*LPLONG;
typedef uint32_t         		*Puint32_t;
typedef uint32_t         		*LPuint32_t;
typedef void          		*LPVOID;
typedef void 				VOID;
typedef const void       	*LPCVOID;
*/

#if ! (defined _GUID_DEFINED || defined GUID_DEFINED) /* also defined in basetyps.h */
#define GUID_DEFINED
typedef struct _GUID {
  unsigned long  Data1;
  unsigned short Data2;
  unsigned short Data3;
  unsigned char  Data4[8];
} GUID, *REFGUID, *LPGUID; 
typedef GUID CLSID;
#endif

#ifndef _MAC

//#include "pshpack4.h"                   // 4 uint8_t packing is the default
#pragma pack(push, 4)
#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
#define IMAGE_OS2_SIGNATURE                 0x454E      // NE
#define IMAGE_OS2_SIGNATURE_LE              0x454C      // LE
#define IMAGE_VXD_SIGNATURE                 0x454C      // LE
#define IMAGE_NT_SIGNATURE                  0x00004550  // PE00

//#include "pshpack2.h"                   // 16 bit headers are 2 uint8_t packed
#pragma pack(push, 2)
#else

//#include "pshpack1.h"
#pragma pack(push, 1)
#define IMAGE_DOS_SIGNATURE                 0x4D5A      // MZ
#define IMAGE_OS2_SIGNATURE                 0x4E45      // NE
#define IMAGE_OS2_SIGNATURE_LE              0x4C45      // LE
#define IMAGE_NT_SIGNATURE                  0x50450000  // PE00
#endif

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	uint16_t   e_magic;                     // Magic number
	uint16_t   e_cblp;                      // uint8_ts on last page of file
	uint16_t   e_cp;                        // Pages in file
	uint16_t   e_crlc;                      // Relocations
	uint16_t   e_cparhdr;                   // Size of header in paragraphs
	uint16_t   e_minalloc;                  // Minimum extra paragraphs needed
	uint16_t   e_maxalloc;                  // Maximum extra paragraphs needed
	uint16_t   e_ss;                        // Initial (relative) SS value
	uint16_t   e_sp;                        // Initial SP value
	uint16_t   e_csum;                      // Checksum
	uint16_t   e_ip;                        // Initial IP value
	uint16_t   e_cs;                        // Initial (relative) CS value
	uint16_t   e_lfarlc;                    // File address of relocation table
	uint16_t   e_ovno;                      // Overlay number
	uint16_t   e_res[4];                    // Reserved uint16_ts
	uint16_t   e_oemid;                     // OEM identifier (for e_oeminfo)
	uint16_t   e_oeminfo;                   // OEM information; e_oemid specific
	uint16_t   e_res2[10];                  // Reserved uint16_ts
	int32_t   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_OS2_HEADER {      // OS/2 .EXE header
	uint16_t   ne_magic;                    // Magic number
	char   ne_ver;                      // Version number
	char   ne_rev;                      // Revision number
	uint16_t   ne_enttab;                   // Offset of Entry Table
	uint16_t   ne_cbenttab;                 // Number of uint8_ts in Entry Table
	int32_t   ne_crc;                      // Checksum of whole file
	uint16_t   ne_flags;                    // Flag uint16_t
	uint16_t   ne_autodata;                 // Automatic data segment number
	uint16_t   ne_heap;                     // Initial heap allocation
	uint16_t   ne_stack;                    // Initial stack allocation
	int32_t   ne_csip;                     // Initial CS:IP setting
	int32_t   ne_sssp;                     // Initial SS:SP setting
	uint16_t   ne_cseg;                     // Count of file segments
	uint16_t   ne_cmod;                     // Entries in Module Reference Table
	uint16_t   ne_cbnrestab;                // Size of non-resident name table
	uint16_t   ne_segtab;                   // Offset of Segment Table
	uint16_t   ne_rsrctab;                  // Offset of Resource Table
	uint16_t   ne_restab;                   // Offset of resident name table
	uint16_t   ne_modtab;                   // Offset of Module Reference Table
	uint16_t   ne_imptab;                   // Offset of Imported Names Table
	int32_t   ne_nrestab;                  // Offset of Non-resident Names Table
	uint16_t   ne_cmovent;                  // Count of movable entries
	uint16_t   ne_align;                    // Segment alignment shift count
	uint16_t   ne_cres;                     // Count of resource segments
	uint8_t   ne_exetyp;                   // Target Operating system
	uint8_t   ne_flagsothers;              // Other .EXE flags
	uint16_t   ne_pretthunks;               // offset to return thunks
	uint16_t   ne_psegrefuint8_ts;             // offset to segment ref. uint8_ts
	uint16_t   ne_swaparea;                 // Minimum code swap area size
	uint16_t   ne_expver;                   // Expected Windows version number
} IMAGE_OS2_HEADER, *PIMAGE_OS2_HEADER;

typedef struct _IMAGE_VXD_HEADER {      // Windows VXD header
	uint16_t   e32_magic;                   // Magic number
	uint8_t   e32_border;                  // The uint8_t ordering for the VXD
	uint8_t   e32_uint16_ter;                  // The uint16_t ordering for the VXD
	uint32_t  e32_level;                   // The EXE format level for now = 0
	uint16_t   e32_cpu;                     // The CPU type
	uint16_t   e32_os;                      // The OS type
	uint32_t  e32_ver;                     // Module version
	uint32_t  e32_mflags;                  // Module flags
	uint32_t  e32_mpages;                  // Module # pages
	uint32_t  e32_startobj;                // Object # for instruction pointer
	uint32_t  e32_eip;                     // Extended instruction pointer
	uint32_t  e32_stackobj;                // Object # for stack pointer
	uint32_t  e32_esp;                     // Extended stack pointer
	uint32_t  e32_pagesize;                // VXD page size
	uint32_t  e32_lastpagesize;            // Last page size in VXD
	uint32_t  e32_fixupsize;               // Fixup section size
	uint32_t  e32_fixupsum;                // Fixup section checksum
	uint32_t  e32_ldrsize;                 // Loader section size
	uint32_t  e32_ldrsum;                  // Loader section checksum
	uint32_t  e32_objtab;                  // Object table offset
	uint32_t  e32_objcnt;                  // Number of objects in module
	uint32_t  e32_objmap;                  // Object page map offset
	uint32_t  e32_itermap;                 // Object iterated data map offset
	uint32_t  e32_rsrctab;                 // Offset of Resource Table
	uint32_t  e32_rsrccnt;                 // Number of resource entries
	uint32_t  e32_restab;                  // Offset of resident name table
	uint32_t  e32_enttab;                  // Offset of Entry Table
	uint32_t  e32_dirtab;                  // Offset of Module Directive Table
	uint32_t  e32_dircnt;                  // Number of module directives
	uint32_t  e32_fpagetab;                // Offset of Fixup Page Table
	uint32_t  e32_frectab;                 // Offset of Fixup Record Table
	uint32_t  e32_impmod;                  // Offset of Import Module Name Table
	uint32_t  e32_impmodcnt;               // Number of entries in Import Module Name Table
	uint32_t  e32_impproc;                 // Offset of Import Procedure Name Table
	uint32_t  e32_pagesum;                 // Offset of Per-Page Checksum Table
	uint32_t  e32_datapage;                // Offset of Enumerated Data Pages
	uint32_t  e32_preload;                 // Number of preload pages
	uint32_t  e32_nrestab;                 // Offset of Non-resident Names Table
	uint32_t  e32_cbnrestab;               // Size of Non-resident Name Table
	uint32_t  e32_nressum;                 // Non-resident Name Table Checksum
	uint32_t  e32_autodata;                // Object # for automatic data object
	uint32_t  e32_debuginfo;               // Offset of the debugging information
	uint32_t  e32_debuglen;                // The length of the debugging info. in uint8_ts
	uint32_t  e32_instpreload;             // Number of instance pages in preload section of VXD file
	uint32_t  e32_instdemand;              // Number of instance pages in demand load section of VXD file
	uint32_t  e32_heapsize;                // Size of heap - for 16-bit apps
	uint8_t   e32_res3[12];                // Reserved uint16_ts
	uint32_t  e32_winresoff;
	uint32_t  e32_winreslen;
	uint16_t   e32_devid;                   // Device ID for VxD
	uint16_t   e32_ddkver;                  // DDK version for VxD
} IMAGE_VXD_HEADER, *PIMAGE_VXD_HEADER;

#ifndef _MAC
//#include "poppack.h"                    // Back to 4 uint8_t packing
#endif

//
// File header format.
//

typedef struct _IMAGE_FILE_HEADER {
	uint16_t    Machine;
	uint16_t    NumberOfSections;
	uint32_t   TimeDateStamp;
	uint32_t   PointerToSymbolTable;
	uint32_t   NumberOfSymbols;
	uint16_t    SizeOfOptionalHeader;
	uint16_t    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

#define IMAGE_SIZEOF_FILE_HEADER             20


#define IMAGE_FILE_RELOCS_STRIPPED           0x0001  // Relocation info stripped from file.
#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002  // File is executable  (i.e. no unresolved externel references).
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004  // Line nunbers stripped from file.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008  // Local symbols stripped from file.
#define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010  // Agressively trim working set
#define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020  // App can handle >2gb addresses
#define IMAGE_FILE_uint8_tS_REVERSED_LO         0x0080  // uint8_ts of machine uint16_t are reversed.
#define IMAGE_FILE_32BIT_MACHINE             0x0100  // 32 bit uint16_t machine.
#define IMAGE_FILE_DEBUG_STRIPPED            0x0200  // Debugging info stripped from file in .DBG file
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400  // If Image is on removable media, copy and run from the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800  // If Image is on Net, copy and run from the swap file.
#define IMAGE_FILE_SYSTEM                    0x1000  // System File.
#define IMAGE_FILE_DLL                       0x2000  // File is a DLL.
#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000  // File should only be run on a UP machine
#define IMAGE_FILE_uint8_tS_REVERSED_HI         0x8000  // uint8_ts of machine uint16_t are reversed.

#define IMAGE_FILE_MACHINE_UNKNOWN           0
#define IMAGE_FILE_MACHINE_I386              0x014c  // Intel 386.
#define IMAGE_FILE_MACHINE_R3000             0x0162  // MIPS little-endian, 0x160 big-endian
#define IMAGE_FILE_MACHINE_R4000             0x0166  // MIPS little-endian
#define IMAGE_FILE_MACHINE_R10000            0x0168  // MIPS little-endian
#define IMAGE_FILE_MACHINE_WCEMIPSV2         0x0169  // MIPS little-endian WCE v2
#define IMAGE_FILE_MACHINE_ALPHA             0x0184  // Alpha_AXP
#define IMAGE_FILE_MACHINE_SH3               0x01a2  // SH3 little-endian
#define IMAGE_FILE_MACHINE_SH3DSP            0x01a3
#define IMAGE_FILE_MACHINE_SH3E              0x01a4  // SH3E little-endian
#define IMAGE_FILE_MACHINE_SH4               0x01a6  // SH4 little-endian
#define IMAGE_FILE_MACHINE_SH5               0x01a8  // SH5
#define IMAGE_FILE_MACHINE_ARM               0x01c0  // ARM Little-Endian
#define IMAGE_FILE_MACHINE_THUMB             0x01c2
#define IMAGE_FILE_MACHINE_AM33              0x01d3
#define IMAGE_FILE_MACHINE_POWERPC           0x01F0  // IBM PowerPC Little-Endian
#define IMAGE_FILE_MACHINE_POWERPCFP         0x01f1
#define IMAGE_FILE_MACHINE_IA64              0x0200  // Intel 64
#define IMAGE_FILE_MACHINE_MIPS16            0x0266  // MIPS
#define IMAGE_FILE_MACHINE_ALPHA64           0x0284  // ALPHA64
#define IMAGE_FILE_MACHINE_MIPSFPU           0x0366  // MIPS
#define IMAGE_FILE_MACHINE_MIPSFPU16         0x0466  // MIPS
#define IMAGE_FILE_MACHINE_AXP64             IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE           0x0520  // Infineon
#define IMAGE_FILE_MACHINE_CEF               0x0CEF
#define IMAGE_FILE_MACHINE_EBC               0x0EBC  // EFI uint8_t Code
#define IMAGE_FILE_MACHINE_AMD64             0x8664  // AMD64 (K8)
#define IMAGE_FILE_MACHINE_M32R              0x9041  // M32R little-endian
#define IMAGE_FILE_MACHINE_CEE               0xC0EE

//
// Directory format.
//

typedef struct _IMAGE_DATA_DIRECTORY {
	uint32_t   VirtualAddress;
	uint32_t   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

//
// Optional header format.
//

typedef struct _IMAGE_OPTIONAL_HEADER {
	//
	// Standard fields.
	//

	uint16_t    Magic;
	uint8_t    MajorLinkerVersion;
	uint8_t    MinorLinkerVersion;
	uint32_t   SizeOfCode;
	uint32_t   SizeOfInitializedData;
	uint32_t   SizeOfUninitializedData;
	uint32_t   AddressOfEntryPoint;
	uint32_t   BaseOfCode;
	uint32_t   BaseOfData;

	//
	// NT additional fields.
	//

	uint32_t   ImageBase;
	uint32_t   SectionAlignment;
	uint32_t   FileAlignment;
	uint16_t    MajorOperatingSystemVersion;
	uint16_t    MinorOperatingSystemVersion;
	uint16_t    MajorImageVersion;
	uint16_t    MinorImageVersion;
	uint16_t    MajorSubsystemVersion;
	uint16_t    MinorSubsystemVersion;
	uint32_t   Win32VersionValue;
	uint32_t   SizeOfImage;
	uint32_t   SizeOfHeaders;
	uint32_t   CheckSum;
	uint16_t    Subsystem;
	uint16_t    DllCharacteristics;
	uint32_t   SizeOfStackReserve;
	uint32_t   SizeOfStackCommit;
	uint32_t   SizeOfHeapReserve;
	uint32_t   SizeOfHeapCommit;
	uint32_t   LoaderFlags;
	uint32_t   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_ROM_OPTIONAL_HEADER {
	uint16_t   Magic;
	uint8_t   MajorLinkerVersion;
	uint8_t   MinorLinkerVersion;
	uint32_t  SizeOfCode;
	uint32_t  SizeOfInitializedData;
	uint32_t  SizeOfUninitializedData;
	uint32_t  AddressOfEntryPoint;
	uint32_t  BaseOfCode;
	uint32_t  BaseOfData;
	uint32_t  BaseOfBss;
	uint32_t  GprMask;
	uint32_t  CprMask[4];
	uint32_t  GpValue;
} IMAGE_ROM_OPTIONAL_HEADER, *PIMAGE_ROM_OPTIONAL_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	uint16_t        Magic;
	uint8_t        MajorLinkerVersion;
	uint8_t        MinorLinkerVersion;
	uint32_t       SizeOfCode;
	uint32_t       SizeOfInitializedData;
	uint32_t       SizeOfUninitializedData;
	uint32_t       AddressOfEntryPoint;
	uint32_t       BaseOfCode;
	uint64_t   ImageBase;
	uint32_t       SectionAlignment;
	uint32_t       FileAlignment;
	uint16_t        MajorOperatingSystemVersion;
	uint16_t        MinorOperatingSystemVersion;
	uint16_t        MajorImageVersion;
	uint16_t        MinorImageVersion;
	uint16_t        MajorSubsystemVersion;
	uint16_t        MinorSubsystemVersion;
	uint32_t       Win32VersionValue;
	uint32_t       SizeOfImage;
	uint32_t       SizeOfHeaders;
	uint32_t       CheckSum;
	uint16_t        Subsystem;
	uint16_t        DllCharacteristics;
	uint64_t   SizeOfStackReserve;
	uint64_t   SizeOfStackCommit;
	uint64_t   SizeOfHeapReserve;
	uint64_t   SizeOfHeapCommit;
	uint32_t       LoaderFlags;
	uint32_t       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

#define IMAGE_SIZEOF_ROM_OPTIONAL_HEADER      56
#define IMAGE_SIZEOF_STD_OPTIONAL_HEADER      28
#define IMAGE_SIZEOF_NT_OPTIONAL32_HEADER    224
#define IMAGE_SIZEOF_NT_OPTIONAL64_HEADER    240

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC       0x107

#ifdef PE_WIN64
typedef IMAGE_OPTIONAL_HEADER64             IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER64            PIMAGE_OPTIONAL_HEADER;
#define IMAGE_SIZEOF_NT_OPTIONAL_HEADER     IMAGE_SIZEOF_NT_OPTIONAL64_HEADER
#define IMAGE_NT_OPTIONAL_HDR_MAGIC         IMAGE_NT_OPTIONAL_HDR64_MAGIC
#else
typedef IMAGE_OPTIONAL_HEADER32             IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32            PIMAGE_OPTIONAL_HEADER;
#define IMAGE_SIZEOF_NT_OPTIONAL_HEADER     IMAGE_SIZEOF_NT_OPTIONAL32_HEADER
#define IMAGE_NT_OPTIONAL_HDR_MAGIC         IMAGE_NT_OPTIONAL_HDR32_MAGIC
#endif

typedef struct _IMAGE_NT_HEADERS64 {
	uint32_t Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
	uint32_t Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_ROM_HEADERS {
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_ROM_OPTIONAL_HEADER OptionalHeader;
} IMAGE_ROM_HEADERS, *PIMAGE_ROM_HEADERS;

#ifdef PE_WIN64
typedef IMAGE_NT_HEADERS64                  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64                 PIMAGE_NT_HEADERS;
#else
typedef IMAGE_NT_HEADERS32                  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32                 PIMAGE_NT_HEADERS;
#endif

// IMAGE_FIRST_SECTION doesn't need 32/64 versions since the file header is the same either way.

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
	((ULONG_PTR)ntheader +                                              \
	FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
	((PIMAGE_NT_HEADERS)(ntheader))->FileHeader.SizeOfOptionalHeader   \
	))

// Subsystem Values

#define IMAGE_SUBSYSTEM_UNKNOWN              0   // Unknown subsystem.
#define IMAGE_SUBSYSTEM_NATIVE               1   // Image doesn't require a subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_GUI          2   // Image runs in the Windows GUI subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_CUI          3   // Image runs in the Windows character subsystem.
#define IMAGE_SUBSYSTEM_OS2_CUI              5   // image runs in the OS/2 character subsystem.
#define IMAGE_SUBSYSTEM_POSIX_CUI            7   // image runs in the Posix character subsystem.
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS       8   // image is a native Win9x driver.
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI       9   // Image runs in the Windows CE subsystem.
#define IMAGE_SUBSYSTEM_EFI_APPLICATION      10  //
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  11   //
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER   12  //
#define IMAGE_SUBSYSTEM_EFI_ROM              13
#define IMAGE_SUBSYSTEM_XBOX                 14

// DllCharacteristics Entries

//      IMAGE_LIBRARY_PROCESS_INIT           0x0001     // Reserved.
//      IMAGE_LIBRARY_PROCESS_TERM           0x0002     // Reserved.
//      IMAGE_LIBRARY_THREAD_INIT            0x0004     // Reserved.
//      IMAGE_LIBRARY_THREAD_TERM            0x0008     // Reserved.
#define IMAGE_DLLcharACTERISTICS_NO_ISOLATION 0x0200    // Image understands isolation and doesn't want it
#define IMAGE_DLLcharACTERISTICS_NO_SEH      0x0400     // Image does not use SEH.  No SE handler may reside in this image
#define IMAGE_DLLcharACTERISTICS_NO_BIND     0x0800     // Do not bind this image.
//                                           0x1000     // Reserved.
#define IMAGE_DLLcharACTERISTICS_WDM_DRIVER  0x2000     // Driver uses WDM model
//                                           0x4000     // Reserved.
#define IMAGE_DLLcharACTERISTICS_TERMINAL_SERVER_AWARE     0x8000

// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

//
// Non-COFF Object file header
//

typedef struct ANON_OBJECT_HEADER {
	uint16_t    Sig1;            // Must be IMAGE_FILE_MACHINE_UNKNOWN
	uint16_t    Sig2;            // Must be 0xffff
	uint16_t    Version;         // >= 1 (implies the CLSID field is present)
	uint16_t    Machine;
	uint32_t   TimeDateStamp;
	CLSID   ClassID;         // Used to invoke CoCreateInstance
	uint32_t   SizeOfData;      // Size of data that follows the header
} ANON_OBJECT_HEADER;

//
// Section header format.
//

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
	uint8_t    Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		uint32_t   PhysicalAddress;
		uint32_t   VirtualSize;
	} Misc;
	uint32_t   VirtualAddress;
	uint32_t   SizeOfRawData;
	uint32_t   PointerToRawData;
	uint32_t   PointerToRelocations;
	uint32_t   PointerToLinenumbers;
	uint16_t    NumberOfRelocations;
	uint16_t    NumberOfLinenumbers;
	uint32_t   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER          40

//
// Section characteristics.
//
//      IMAGE_SCN_TYPE_REG                   0x00000000  // Reserved.
//      IMAGE_SCN_TYPE_DSECT                 0x00000001  // Reserved.
//      IMAGE_SCN_TYPE_NOLOAD                0x00000002  // Reserved.
//      IMAGE_SCN_TYPE_GROUP                 0x00000004  // Reserved.
#define IMAGE_SCN_TYPE_NO_PAD                0x00000008  // Reserved.
//      IMAGE_SCN_TYPE_COPY                  0x00000010  // Reserved.

#define IMAGE_SCN_CNT_CODE                   0x00000020  // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // Section contains uninitialized data.

#define IMAGE_SCN_LNK_OTHER                  0x00000100  // Reserved.
#define IMAGE_SCN_LNK_INFO                   0x00000200  // Section contains comments or some other type of information.
//      IMAGE_SCN_TYPE_OVER                  0x00000400  // Reserved.
#define IMAGE_SCN_LNK_REMOVE                 0x00000800  // Section contents will not become part of image.
#define IMAGE_SCN_LNK_COMDAT                 0x00001000  // Section contents comdat.
//                                           0x00002000  // Reserved.
//      IMAGE_SCN_MEM_PROTECTED - Obsolete   0x00004000
#define IMAGE_SCN_NO_DEFER_SPEC_EXC          0x00004000  // Reset speculative exceptions handling bits in the TLB entries for this section.
#define IMAGE_SCN_GPREL                      0x00008000  // Section content can be accessed relative to GP
#define IMAGE_SCN_MEM_FARDATA                0x00008000
//      IMAGE_SCN_MEM_SYSHEAP  - Obsolete    0x00010000
#define IMAGE_SCN_MEM_PURGEABLE              0x00020000
#define IMAGE_SCN_MEM_16BIT                  0x00020000
#define IMAGE_SCN_MEM_LOCKED                 0x00040000
#define IMAGE_SCN_MEM_PRELOAD                0x00080000

#define IMAGE_SCN_ALIGN_1uint8_tS               0x00100000  //
#define IMAGE_SCN_ALIGN_2uint8_tS               0x00200000  //
#define IMAGE_SCN_ALIGN_4uint8_tS               0x00300000  //
#define IMAGE_SCN_ALIGN_8uint8_tS               0x00400000  //
#define IMAGE_SCN_ALIGN_16uint8_tS              0x00500000  // Default alignment if no others are specified.
#define IMAGE_SCN_ALIGN_32uint8_tS              0x00600000  //
#define IMAGE_SCN_ALIGN_64uint8_tS              0x00700000  //
#define IMAGE_SCN_ALIGN_128uint8_tS             0x00800000  //
#define IMAGE_SCN_ALIGN_256uint8_tS             0x00900000  //
#define IMAGE_SCN_ALIGN_512uint8_tS             0x00A00000  //
#define IMAGE_SCN_ALIGN_1024uint8_tS            0x00B00000  //
#define IMAGE_SCN_ALIGN_2048uint8_tS            0x00C00000  //
#define IMAGE_SCN_ALIGN_4096uint8_tS            0x00D00000  //
#define IMAGE_SCN_ALIGN_8192uint8_tS            0x00E00000  //
// Unused                                    0x00F00000
#define IMAGE_SCN_ALIGN_MASK                 0x00F00000

#define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000  // Section contains extended relocations.
#define IMAGE_SCN_MEM_DISCARDABLE            0x02000000  // Section can be discarded.
#define IMAGE_SCN_MEM_NOT_CACHED             0x04000000  // Section is not cachable.
#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000  // Section is not pageable.
#define IMAGE_SCN_MEM_SHARED                 0x10000000  // Section is shareable.
#define IMAGE_SCN_MEM_EXECUTE                0x20000000  // Section is executable.
#define IMAGE_SCN_MEM_READ                   0x40000000  // Section is readable.
#define IMAGE_SCN_MEM_WRITE                  0x80000000  // Section is writeable.

//
// TLS Chaacteristic Flags
//
#define IMAGE_SCN_SCALE_INDEX                0x00000001  // Tls index is scaled

#ifndef _MAC
#include "pshpack2.h"                       // Symbols, relocs, and linenumbers are 2 uint8_t packed
#endif

//
// Symbol format.
//

typedef struct _IMAGE_SYMBOL {
	union {
		uint8_t    ShortName[8];
		struct {
			uint32_t   Short;     // if 0, use LongName
			uint32_t   Long;      // offset into string table
		} Name;
		uint32_t   LongName[2];    // Puint8_t [2]
	} N;
	uint32_t   Value;
	int16_t   SectionNumber;
	uint16_t    Type;
	uint8_t    StorageClass;
	uint8_t    NumberOfAuxSymbols;
} IMAGE_SYMBOL;
//typedef IMAGE_SYMBOL UNALIGNED *PIMAGE_SYMBOL;


#define IMAGE_SIZEOF_SYMBOL                  18

//
// Section values.
//
// Symbols have a section number of the section in which they are
// defined. Otherwise, section numbers have the following meanings:
//

#define IMAGE_SYM_UNDEFINED           (SHORT)0          // Symbol is undefined or is common.
#define IMAGE_SYM_ABSOLUTE            (SHORT)-1         // Symbol is an absolute value.
#define IMAGE_SYM_DEBUG               (SHORT)-2         // Symbol is a special debug item.
#define IMAGE_SYM_SECTION_MAX         0xFEFF            // Values 0xFF00-0xFFFF are special

//
// Type (fundamental) values.
//

#define IMAGE_SYM_TYPE_NULL                 0x0000  // no type.
#define IMAGE_SYM_TYPE_VOID                 0x0001  //
#define IMAGE_SYM_TYPE_char                 0x0002  // type character.
#define IMAGE_SYM_TYPE_SHORT                0x0003  // type short integer.
#define IMAGE_SYM_TYPE_INT                  0x0004  //
#define IMAGE_SYM_TYPE_LONG                 0x0005  //
#define IMAGE_SYM_TYPE_FLOAT                0x0006  //
#define IMAGE_SYM_TYPE_DOUBLE               0x0007  //
#define IMAGE_SYM_TYPE_STRUCT               0x0008  //
#define IMAGE_SYM_TYPE_UNION                0x0009  //
#define IMAGE_SYM_TYPE_ENUM                 0x000A  // enumeration.
#define IMAGE_SYM_TYPE_MOE                  0x000B  // member of enumeration.
#define IMAGE_SYM_TYPE_uint8_t                 0x000C  //
#define IMAGE_SYM_TYPE_uint16_t                 0x000D  //
#define IMAGE_SYM_TYPE_UINT                 0x000E  //
#define IMAGE_SYM_TYPE_uint32_t                0x000F  //
#define IMAGE_SYM_TYPE_PCODE                0x8000  //
//
// Type (derived) values.
//

#define IMAGE_SYM_DTYPE_NULL                0       // no derived type.
#define IMAGE_SYM_DTYPE_POINTER             1       // pointer.
#define IMAGE_SYM_DTYPE_FUNCTION            2       // function.
#define IMAGE_SYM_DTYPE_ARRAY               3       // array.

//
// Storage classes.
//
#define IMAGE_SYM_CLASS_END_OF_FUNCTION     (uint8_t )-1
#define IMAGE_SYM_CLASS_NULL                0x0000
#define IMAGE_SYM_CLASS_AUTOMATIC           0x0001
#define IMAGE_SYM_CLASS_EXTERNAL            0x0002
#define IMAGE_SYM_CLASS_STATIC              0x0003
#define IMAGE_SYM_CLASS_REGISTER            0x0004
#define IMAGE_SYM_CLASS_EXTERNAL_DEF        0x0005
#define IMAGE_SYM_CLASS_LABEL               0x0006
#define IMAGE_SYM_CLASS_UNDEFINED_LABEL     0x0007
#define IMAGE_SYM_CLASS_MEMBER_OF_STRUCT    0x0008
#define IMAGE_SYM_CLASS_ARGUMENT            0x0009
#define IMAGE_SYM_CLASS_STRUCT_TAG          0x000A
#define IMAGE_SYM_CLASS_MEMBER_OF_UNION     0x000B
#define IMAGE_SYM_CLASS_UNION_TAG           0x000C
#define IMAGE_SYM_CLASS_TYPE_DEFINITION     0x000D
#define IMAGE_SYM_CLASS_UNDEFINED_STATIC    0x000E
#define IMAGE_SYM_CLASS_ENUM_TAG            0x000F
#define IMAGE_SYM_CLASS_MEMBER_OF_ENUM      0x0010
#define IMAGE_SYM_CLASS_REGISTER_PARAM      0x0011
#define IMAGE_SYM_CLASS_BIT_FIELD           0x0012

#define IMAGE_SYM_CLASS_FAR_EXTERNAL        0x0044  //

#define IMAGE_SYM_CLASS_BLOCK               0x0064
#define IMAGE_SYM_CLASS_FUNCTION            0x0065
#define IMAGE_SYM_CLASS_END_OF_STRUCT       0x0066
#define IMAGE_SYM_CLASS_FILE                0x0067
// new
#define IMAGE_SYM_CLASS_SECTION             0x0068
#define IMAGE_SYM_CLASS_WEAK_EXTERNAL       0x0069

#define IMAGE_SYM_CLASS_CLR_TOKEN           0x006B

// type packing constants

#define N_BTMASK                            0x000F
#define N_TMASK                             0x0030
#define N_TMASK1                            0x00C0
#define N_TMASK2                            0x00F0
#define N_BTSHFT                            4
#define N_TSHIFT                            2
// MACROS

// Basic Type of  x
#define BTYPE(x) ((x) & N_BTMASK)

// Is x a pointer?
#ifndef ISPTR
#define ISPTR(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_POINTER << N_BTSHFT))
#endif

// Is x a function?
#ifndef ISFCN
#define ISFCN(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_FUNCTION << N_BTSHFT))
#endif

// Is x an array?

#ifndef ISARY
#define ISARY(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_ARRAY << N_BTSHFT))
#endif

// Is x a structure, union, or enumeration TAG?
#ifndef ISTAG
#define ISTAG(x) ((x)==IMAGE_SYM_CLASS_STRUCT_TAG || (x)==IMAGE_SYM_CLASS_UNION_TAG || (x)==IMAGE_SYM_CLASS_ENUM_TAG)
#endif

#ifndef INCREF
#define INCREF(x) ((((x)&~N_BTMASK)<<N_TSHIFT)|(IMAGE_SYM_DTYPE_POINTER<<N_BTSHFT)|((x)&N_BTMASK))
#endif
#ifndef DECREF
#define DECREF(x) ((((x)>>N_TSHIFT)&~N_BTMASK)|((x)&N_BTMASK))
#endif

//
// Auxiliary entry format.
//

typedef union _IMAGE_AUX_SYMBOL {
	struct {
		uint32_t    TagIndex;                      // struct, union, or enum tag index
		union {
			struct {
				uint16_t    Linenumber;             // declaration line number
				uint16_t    Size;                   // size of struct, union, or enum
			} LnSz;
			uint32_t    TotalSize;
		} Misc;
		union {
			struct {                            // if ISFCN, tag, or .bb
				uint32_t    PointerToLinenumber;
				uint32_t    PointerToNextFunction;
			} Function;
			struct {                            // if ISARY, up to 4 dimen.
				uint16_t     Dimension[4];
			} Array;
		} FcnAry;
		uint16_t    TvIndex;                        // tv index
	} Sym;
	struct {
		uint8_t    Name[IMAGE_SIZEOF_SYMBOL];
	} File;
	struct {
		uint32_t   Length;                         // section length
		uint16_t    NumberOfRelocations;            // number of relocation entries
		uint16_t    NumberOfLinenumbers;            // number of line numbers
		uint32_t   CheckSum;                       // checksum for communal
		int16_t   Number;                         // section number to associate with
		uint8_t    Selection;                      // communal selection type
	} Section;
} IMAGE_AUX_SYMBOL;
//typedef IMAGE_AUX_SYMBOL UNALIGNED *PIMAGE_AUX_SYMBOL;

#define IMAGE_SIZEOF_AUX_SYMBOL             18

typedef enum IMAGE_AUX_SYMBOL_TYPE {
	IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF = 1,
} IMAGE_AUX_SYMBOL_TYPE;

#include "pshpack2.h"

typedef struct IMAGE_AUX_SYMBOL_TOKEN_DEF {
	uint8_t  bAuxType;                  // IMAGE_AUX_SYMBOL_TYPE
	uint8_t  bReserved;                 // Must be 0
	uint32_t SymbolTableIndex;
	uint8_t  rgbReserved[12];           // Must be 0
} IMAGE_AUX_SYMBOL_TOKEN_DEF;

//typedef IMAGE_AUX_SYMBOL_TOKEN_DEF UNALIGNED *PIMAGE_AUX_SYMBOL_TOKEN_DEF;

#include "poppack.h"

//
// Communal selection types.
//

#define IMAGE_COMDAT_SELECT_NODUPLICATES    1
#define IMAGE_COMDAT_SELECT_ANY             2
#define IMAGE_COMDAT_SELECT_SAME_SIZE       3
#define IMAGE_COMDAT_SELECT_EXACT_MATCH     4
#define IMAGE_COMDAT_SELECT_ASSOCIATIVE     5
#define IMAGE_COMDAT_SELECT_LARGEST         6
#define IMAGE_COMDAT_SELECT_NEWEST          7

#define IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY  1
#define IMAGE_WEAK_EXTERN_SEARCH_LIBRARY    2
#define IMAGE_WEAK_EXTERN_SEARCH_ALIAS      3

//
// Relocation format.
//

typedef struct _IMAGE_RELOCATION {
	union {
		uint32_t   VirtualAddress;
		uint32_t   RelocCount;             // Set to the real count when IMAGE_SCN_LNK_NRELOC_OVFL is set
	};
	uint32_t   SymbolTableIndex;
	uint16_t    Type;
} IMAGE_RELOCATION;
//typedef IMAGE_RELOCATION UNALIGNED *PIMAGE_RELOCATION;

#define IMAGE_SIZEOF_RELOCATION         10

//
// I386 relocation types.
//
#define IMAGE_REL_I386_ABSOLUTE         0x0000  // Reference is absolute, no relocation is necessary
#define IMAGE_REL_I386_DIR16            0x0001  // Direct 16-bit reference to the symbols virtual address
#define IMAGE_REL_I386_REL16            0x0002  // PC-relative 16-bit reference to the symbols virtual address
#define IMAGE_REL_I386_DIR32            0x0006  // Direct 32-bit reference to the symbols virtual address
#define IMAGE_REL_I386_DIR32NB          0x0007  // Direct 32-bit reference to the symbols virtual address, base not included
#define IMAGE_REL_I386_SEG12            0x0009  // Direct 16-bit reference to the segment-selector bits of a 32-bit virtual address
#define IMAGE_REL_I386_SECTION          0x000A
#define IMAGE_REL_I386_SECREL           0x000B
#define IMAGE_REL_I386_TOKEN            0x000C  // clr token
#define IMAGE_REL_I386_SECREL7          0x000D  // 7 bit offset from base of section containing target
#define IMAGE_REL_I386_REL32            0x0014  // PC-relative 32-bit reference to the symbols virtual address

//
// MIPS relocation types.
//
#define IMAGE_REL_MIPS_ABSOLUTE         0x0000  // Reference is absolute, no relocation is necessary
#define IMAGE_REL_MIPS_REFHALF          0x0001
#define IMAGE_REL_MIPS_REFuint16_t          0x0002
#define IMAGE_REL_MIPS_JMPADDR          0x0003
#define IMAGE_REL_MIPS_REFHI            0x0004
#define IMAGE_REL_MIPS_REFLO            0x0005
#define IMAGE_REL_MIPS_GPREL            0x0006
#define IMAGE_REL_MIPS_LITERAL          0x0007
#define IMAGE_REL_MIPS_SECTION          0x000A
#define IMAGE_REL_MIPS_SECREL           0x000B
#define IMAGE_REL_MIPS_SECRELLO         0x000C  // Low 16-bit section relative referemce (used for >32k TLS)
#define IMAGE_REL_MIPS_SECRELHI         0x000D  // High 16-bit section relative reference (used for >32k TLS)
#define IMAGE_REL_MIPS_TOKEN            0x000E  // clr token
#define IMAGE_REL_MIPS_JMPADDR16        0x0010
#define IMAGE_REL_MIPS_REFuint16_tNB        0x0022
#define IMAGE_REL_MIPS_PAIR             0x0025

//
// Alpha Relocation types.
//
#define IMAGE_REL_ALPHA_ABSOLUTE        0x0000
#define IMAGE_REL_ALPHA_REFLONG         0x0001
#define IMAGE_REL_ALPHA_REFQUAD         0x0002
#define IMAGE_REL_ALPHA_GPREL32         0x0003
#define IMAGE_REL_ALPHA_LITERAL         0x0004
#define IMAGE_REL_ALPHA_LITUSE          0x0005
#define IMAGE_REL_ALPHA_GPDISP          0x0006
#define IMAGE_REL_ALPHA_BRADDR          0x0007
#define IMAGE_REL_ALPHA_HINT            0x0008
#define IMAGE_REL_ALPHA_INLINE_REFLONG  0x0009
#define IMAGE_REL_ALPHA_REFHI           0x000A
#define IMAGE_REL_ALPHA_REFLO           0x000B
#define IMAGE_REL_ALPHA_PAIR            0x000C
#define IMAGE_REL_ALPHA_MATCH           0x000D
#define IMAGE_REL_ALPHA_SECTION         0x000E
#define IMAGE_REL_ALPHA_SECREL          0x000F
#define IMAGE_REL_ALPHA_REFLONGNB       0x0010
#define IMAGE_REL_ALPHA_SECRELLO        0x0011  // Low 16-bit section relative reference
#define IMAGE_REL_ALPHA_SECRELHI        0x0012  // High 16-bit section relative reference
#define IMAGE_REL_ALPHA_REFQ3           0x0013  // High 16 bits of 48 bit reference
#define IMAGE_REL_ALPHA_REFQ2           0x0014  // Middle 16 bits of 48 bit reference
#define IMAGE_REL_ALPHA_REFQ1           0x0015  // Low 16 bits of 48 bit reference
#define IMAGE_REL_ALPHA_GPRELLO         0x0016  // Low 16-bit GP relative reference
#define IMAGE_REL_ALPHA_GPRELHI         0x0017  // High 16-bit GP relative reference

//
// IBM PowerPC relocation types.
//
#define IMAGE_REL_PPC_ABSOLUTE          0x0000  // NOP
#define IMAGE_REL_PPC_ADDR64            0x0001  // 64-bit address
#define IMAGE_REL_PPC_ADDR32            0x0002  // 32-bit address
#define IMAGE_REL_PPC_ADDR24            0x0003  // 26-bit address, shifted left 2 (branch absolute)
#define IMAGE_REL_PPC_ADDR16            0x0004  // 16-bit address
#define IMAGE_REL_PPC_ADDR14            0x0005  // 16-bit address, shifted left 2 (load doubleuint16_t)
#define IMAGE_REL_PPC_REL24             0x0006  // 26-bit PC-relative offset, shifted left 2 (branch relative)
#define IMAGE_REL_PPC_REL14             0x0007  // 16-bit PC-relative offset, shifted left 2 (br cond relative)
#define IMAGE_REL_PPC_TOCREL16          0x0008  // 16-bit offset from TOC base
#define IMAGE_REL_PPC_TOCREL14          0x0009  // 16-bit offset from TOC base, shifted left 2 (load doubleuint16_t)

#define IMAGE_REL_PPC_ADDR32NB          0x000A  // 32-bit addr w/o image base
#define IMAGE_REL_PPC_SECREL            0x000B  // va of containing section (as in an image sectionhdr)
#define IMAGE_REL_PPC_SECTION           0x000C  // sectionheader number
#define IMAGE_REL_PPC_IFGLUE            0x000D  // substitute TOC restore instruction iff symbol is glue code
#define IMAGE_REL_PPC_IMGLUE            0x000E  // symbol is glue code; virtual address is TOC restore instruction
#define IMAGE_REL_PPC_SECREL16          0x000F  // va of containing section (limited to 16 bits)
#define IMAGE_REL_PPC_REFHI             0x0010
#define IMAGE_REL_PPC_REFLO             0x0011
#define IMAGE_REL_PPC_PAIR              0x0012
#define IMAGE_REL_PPC_SECRELLO          0x0013  // Low 16-bit section relative reference (used for >32k TLS)
#define IMAGE_REL_PPC_SECRELHI          0x0014  // High 16-bit section relative reference (used for >32k TLS)
#define IMAGE_REL_PPC_GPREL             0x0015
#define IMAGE_REL_PPC_TOKEN             0x0016  // clr token

#define IMAGE_REL_PPC_TYPEMASK          0x00FF  // mask to isolate above values in IMAGE_RELOCATION.Type

// Flag bits in IMAGE_RELOCATION.TYPE

#define IMAGE_REL_PPC_NEG               0x0100  // subtract reloc value rather than adding it
#define IMAGE_REL_PPC_BRTAKEN           0x0200  // fix branch prediction bit to predict branch taken
#define IMAGE_REL_PPC_BRNTAKEN          0x0400  // fix branch prediction bit to predict branch not taken
#define IMAGE_REL_PPC_TOCDEFN           0x0800  // toc slot defined in file (or, data in toc)

//
// Hitachi SH3 relocation types.
//
#define IMAGE_REL_SH3_ABSOLUTE          0x0000  // No relocation
#define IMAGE_REL_SH3_DIRECT16          0x0001  // 16 bit direct
#define IMAGE_REL_SH3_DIRECT32          0x0002  // 32 bit direct
#define IMAGE_REL_SH3_DIRECT8           0x0003  // 8 bit direct, -128..255
#define IMAGE_REL_SH3_DIRECT8_uint16_t      0x0004  // 8 bit direct .W (0 ext.)
#define IMAGE_REL_SH3_DIRECT8_LONG      0x0005  // 8 bit direct .L (0 ext.)
#define IMAGE_REL_SH3_DIRECT4           0x0006  // 4 bit direct (0 ext.)
#define IMAGE_REL_SH3_DIRECT4_uint16_t      0x0007  // 4 bit direct .W (0 ext.)
#define IMAGE_REL_SH3_DIRECT4_LONG      0x0008  // 4 bit direct .L (0 ext.)
#define IMAGE_REL_SH3_PCREL8_uint16_t       0x0009  // 8 bit PC relative .W
#define IMAGE_REL_SH3_PCREL8_LONG       0x000A  // 8 bit PC relative .L
#define IMAGE_REL_SH3_PCREL12_uint16_t      0x000B  // 12 LSB PC relative .W
#define IMAGE_REL_SH3_STARTOF_SECTION   0x000C  // Start of EXE section
#define IMAGE_REL_SH3_SIZEOF_SECTION    0x000D  // Size of EXE section
#define IMAGE_REL_SH3_SECTION           0x000E  // Section table index
#define IMAGE_REL_SH3_SECREL            0x000F  // Offset within section
#define IMAGE_REL_SH3_DIRECT32_NB       0x0010  // 32 bit direct not based
#define IMAGE_REL_SH3_GPREL4_LONG       0x0011  // GP-relative addressing
#define IMAGE_REL_SH3_TOKEN             0x0012  // clr token

#define IMAGE_REL_ARM_ABSOLUTE          0x0000  // No relocation required
#define IMAGE_REL_ARM_ADDR32            0x0001  // 32 bit address
#define IMAGE_REL_ARM_ADDR32NB          0x0002  // 32 bit address w/o image base
#define IMAGE_REL_ARM_BRANCH24          0x0003  // 24 bit offset << 2 & sign ext.
#define IMAGE_REL_ARM_BRANCH11          0x0004  // Thumb: 2 11 bit offsets
#define IMAGE_REL_ARM_TOKEN             0x0005  // clr token
#define IMAGE_REL_ARM_GPREL12           0x0006  // GP-relative addressing (ARM)
#define IMAGE_REL_ARM_GPREL7            0x0007  // GP-relative addressing (Thumb)
#define IMAGE_REL_ARM_BLX24             0x0008
#define IMAGE_REL_ARM_BLX11             0x0009
#define IMAGE_REL_ARM_SECTION           0x000E  // Section table index
#define IMAGE_REL_ARM_SECREL            0x000F  // Offset within section

#define IMAGE_REL_AM_ABSOLUTE           0x0000
#define IMAGE_REL_AM_ADDR32             0x0001
#define IMAGE_REL_AM_ADDR32NB           0x0002
#define IMAGE_REL_AM_CALL32             0x0003
#define IMAGE_REL_AM_FUNCINFO           0x0004
#define IMAGE_REL_AM_REL32_1            0x0005
#define IMAGE_REL_AM_REL32_2            0x0006
#define IMAGE_REL_AM_SECREL             0x0007
#define IMAGE_REL_AM_SECTION            0x0008
#define IMAGE_REL_AM_TOKEN              0x0009

//
// x64 relocations
//
#define IMAGE_REL_AMD64_ABSOLUTE        0x0000  // Reference is absolute, no relocation is necessary
#define IMAGE_REL_AMD64_ADDR64          0x0001  // 64-bit address (VA).
#define IMAGE_REL_AMD64_ADDR32          0x0002  // 32-bit address (VA).
#define IMAGE_REL_AMD64_ADDR32NB        0x0003  // 32-bit address w/o image base (RVA).
#define IMAGE_REL_AMD64_REL32           0x0004  // 32-bit relative address from uint8_t following reloc
#define IMAGE_REL_AMD64_REL32_1         0x0005  // 32-bit relative address from uint8_t distance 1 from reloc
#define IMAGE_REL_AMD64_REL32_2         0x0006  // 32-bit relative address from uint8_t distance 2 from reloc
#define IMAGE_REL_AMD64_REL32_3         0x0007  // 32-bit relative address from uint8_t distance 3 from reloc
#define IMAGE_REL_AMD64_REL32_4         0x0008  // 32-bit relative address from uint8_t distance 4 from reloc
#define IMAGE_REL_AMD64_REL32_5         0x0009  // 32-bit relative address from uint8_t distance 5 from reloc
#define IMAGE_REL_AMD64_SECTION         0x000A  // Section index
#define IMAGE_REL_AMD64_SECREL          0x000B  // 32 bit offset from base of section containing target
#define IMAGE_REL_AMD64_SECREL7         0x000C  // 7 bit unsigned offset from base of section containing target
#define IMAGE_REL_AMD64_TOKEN           0x000D  // 32 bit metadata token
#define IMAGE_REL_AMD64_SREL32          0x000E  // 32 bit signed span-dependent value emitted into object
#define IMAGE_REL_AMD64_PAIR            0x000F
#define IMAGE_REL_AMD64_SSPAN32         0x0010  // 32 bit signed span-dependent value applied at link time

//
// IA64 relocation types.
//
#define IMAGE_REL_IA64_ABSOLUTE         0x0000
#define IMAGE_REL_IA64_IMM14            0x0001
#define IMAGE_REL_IA64_IMM22            0x0002
#define IMAGE_REL_IA64_IMM64            0x0003
#define IMAGE_REL_IA64_DIR32            0x0004
#define IMAGE_REL_IA64_DIR64            0x0005
#define IMAGE_REL_IA64_PCREL21B         0x0006
#define IMAGE_REL_IA64_PCREL21M         0x0007
#define IMAGE_REL_IA64_PCREL21F         0x0008
#define IMAGE_REL_IA64_GPREL22          0x0009
#define IMAGE_REL_IA64_LTOFF22          0x000A
#define IMAGE_REL_IA64_SECTION          0x000B
#define IMAGE_REL_IA64_SECREL22         0x000C
#define IMAGE_REL_IA64_SECREL64I        0x000D
#define IMAGE_REL_IA64_SECREL32         0x000E
// 
#define IMAGE_REL_IA64_DIR32NB          0x0010
#define IMAGE_REL_IA64_SREL14           0x0011
#define IMAGE_REL_IA64_SREL22           0x0012
#define IMAGE_REL_IA64_SREL32           0x0013
#define IMAGE_REL_IA64_UREL32           0x0014
#define IMAGE_REL_IA64_PCREL60X         0x0015  // This is always a BRL and never converted
#define IMAGE_REL_IA64_PCREL60B         0x0016  // If possible, convert to MBB bundle with NOP.B in slot 1
#define IMAGE_REL_IA64_PCREL60F         0x0017  // If possible, convert to MFB bundle with NOP.F in slot 1
#define IMAGE_REL_IA64_PCREL60I         0x0018  // If possible, convert to MIB bundle with NOP.I in slot 1
#define IMAGE_REL_IA64_PCREL60M         0x0019  // If possible, convert to MMB bundle with NOP.M in slot 1
#define IMAGE_REL_IA64_IMMGPREL64       0x001A
#define IMAGE_REL_IA64_TOKEN            0x001B  // clr token
#define IMAGE_REL_IA64_GPREL32          0x001C
#define IMAGE_REL_IA64_ADDEND           0x001F

//
// CEF relocation types.
//
#define IMAGE_REL_CEF_ABSOLUTE          0x0000  // Reference is absolute, no relocation is necessary
#define IMAGE_REL_CEF_ADDR32            0x0001  // 32-bit address (VA).
#define IMAGE_REL_CEF_ADDR64            0x0002  // 64-bit address (VA).
#define IMAGE_REL_CEF_ADDR32NB          0x0003  // 32-bit address w/o image base (RVA).
#define IMAGE_REL_CEF_SECTION           0x0004  // Section index
#define IMAGE_REL_CEF_SECREL            0x0005  // 32 bit offset from base of section containing target
#define IMAGE_REL_CEF_TOKEN             0x0006  // 32 bit metadata token

//
// clr relocation types.
//
#define IMAGE_REL_CEE_ABSOLUTE          0x0000  // Reference is absolute, no relocation is necessary
#define IMAGE_REL_CEE_ADDR32            0x0001  // 32-bit address (VA).
#define IMAGE_REL_CEE_ADDR64            0x0002  // 64-bit address (VA).
#define IMAGE_REL_CEE_ADDR32NB          0x0003  // 32-bit address w/o image base (RVA).
#define IMAGE_REL_CEE_SECTION           0x0004  // Section index
#define IMAGE_REL_CEE_SECREL            0x0005  // 32 bit offset from base of section containing target
#define IMAGE_REL_CEE_TOKEN             0x0006  // 32 bit metadata token


#define IMAGE_REL_M32R_ABSOLUTE       0x0000   // No relocation required
#define IMAGE_REL_M32R_ADDR32         0x0001   // 32 bit address
#define IMAGE_REL_M32R_ADDR32NB       0x0002   // 32 bit address w/o image base
#define IMAGE_REL_M32R_ADDR24         0x0003   // 24 bit address
#define IMAGE_REL_M32R_GPREL16        0x0004   // GP relative addressing
#define IMAGE_REL_M32R_PCREL24        0x0005   // 24 bit offset << 2 & sign ext.
#define IMAGE_REL_M32R_PCREL16        0x0006   // 16 bit offset << 2 & sign ext.
#define IMAGE_REL_M32R_PCREL8         0x0007   // 8 bit offset << 2 & sign ext.
#define IMAGE_REL_M32R_REFHALF        0x0008   // 16 MSBs
#define IMAGE_REL_M32R_REFHI          0x0009   // 16 MSBs; adj for LSB sign ext.
#define IMAGE_REL_M32R_REFLO          0x000A   // 16 LSBs
#define IMAGE_REL_M32R_PAIR           0x000B   // Link HI and LO
#define IMAGE_REL_M32R_SECTION        0x000C   // Section table index
#define IMAGE_REL_M32R_SECREL32       0x000D   // 32 bit section relative reference
#define IMAGE_REL_M32R_TOKEN          0x000E   // clr token


#define EXT_IMM64(Value, Address, Size, InstPos, ValPos)  /* Intel-IA64-Filler */           \
	Value |= (((uint64_t)((*(Address) >> InstPos) & (((uint64_t)1 << Size) - 1))) << ValPos)  // Intel-IA64-Filler

#define INS_IMM64(Value, Address, Size, InstPos, ValPos)  /* Intel-IA64-Filler */\
	*(Puint32_t)Address = (*(Puint32_t)Address & ~(((1 << Size) - 1) << InstPos)) | /* Intel-IA64-Filler */\
	((uint32_t)((((uint64_t)Value >> ValPos) & (((uint64_t)1 << Size) - 1))) << InstPos)  // Intel-IA64-Filler

#define EMARCH_ENC_I17_IMM7B_INST_uint16_t_X         3  // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM7B_SIZE_X              7  // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM7B_INST_uint16_t_POS_X     4  // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM7B_VAL_POS_X           0  // Intel-IA64-Filler

#define EMARCH_ENC_I17_IMM9D_INST_uint16_t_X         3  // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM9D_SIZE_X              9  // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM9D_INST_uint16_t_POS_X     18 // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM9D_VAL_POS_X           7  // Intel-IA64-Filler

#define EMARCH_ENC_I17_IMM5C_INST_uint16_t_X         3  // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM5C_SIZE_X              5  // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM5C_INST_uint16_t_POS_X     13 // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM5C_VAL_POS_X           16 // Intel-IA64-Filler

#define EMARCH_ENC_I17_IC_INST_uint16_t_X            3  // Intel-IA64-Filler
#define EMARCH_ENC_I17_IC_SIZE_X                 1  // Intel-IA64-Filler
#define EMARCH_ENC_I17_IC_INST_uint16_t_POS_X        12 // Intel-IA64-Filler
#define EMARCH_ENC_I17_IC_VAL_POS_X              21 // Intel-IA64-Filler

#define EMARCH_ENC_I17_IMM41a_INST_uint16_t_X        1  // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41a_SIZE_X             10 // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41a_INST_uint16_t_POS_X    14 // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41a_VAL_POS_X          22 // Intel-IA64-Filler

#define EMARCH_ENC_I17_IMM41b_INST_uint16_t_X        1  // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41b_SIZE_X             8  // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41b_INST_uint16_t_POS_X    24 // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41b_VAL_POS_X          32 // Intel-IA64-Filler

#define EMARCH_ENC_I17_IMM41c_INST_uint16_t_X        2  // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41c_SIZE_X             23 // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41c_INST_uint16_t_POS_X    0  // Intel-IA64-Filler
#define EMARCH_ENC_I17_IMM41c_VAL_POS_X          40 // Intel-IA64-Filler

#define EMARCH_ENC_I17_SIGN_INST_uint16_t_X          3  // Intel-IA64-Filler
#define EMARCH_ENC_I17_SIGN_SIZE_X               1  // Intel-IA64-Filler
#define EMARCH_ENC_I17_SIGN_INST_uint16_t_POS_X      27 // Intel-IA64-Filler
#define EMARCH_ENC_I17_SIGN_VAL_POS_X            63 // Intel-IA64-Filler

#define X3_OPCODE_INST_uint16_t_X                    3  // Intel-IA64-Filler
#define X3_OPCODE_SIZE_X                         4  // Intel-IA64-Filler
#define X3_OPCODE_INST_uint16_t_POS_X                28 // Intel-IA64-Filler
#define X3_OPCODE_SIGN_VAL_POS_X                 0  // Intel-IA64-Filler

#define X3_I_INST_uint16_t_X                         3  // Intel-IA64-Filler
#define X3_I_SIZE_X                              1  // Intel-IA64-Filler
#define X3_I_INST_uint16_t_POS_X                     27 // Intel-IA64-Filler
#define X3_I_SIGN_VAL_POS_X                      59 // Intel-IA64-Filler

#define X3_D_WH_INST_uint16_t_X                      3  // Intel-IA64-Filler
#define X3_D_WH_SIZE_X                           3  // Intel-IA64-Filler
#define X3_D_WH_INST_uint16_t_POS_X                  24 // Intel-IA64-Filler
#define X3_D_WH_SIGN_VAL_POS_X                   0  // Intel-IA64-Filler

#define X3_IMM20_INST_uint16_t_X                     3  // Intel-IA64-Filler
#define X3_IMM20_SIZE_X                          20 // Intel-IA64-Filler
#define X3_IMM20_INST_uint16_t_POS_X                 4  // Intel-IA64-Filler
#define X3_IMM20_SIGN_VAL_POS_X                  0  // Intel-IA64-Filler

#define X3_IMM39_1_INST_uint16_t_X                   2  // Intel-IA64-Filler
#define X3_IMM39_1_SIZE_X                        23 // Intel-IA64-Filler
#define X3_IMM39_1_INST_uint16_t_POS_X               0  // Intel-IA64-Filler
#define X3_IMM39_1_SIGN_VAL_POS_X                36 // Intel-IA64-Filler

#define X3_IMM39_2_INST_uint16_t_X                   1  // Intel-IA64-Filler
#define X3_IMM39_2_SIZE_X                        16 // Intel-IA64-Filler
#define X3_IMM39_2_INST_uint16_t_POS_X               16 // Intel-IA64-Filler
#define X3_IMM39_2_SIGN_VAL_POS_X                20 // Intel-IA64-Filler

#define X3_P_INST_uint16_t_X                         3  // Intel-IA64-Filler
#define X3_P_SIZE_X                              4  // Intel-IA64-Filler
#define X3_P_INST_uint16_t_POS_X                     0  // Intel-IA64-Filler
#define X3_P_SIGN_VAL_POS_X                      0  // Intel-IA64-Filler

#define X3_TMPLT_INST_uint16_t_X                     0  // Intel-IA64-Filler
#define X3_TMPLT_SIZE_X                          4  // Intel-IA64-Filler
#define X3_TMPLT_INST_uint16_t_POS_X                 0  // Intel-IA64-Filler
#define X3_TMPLT_SIGN_VAL_POS_X                  0  // Intel-IA64-Filler

#define X3_BTYPE_QP_INST_uint16_t_X                  2  // Intel-IA64-Filler
#define X3_BTYPE_QP_SIZE_X                       9  // Intel-IA64-Filler
#define X3_BTYPE_QP_INST_uint16_t_POS_X              23 // Intel-IA64-Filler
#define X3_BTYPE_QP_INST_VAL_POS_X               0  // Intel-IA64-Filler

#define X3_EMPTY_INST_uint16_t_X                     1  // Intel-IA64-Filler
#define X3_EMPTY_SIZE_X                          2  // Intel-IA64-Filler
#define X3_EMPTY_INST_uint16_t_POS_X                 14 // Intel-IA64-Filler
#define X3_EMPTY_INST_VAL_POS_X                  0  // Intel-IA64-Filler

//
// Line number format.
//

typedef struct _IMAGE_LINENUMBER {
	union {
		uint32_t   SymbolTableIndex;               // Symbol table index of function name if Linenumber is 0.
		uint32_t   VirtualAddress;                 // Virtual address of line number.
	} Type;
	uint16_t    Linenumber;                         // Line number.
} IMAGE_LINENUMBER;
//typedef IMAGE_LINENUMBER UNALIGNED *PIMAGE_LINENUMBER;

#define IMAGE_SIZEOF_LINENUMBER              6

#ifndef _MAC
#include "poppack.h"                        // Back to 4 uint8_t packing
#endif

//
// Based relocation format.
//

typedef struct _IMAGE_BASE_RELOCATION {
	uint32_t   VirtualAddress;
	uint32_t   SizeOfBlock;
	//  uint16_t    TypeOffset[1];
} IMAGE_BASE_RELOCATION;
//typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;

#define IMAGE_SIZEOF_BASE_RELOCATION         8

//
// Based relocation types.
//

#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3
#define IMAGE_REL_BASED_HIGHADJ               4
#define IMAGE_REL_BASED_MIPS_JMPADDR          5
#define IMAGE_REL_BASED_MIPS_JMPADDR16        9
#define IMAGE_REL_BASED_IA64_IMM64            9
#define IMAGE_REL_BASED_DIR64                 10


//
// Archive format.
//

#define IMAGE_ARCHIVE_START_SIZE             8
#define IMAGE_ARCHIVE_START                  "!<arch>\n"
#define IMAGE_ARCHIVE_END                    "`\n"
#define IMAGE_ARCHIVE_PAD                    "\n"
#define IMAGE_ARCHIVE_LINKER_MEMBER          "/               "
#define IMAGE_ARCHIVE_LONGNAMES_MEMBER       "//              "

typedef struct _IMAGE_ARCHIVE_MEMBER_HEADER {
	uint8_t     Name[16];                          // File member name - `/' terminated.
	uint8_t     Date[12];                          // File member date - decimal.
	uint8_t     UserID[6];                         // File member user id - decimal.
	uint8_t     GroupID[6];                        // File member group id - decimal.
	uint8_t     Mode[8];                           // File member mode - octal.
	uint8_t     Size[10];                          // File member size - decimal.
	uint8_t     EndHeader[2];                      // String to end header.
} IMAGE_ARCHIVE_MEMBER_HEADER, *PIMAGE_ARCHIVE_MEMBER_HEADER;

#define IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR      60

//
// DLL support.
//

//
// Export Format
//

typedef struct _IMAGE_EXPORT_DIRECTORY {
	uint32_t   Characteristics;
	uint32_t   TimeDateStamp;
	uint16_t    MajorVersion;
	uint16_t    MinorVersion;
	uint32_t   Name;
	uint32_t   Base;
	uint32_t   NumberOfFunctions;
	uint32_t   NumberOfNames;
	uint32_t   AddressOfFunctions;     // RVA from base of image
	uint32_t   AddressOfNames;         // RVA from base of image
	uint32_t   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;


//
// Import Format
//

typedef struct _IMAGE_IMPORT_BY_NAME {
	uint16_t    Hint;
	uint8_t    Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

//#include "pshpack8.h"                       // Use align 8 for the 64-bit IAT.
#pragma pack(push, 8)
typedef struct _IMAGE_THUNK_DATA64 {
	union {
		uint64_t ForwarderString;  // Puint8_t 
		uint64_t Function;         // Puint32_t
		uint64_t Ordinal;
		uint64_t AddressOfData;    // PIMAGE_IMPORT_BY_NAME
	} u1;
} IMAGE_THUNK_DATA64;
//typedef IMAGE_THUNK_DATA64 * PIMAGE_THUNK_DATA64;



#pragma pack(pop)                        // Back to 4 uint8_t packing

typedef struct _IMAGE_THUNK_DATA32 {
	union {
		uint32_t ForwarderString;      // Puint8_t 
		uint32_t Function;             // Puint32_t
		uint32_t Ordinal;
		uint32_t AddressOfData;        // PIMAGE_IMPORT_BY_NAME
	} u1;
} IMAGE_THUNK_DATA32;
//typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)

//
// Thread Local Storage
//

typedef void
(/*NTAPI*/ *PIMAGE_TLS_CALLBACK) (
			      void* DllHandle,
			      uint32_t Reason,
			      void* Reserved
			      );

typedef struct _IMAGE_TLS_DIRECTORY64 {
	uint64_t   StartAddressOfRawData;
	uint64_t   EndAddressOfRawData;
	uint64_t   AddressOfIndex;         // Puint32_t
	uint64_t   AddressOfCallBacks;     // PIMAGE_TLS_CALLBACK *;
	uint32_t   SizeOfZeroFill;
	uint32_t   Characteristics;
} IMAGE_TLS_DIRECTORY64;
//typedef IMAGE_TLS_DIRECTORY64 * PIMAGE_TLS_DIRECTORY64;

typedef struct _IMAGE_TLS_DIRECTORY32 {
	uint32_t   StartAddressOfRawData;
	uint32_t   EndAddressOfRawData;
	uint32_t   AddressOfIndex;             // Puint32_t
	uint32_t   AddressOfCallBacks;         // PIMAGE_TLS_CALLBACK *
	uint32_t   SizeOfZeroFill;
	uint32_t   Characteristics;
} IMAGE_TLS_DIRECTORY32;
//typedef IMAGE_TLS_DIRECTORY32 * PIMAGE_TLS_DIRECTORY32;

#ifdef PE_WIN64
#define IMAGE_ORDINAL_FLAG              IMAGE_ORDINAL_FLAG64
#define IMAGE_ORDINAL(Ordinal)          IMAGE_ORDINAL64(Ordinal)
typedef IMAGE_THUNK_DATA64              IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA64             PIMAGE_THUNK_DATA;
#define IMAGE_SNAP_BY_ORDINAL(Ordinal)  IMAGE_SNAP_BY_ORDINAL64(Ordinal)
typedef IMAGE_TLS_DIRECTORY64           IMAGE_TLS_DIRECTORY;
typedef PIMAGE_TLS_DIRECTORY64          PIMAGE_TLS_DIRECTORY;
#else
#define IMAGE_ORDINAL_FLAG              IMAGE_ORDINAL_FLAG32
#define IMAGE_ORDINAL(Ordinal)          IMAGE_ORDINAL32(Ordinal)
typedef IMAGE_THUNK_DATA32              IMAGE_THUNK_DATA;
typedef IMAGE_THUNK_DATA32*             PIMAGE_THUNK_DATA;
#define IMAGE_SNAP_BY_ORDINAL(Ordinal)  IMAGE_SNAP_BY_ORDINAL32(Ordinal)
typedef IMAGE_TLS_DIRECTORY32           IMAGE_TLS_DIRECTORY;
typedef IMAGE_TLS_DIRECTORY32*          PIMAGE_TLS_DIRECTORY;
#endif

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	union {
		uint32_t   Characteristics;            // 0 for terminating null import descriptor
		uint32_t   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	};
	uint32_t   TimeDateStamp;                  // 0 if not bound,
	// -1 if bound, and real date\time stamp
	//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
	// O.W. date/time stamp of DLL bound to (Old BIND)

	uint32_t   ForwarderChain;                 // -1 if no forwarders
	uint32_t   Name;
	uint32_t   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
//typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;

//
// New format import descriptors pointed to by DataDirectory[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ]
//

typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
	uint32_t   TimeDateStamp;
	uint16_t    OffsetModuleName;
	uint16_t    NumberOfModuleForwarderRefs;
	// Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
} IMAGE_BOUND_IMPORT_DESCRIPTOR,  *PIMAGE_BOUND_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_BOUND_FORWARDER_REF {
	uint32_t   TimeDateStamp;
	uint16_t    OffsetModuleName;
	uint16_t    Reserved;
} IMAGE_BOUND_FORWARDER_REF, *PIMAGE_BOUND_FORWARDER_REF;

//
// Resource Format.
//

//
// Resource directory consists of two counts, following by a variable length
// array of directory entries.  The first count is the number of entries at
// beginning of the array that have actual names associated with each entry.
// The entries are in ascending order, case insensitive strings.  The second
// count is the number of entries that immediately follow the named entries.
// This second count identifies the number of entries that have 16-bit integer
// Ids as their name.  These entries are also sorted in ascending order.
//
// This structure allows fast lookup by either name or number, but for any
// given resource entry only one form of lookup is supported, not both.
// This is consistant with the syntax of the .RC file and the .RES file.
//

typedef struct _IMAGE_RESOURCE_DIRECTORY {
	uint32_t   Characteristics;
	uint32_t   TimeDateStamp;
	uint16_t    MajorVersion;
	uint16_t    MinorVersion;
	uint16_t    NumberOfNamedEntries;
	uint16_t    NumberOfIdEntries;
	//  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

#define IMAGE_RESOURCE_NAME_IS_STRING        0x80000000
#define IMAGE_RESOURCE_DATA_IS_DIRECTORY     0x80000000
//
// Each directory contains the 32-bit Name of the entry and an offset,
// relative to the beginning of the resource directory of the data associated
// with this directory entry.  If the name of the entry is an actual text
// string instead of an integer Id, then the high order bit of the name field
// is set to one and the low order 31-bits are an offset, relative to the
// beginning of the resource directory of the string, which is of type
// IMAGE_RESOURCE_DIRECTORY_STRING.  Otherwise the high bit is clear and the
// low-order 16-bits are the integer Id that identify this resource directory
// entry. If the directory entry is yet another resource directory (i.e. a
// subdirectory), then the high order bit of the offset field will be
// set to indicate this.  Otherwise the high bit is clear and the offset
// field points to a resource data entry.
//

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
	union {
		struct {
			uint32_t NameOffset:31;
			uint32_t NameIsString:1;
		};
		uint32_t   Name;
		uint16_t    Id;
	};
	union {
		uint32_t   OffsetToData;
		struct {
			uint32_t   OffsetToDirectory:31;
			uint32_t   DataIsDirectory:1;
		};
	};
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

//
// For resource directory entries that have actual string names, the Name
// field of the directory entry points to an object of the following type.
// All of these string objects are stored together after the last resource
// directory entry and before the first resource data object.  This minimizes
// the impact of these variable length objects on the alignment of the fixed
// size directory entry objects.
//

typedef struct _IMAGE_RESOURCE_DIRECTORY_STRING {
	uint16_t    Length;
	char    NameString[ 1 ];
} IMAGE_RESOURCE_DIRECTORY_STRING, *PIMAGE_RESOURCE_DIRECTORY_STRING;


typedef struct _IMAGE_RESOURCE_DIR_STRING_U {
	uint16_t    Length;
	uint16_t   NameString[ 1 ];
} IMAGE_RESOURCE_DIR_STRING_U, *PIMAGE_RESOURCE_DIR_STRING_U;


//
// Each resource data entry describes a leaf node in the resource directory
// tree.  It contains an offset, relative to the beginning of the resource
// directory of the data for the resource, a size field that gives the number
// of uint8_ts of data at that offset, a CodePage that should be used when
// decoding code point values within the resource data.  Typically for new
// applications the code page would be the unicode code page.
//

typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
	uint32_t   OffsetToData;	//rav of data
	uint32_t   Size;			//size of data
	uint32_t   CodePage;
	uint32_t   Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

//
// Load Configuration Directory Entry
//

typedef struct {
	uint32_t   Size;
	uint32_t   TimeDateStamp;
	uint16_t    MajorVersion;
	uint16_t    MinorVersion;
	uint32_t   GlobalFlagsClear;
	uint32_t   GlobalFlagsSet;
	uint32_t   CriticalSectionDefaultTimeout;
	uint32_t   DeCommitFreeBlockThreshold;
	uint32_t   DeCommitTotalFreeThreshold;
	uint32_t   LockPrefixTable;            // VA
	uint32_t   MaximumAllocationSize;
	uint32_t   VirtualMemoryThreshold;
	uint32_t   ProcessHeapFlags;
	uint32_t   ProcessAffinityMask;
	uint16_t    CSDVersion;
	uint16_t    Reserved1;
	uint32_t   EditList;                   // VA
	uint32_t   SecurityCookie;             // VA
	uint32_t   SEHandlerTable;             // VA
	uint32_t   SEHandlerCount;
} IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

typedef struct {
	uint32_t      Size;
	uint32_t      TimeDateStamp;
	uint16_t       MajorVersion;
	uint16_t       MinorVersion;
	uint32_t      GlobalFlagsClear;
	uint32_t      GlobalFlagsSet;
	uint32_t      CriticalSectionDefaultTimeout;
	uint64_t  DeCommitFreeBlockThreshold;
	uint64_t  DeCommitTotalFreeThreshold;
	uint64_t  LockPrefixTable;         // VA
	uint64_t  MaximumAllocationSize;
	uint64_t  VirtualMemoryThreshold;
	uint64_t  ProcessAffinityMask;
	uint32_t      ProcessHeapFlags;
	uint16_t       CSDVersion;
	uint16_t       Reserved1;
	uint64_t  EditList;                // VA
	uint64_t  SecurityCookie;          // VA
	uint64_t  SEHandlerTable;          // VA
	uint64_t  SEHandlerCount;
} IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

#ifdef PE_WIN64
typedef IMAGE_LOAD_CONFIG_DIRECTORY64     IMAGE_LOAD_CONFIG_DIRECTORY;
typedef PIMAGE_LOAD_CONFIG_DIRECTORY64    PIMAGE_LOAD_CONFIG_DIRECTORY;
#else
typedef IMAGE_LOAD_CONFIG_DIRECTORY32     IMAGE_LOAD_CONFIG_DIRECTORY;
typedef PIMAGE_LOAD_CONFIG_DIRECTORY32    PIMAGE_LOAD_CONFIG_DIRECTORY;
#endif

//
// WIN CE Exception table format
//

//
// Function table entry format.  Function table is pointed to by the
// IMAGE_DIRECTORY_ENTRY_EXCEPTION directory entry.
//

typedef struct _IMAGE_CE_RUNTIME_FUNCTION_ENTRY {
	uint32_t FuncStart;
	uint32_t PrologLen : 8;
	uint32_t FuncLen : 22;
	uint32_t ThirtyTwoBit : 1;
	uint32_t ExceptionFlag : 1;
} IMAGE_CE_RUNTIME_FUNCTION_ENTRY, * PIMAGE_CE_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY {
	uint64_t BeginAddress;
	uint64_t EndAddress;
	uint64_t ExceptionHandler;
	uint64_t HandlerData;
	uint64_t PrologEndAddress;
} IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY, *PIMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY {
	uint32_t BeginAddress;
	uint32_t EndAddress;
	uint32_t ExceptionHandler;
	uint32_t HandlerData;
	uint32_t PrologEndAddress;
} IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY, *PIMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
	uint32_t BeginAddress;
	uint32_t EndAddress;
	uint32_t UnwindInfoAddress;
} _IMAGE_RUNTIME_FUNCTION_ENTRY, *_PIMAGE_RUNTIME_FUNCTION_ENTRY;

typedef  _IMAGE_RUNTIME_FUNCTION_ENTRY  IMAGE_IA64_RUNTIME_FUNCTION_ENTRY;
typedef _PIMAGE_RUNTIME_FUNCTION_ENTRY PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY;

#if defined(_AXP64_)

typedef  IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY  IMAGE_AXP64_RUNTIME_FUNCTION_ENTRY;
typedef PIMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY PIMAGE_AXP64_RUNTIME_FUNCTION_ENTRY;
typedef  IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY  IMAGE_RUNTIME_FUNCTION_ENTRY;
typedef PIMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY PIMAGE_RUNTIME_FUNCTION_ENTRY;

#elif defined(_ALPHA_)

typedef  IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY  IMAGE_RUNTIME_FUNCTION_ENTRY;
typedef PIMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY PIMAGE_RUNTIME_FUNCTION_ENTRY;

#else

typedef  _IMAGE_RUNTIME_FUNCTION_ENTRY  IMAGE_RUNTIME_FUNCTION_ENTRY;
typedef _PIMAGE_RUNTIME_FUNCTION_ENTRY PIMAGE_RUNTIME_FUNCTION_ENTRY;

#endif

//
// Debug Format
//

typedef struct _IMAGE_DEBUG_DIRECTORY {
	uint32_t   Characteristics;
	uint32_t   TimeDateStamp;
	uint16_t    MajorVersion;
	uint16_t    MinorVersion;
	uint32_t   Type;
	uint32_t   SizeOfData;
	uint32_t   AddressOfRawData;
	uint32_t   PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

#define IMAGE_DEBUG_TYPE_UNKNOWN          0
#define IMAGE_DEBUG_TYPE_COFF             1
#define IMAGE_DEBUG_TYPE_CODEVIEW         2
#define IMAGE_DEBUG_TYPE_FPO              3
#define IMAGE_DEBUG_TYPE_MISC             4
#define IMAGE_DEBUG_TYPE_EXCEPTION        5
#define IMAGE_DEBUG_TYPE_FIXUP            6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC      7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC    8
#define IMAGE_DEBUG_TYPE_BORLAND          9
#define IMAGE_DEBUG_TYPE_RESERVED10       10
#define IMAGE_DEBUG_TYPE_CLSID            11


typedef struct _IMAGE_COFF_SYMBOLS_HEADER {
	uint32_t   NumberOfSymbols;
	uint32_t   LvaToFirstSymbol;
	uint32_t   NumberOfLinenumbers;
	uint32_t   LvaToFirstLinenumber;
	uint32_t   RvaToFirstuint8_tOfCode;
	uint32_t   RvaToLastuint8_tOfCode;
	uint32_t   RvaToFirstuint8_tOfData;
	uint32_t   RvaToLastuint8_tOfData;
} IMAGE_COFF_SYMBOLS_HEADER, *PIMAGE_COFF_SYMBOLS_HEADER;

#define FRAME_FPO       0
#define FRAME_TRAP      1
#define FRAME_TSS       2
#define FRAME_NONFPO    3

typedef struct _FPO_DATA {
	uint32_t       ulOffStart;             // offset 1st uint8_t of function code
	uint32_t       cbProcSize;             // # uint8_ts in function
	uint32_t       cdwLocals;              // # uint8_ts in locals/4
	uint16_t        cdwParams;              // # uint8_ts in params/4
	uint16_t        cbProlog : 8;           // # uint8_ts in prolog
	uint16_t        cbRegs   : 3;           // # regs saved
	uint16_t        fHasSEH  : 1;           // TRUE if SEH in func
	uint16_t        fUseBP   : 1;           // TRUE if EBP has been allocated
	uint16_t        reserved : 1;           // reserved for future use
	uint16_t        cbFrame  : 2;           // frame type
} FPO_DATA, *PFPO_DATA;
#define SIZEOF_RFPO_DATA 16


#define IMAGE_DEBUG_MISC_EXENAME    1

typedef struct _IMAGE_DEBUG_MISC {
	uint32_t       DataType;               // type of misc data, see defines
	uint32_t       Length;                 // total length of record, rounded to four
	// uint8_t multiple.
	bool 		   Unicode;                // TRUE if data is unicode string
	uint8_t        Reserved[ 3 ];
	uint8_t        Data[ 1 ];              // Actual data
} IMAGE_DEBUG_MISC, *PIMAGE_DEBUG_MISC;


//
// Function table extracted from MIPS/ALPHA/IA64 images.  Does not contain
// information needed only for runtime support.  Just those fields for
// each entry needed by a debugger.
//

typedef struct _IMAGE_FUNCTION_ENTRY {
	uint32_t   StartingAddress;
	uint32_t   EndingAddress;
	uint32_t   EndOfPrologue;
} IMAGE_FUNCTION_ENTRY, *PIMAGE_FUNCTION_ENTRY;

typedef struct _IMAGE_FUNCTION_ENTRY64 {
	uint64_t   StartingAddress;
	uint64_t   EndingAddress;
	union {
		uint64_t   EndOfPrologue;
		uint64_t   UnwindInfoAddress;
	};
} IMAGE_FUNCTION_ENTRY64, *PIMAGE_FUNCTION_ENTRY64;

//
// Debugging information can be stripped from an image file and placed
// in a separate .DBG file, whose file name part is the same as the
// image file name part (e.g. symbols for CMD.EXE could be stripped
// and placed in CMD.DBG).  This is indicated by the IMAGE_FILE_DEBUG_STRIPPED
// flag in the Characteristics field of the file header.  The beginning of
// the .DBG file contains the following structure which captures certain
// information from the image file.  This allows a debug to proceed even if
// the original image file is not accessable.  This header is followed by
// zero of more IMAGE_SECTION_HEADER structures, followed by zero or more
// IMAGE_DEBUG_DIRECTORY structures.  The latter structures and those in
// the image file contain file offsets relative to the beginning of the
// .DBG file.
//
// If symbols have been stripped from an image, the IMAGE_DEBUG_MISC structure
// is left in the image file, but not mapped.  This allows a debugger to
// compute the name of the .DBG file, from the name of the image in the
// IMAGE_DEBUG_MISC structure.
//

typedef struct _IMAGE_SEPARATE_DEBUG_HEADER {
	uint16_t        Signature;
	uint16_t        Flags;
	uint16_t        Machine;
	uint16_t        Characteristics;
	uint32_t       TimeDateStamp;
	uint32_t       CheckSum;
	uint32_t       ImageBase;
	uint32_t       SizeOfImage;
	uint32_t       NumberOfSections;
	uint32_t       ExportedNamesSize;
	uint32_t       DebugDirectorySize;
	uint32_t       SectionAlignment;
	uint32_t       Reserved[2];
} IMAGE_SEPARATE_DEBUG_HEADER, *PIMAGE_SEPARATE_DEBUG_HEADER;

typedef struct _NON_PAGED_DEBUG_INFO {
	uint16_t        Signature;
	uint16_t        Flags;
	uint32_t       Size;
	uint16_t        Machine;
	uint16_t        Characteristics;
	uint32_t       TimeDateStamp;
	uint32_t       CheckSum;
	uint32_t       SizeOfImage;
	uint64_t   ImageBase;
	//DebugDirectorySize
	//IMAGE_DEBUG_DIRECTORY
} NON_PAGED_DEBUG_INFO, *PNON_PAGED_DEBUG_INFO;

#ifndef _MAC
#define IMAGE_SEPARATE_DEBUG_SIGNATURE 0x4944
#define NON_PAGED_DEBUG_SIGNATURE      0x494E
#else
#define IMAGE_SEPARATE_DEBUG_SIGNATURE 0x4449  // DI
#define NON_PAGED_DEBUG_SIGNATURE      0x4E49  // NI
#endif

#define IMAGE_SEPARATE_DEBUG_FLAGS_MASK 0x8000
#define IMAGE_SEPARATE_DEBUG_MISMATCH   0x8000  // when DBG was updated, the
// old checksum didn't match.

//
//  The .arch section is made up of headers, each describing an amask position/value
//  pointing to an array of IMAGE_ARCHITECTURE_ENTRY's.  Each "array" (both the header
//  and entry arrays) are terminiated by a quauint32_t of 0xffffffffL.
//
//  NOTE: There may be quauint32_ts of 0 sprinkled around and must be skipped.
//

typedef struct _ImageArchitectureHeader {
	unsigned int AmaskValue: 1;                 // 1 -> code section depends on mask bit
	// 0 -> new instruction depends on mask bit
	int :7;                                     // MBZ
	unsigned int AmaskShift: 8;                 // Amask bit in question for this fixup
	int :16;                                    // MBZ
	uint32_t FirstEntryRVA;                        // RVA into .arch section to array of ARCHITECTURE_ENTRY's
} IMAGE_ARCHITECTURE_HEADER, *PIMAGE_ARCHITECTURE_HEADER;

typedef struct _ImageArchitectureEntry {
	uint32_t FixupInstRVA;                         // RVA of instruction to fixup
	uint32_t NewInst;                              // fixup instruction (see alphaops.h)
} IMAGE_ARCHITECTURE_ENTRY, *PIMAGE_ARCHITECTURE_ENTRY;

//#include "poppack.h"                // Back to the initial value
#pragma pack(pop)
// The following structure defines the new import object.  Note the values of the first two fields,
// which must be set as stated in order to differentiate old and new import members.
// Following this structure, the linker emits two null-terminated strings used to recreate the
// import at the time of use.  The first string is the import's name, the second is the dll's name.

#define IMPORT_OBJECT_HDR_SIG2  0xffff

typedef struct IMPORT_OBJECT_HEADER {
	uint16_t    Sig1;                       // Must be IMAGE_FILE_MACHINE_UNKNOWN
	uint16_t    Sig2;                       // Must be IMPORT_OBJECT_HDR_SIG2.
	uint16_t    Version;
	uint16_t    Machine;
	uint32_t   TimeDateStamp;              // Time/date stamp
	uint32_t   SizeOfData;                 // particularly useful for incremental links

	union {
		uint16_t    Ordinal;                // if grf & IMPORT_OBJECT_ORDINAL
		uint16_t    Hint;
	};

	uint16_t    Type : 2;                   // IMPORT_TYPE
	uint16_t    NameType : 3;               // IMPORT_NAME_TYPE
	uint16_t    Reserved : 11;              // Reserved. Must be zero.
} IMPORT_OBJECT_HEADER;

typedef enum IMPORT_OBJECT_TYPE
{
	IMPORT_OBJECT_CODE = 0,
	IMPORT_OBJECT_DATA = 1,
	IMPORT_OBJECT_CONST = 2,
} IMPORT_OBJECT_TYPE;

typedef enum IMPORT_OBJECT_NAME_TYPE
{
	IMPORT_OBJECT_ORDINAL = 0,          // Import by ordinal
	IMPORT_OBJECT_NAME = 1,             // Import name == public symbol name.
	IMPORT_OBJECT_NAME_NO_PREFIX = 2,   // Import name == public symbol name skipping leading ?, @, or optionally _.
	IMPORT_OBJECT_NAME_UNDECORATE = 3,  // Import name == public symbol name skipping leading ?, @, or optionally _
	// and truncating at first @
} IMPORT_OBJECT_NAME_TYPE;


#ifndef __IMAGE_COR20_HEADER_DEFINED__
#define __IMAGE_COR20_HEADER_DEFINED__

typedef enum ReplacesCorHdrNumericDefines
{
	// COM+ Header entry point flags.
	COMIMAGE_FLAGS_ILONLY               =0x00000001,
	COMIMAGE_FLAGS_32BITREQUIRED        =0x00000002,
	COMIMAGE_FLAGS_IL_LIBRARY           =0x00000004,
	COMIMAGE_FLAGS_STRONGNAMESIGNED     =0x00000008,
	COMIMAGE_FLAGS_TRACKDEBUGDATA       =0x00010000,

	// Version flags for image.
	COR_VERSION_MAJOR_V2                =2,
	COR_VERSION_MAJOR                   =COR_VERSION_MAJOR_V2,
	COR_VERSION_MINOR                   =0,
	COR_DELETED_NAME_LENGTH             =8,
	COR_VTABLEGAP_NAME_LENGTH           =8,

	// Maximum size of a NativeType descriptor.
	NATIVE_TYPE_MAX_CB                  =1,   
	COR_ILMETHOD_SECT_SMALL_MAX_DATASIZE=0xFF,

	// #defines for the MIH FLAGS
	IMAGE_COR_MIH_METHODRVA             =0x01,
	IMAGE_COR_MIH_EHRVA                 =0x02,    
	IMAGE_COR_MIH_BASICBLOCK            =0x08,

	// V-table constants
	COR_VTABLE_32BIT                    =0x01,          // V-table slots are 32-bits in size.   
	COR_VTABLE_64BIT                    =0x02,          // V-table slots are 64-bits in size.   
	COR_VTABLE_FROM_UNMANAGED           =0x04,          // If set, transition from unmanaged.
	COR_VTABLE_CALL_MOST_DERIVED        =0x10,          // Call most derived method described by

	// EATJ constants
	IMAGE_COR_EATJ_THUNK_SIZE           =32,            // Size of a jump thunk reserved range.

	// Max name lengths    
	//@todo: Change to unlimited name lengths.
	MAX_CLASS_NAME                      =1024,
	MAX_PACKAGE_NAME                    =1024,
} ReplacesCorHdrNumericDefines;

// COM+ 2.0 header structure.
typedef struct IMAGE_COR20_HEADER
{
	// Header versioning
	uint32_t                   cb;              
	uint16_t                    MajorRuntimeVersion;
	uint16_t                    MinorRuntimeVersion;

	// Symbol table and startup information
	IMAGE_DATA_DIRECTORY    MetaData;        
	uint32_t                   Flags;           
	uint32_t                   EntryPointToken;

	// Binding information
	IMAGE_DATA_DIRECTORY    Resources;
	IMAGE_DATA_DIRECTORY    StrongNameSignature;

	// Regular fixup and binding information
	IMAGE_DATA_DIRECTORY    CodeManagerTable;
	IMAGE_DATA_DIRECTORY    VTableFixups;
	IMAGE_DATA_DIRECTORY    ExportAddressTableJumps;

	// Precompiled image info (internal use only - set to zero)
	IMAGE_DATA_DIRECTORY    ManagedNativeHeader;

} IMAGE_COR20_HEADER, *PIMAGE_COR20_HEADER;


#endif // __IMAGE_COR20_HEADER_DEFINED__

#endif	/* !( defined( WIN32 ) && !defined( __KERNEL__ ) ) */

/* user defined structure*/
#pragma pack(push, 2)

typedef struct _IMAGE_EXPORT_FUNCTION
{
  int32_t   	Ordinal;                //函数序号
  char      	FunctionName[256];      //函数名称
  uint32_t      FunctionVirtualAddress; //函数内存地址
}IMAGE_EXPORT_FUNCTION;

typedef struct _IMAGE_OVERLAY
{
  uint32_t  offset_in_file;
  uint32_t  size;
} IMAGE_OVERLAY;

typedef struct _IMAGE_GAP
{
	uint32_t offset;
	uint32_t size;
}IMAGE_GAP;

#define MAX_VER_NAME_LEN   128
#define MAX_VER_VALUE_LEN  512
typedef struct _IMAGE_VERSION
{
  char name[MAX_VER_NAME_LEN];
  char value[MAX_VER_VALUE_LEN];
} IMAGE_VERSION;

typedef struct _IMAGE_RELOCATION_ITEM
{
  int32_t 	rva;
  int32_t 	type;
} IMAGE_RELOCATION_ITEM;


typedef struct _IMAGE_IMPORT_FUNCTION
{
  //int IndexOfModule;
  //uint32_t IndexInModule;   //在该导入模块中第几个导入函数
  union {
    uint16_t FunctionOrdinal; //以序号的方式导入函数时有效
    uint16_t FunctionHint;    //以名称的方式导入函数时有效
  };
  char      FunctionName[256];     //以名称的方式导入函数
  uint32_t     ThunkOffset;
  uint32_t     ThunkRVA;
  uint32_t  ThunkValue;    //最高位1， 表示序号方式导入， 无函数名称
  uint32_t     OffsetName;
  uint32_t     iat;                  //导入函数地址实际填入的位置. RVA
}IMAGE_IMPORT_FUNCTION;

typedef struct _ICON_ENTRY
{
  uint8_t   bWidth;
  uint8_t   bHeigh;
  uint8_t   bColorCount;      //Number of colors in image(0 if>=8bpp)
  uint8_t   bReserved;
  uint16_t  wPlanes;          //color planes
  uint16_t  wBitCount;        //bits per pixel
  uint32_t  dwBytesInRes;
  uint32_t  dwImageOffset;    //where in the file is this image
}ICON_ENTRY;

typedef struct _ICON_DIR
{
  uint16_t    idReserved;
  uint16_t    idType;
  uint16_t    idCount;
  ICON_ENTRY idEntries[1];
}ICON_DIR;

typedef struct _GRPICON_DIR_ENTRY
{
  uint8_t   bWidth;
  uint8_t   bHeigh;
  uint8_t   bColorCount;
  uint8_t   bReserved;
  uint16_t  wPlanes;
  uint16_t  wBitCount;
  uint32_t  dwBytesInRes;
  uint16_t  nID;
}GRPICON_DIR_ENTRY;

typedef struct _GRPICONDIR
{
  uint16_t    idReserved;
  uint16_t    idType;
  uint16_t    idCount;
  GRPICON_DIR_ENTRY idEntries[1];
}GRPICONDIR;

#pragma pack(pop)


#endif	/* !defined( __windows_image_formats_h__ ) */