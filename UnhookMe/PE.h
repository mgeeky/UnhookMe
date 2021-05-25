#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <cctype>
#include <string>
#include <sstream>
#include <winnt.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <psapi.h>
#include <processthreadsapi.h>

#include "usings.h"

#define RESOLVE_NO_UNHOOK(a, b) \
    auto _ ## b = reinterpret_cast<fn_ ## b *>(::GetProcAddress(::LoadLibraryA(#a), #b));

///////////////////////////////////

#define PE_MAX_SECTIONS_COUNT           96          // according to Microsoft "pecoff_v8.doc"
                                                    // and "The Art of computer virus research
                                                    // and defense" by Peter Szor
#define PE_MAX_ELFANEW_VALUE            0x400       
#define PE_MAX_SECTION_NAME_LEN         9
#define PE_MAX_RELOCS_LIMIT             0x3000
#define PE_MAX_BASE_RELOCATIONS         0x400
#define PE_MAX_IAT_SIZE                 0x100000
#define PE_MAX_IAT_DESCRIPTORS          0x100
#define PE_MAX_IAT_THUNKS               0x2000
#define PE_MAX_EXPORTS_NUMBER           0x2000

// Errors

#define ERROR_FILE_IS_COMPRESSED        0x80001     // File is probably compressed
#define ERROR_IAT_UNACCESSIBLE          0x80002     // IAT is unaccessible
#define ERROR_INVALID_MAGIC             0x80003     // DOS_HEADER.eMagic is not "MZ"
#define ERROR_INVALID_PE                ERROR_INVALID_MAGIC
#define ERROR_INVALID_SIGNATURE         0x80004     // NT_HEADERS.Signature is not "PE"
#define ERROR_HEAP_CORRUPTED            0x80005     // Error while allocating memory at the Heap
#define ERROR_READ_LESS_THAN_SHOULD     0x80006     // Read less bytes than should read
#define ERROR_WRITE_LESS_THAN_SHOULD    0x80007     // Write less bytes than should write
#define ERROR_EAT_UNACCESSIBLE          0x80008     // EAT is unaccessible
#define ERROR_IAT_CORRUPTED             0x80009     // IAT is corrupted
#define ERROR_EAT_CORRUPTED             0x8000A     // EAT is corrupted
#define ERROR_OPENED_FOR_READ_ONLY      0x8000B     // File was opened for read only access.
#define ERROR_PE_HEADERS_CORRUPTED      0x8000C
#define ERROR_NO_RELOCS                 0x8000D
#define ERROR_RELOCS_CORRUPTED          0x8000E
#define ERROR_RESOURCES_CORRUPTED       0x8000F
#define ERROR_NO_RESOURCES              0x80010
#define ERROR_IAT_TOO_BIG               0x80011
#define ERROR_TOO_MANY_EXPORTS          0x80012
#define ERROR_TOO_MANY_RELOCS           0x80013


typedef struct _LDR_MODULE {
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    void*   BaseAddress;
    void*   EntryPoint;
    ULONG   SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG   Flags;
    SHORT   LoadCount;
    SHORT   TlsIndex;
    HANDLE  SectionHandle;
    ULONG   CheckSum;
    ULONG   TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

struct IMPORTED_FUNCTION
{
    IMPORTED_FUNCTION() { memset((void*)szFunction, 0, sizeof(szFunction)); }

    unsigned uImpDescriptorIndex;       // Index of import descriptor (index in vector)
    unsigned uImportIndex;              // Index of import inside import descriptor
    char szFunction[65];

    ULONGLONG dwPtrValueVA;            // Value of pointer to this thunk
    ULONGLONG dwPtrValueRVA;            // Value of pointer to this thunk
    DWORD dwHint;                       // Hint
    WORD wOrdinal;
    DWORD dwThunkRVA;                   // RVA address of this Thunk in file (not of value)
};


// Class describing each exported thunk

struct EXPORTED_FUNCTION
{
    EXPORTED_FUNCTION() { memset((void*)szFunction, 0, sizeof(szFunction)); }

    bool bIsOrdinal;                    // Specifies wheter function is exported by ordinal
                                        // instead of by name
    unsigned uExportIndex;              // Export thunk index.
    union {
        char szFunction[65];
        DWORD dwOrdinal;
    };

    bool bIsForwarded;                  // Specifies wheter exported thunk is forwarded
    char szForwarder[256];

    ULONGLONG dwPtrValue;               // Value of pointer to this thunk
    DWORD dwPtrValueRVA;                // Value of pointer to this thunk
    WORD wOrdinal;                      // Ordinal
    DWORD dwThunkRVA;                   // RVA address of this Thunk in file (not of value)
};


// Class describing each import descriptor

struct __IMAGE_IMPORT_DESCRIPTOR
{
    IMAGE_IMPORT_DESCRIPTOR    d;
    char szName[128];
    std::vector< IMPORTED_FUNCTION> vImports;
};

struct __IMAGE_EXPORT_DIRECTORY
{
	IMAGE_EXPORT_DIRECTORY    d;
	char szName[128];
};

struct __IMAGE_SECTION_HEADER
{
    IMAGE_SECTION_HEADER s;
    char szSectionName[PE_MAX_SECTION_NAME_LEN];
};

struct __IMAGE_RELOC_ENTRY
{
    WORD offset : 12;
    WORD type : 4;
};

struct __IMAGE_RELOCATION
{
    IMAGE_BASE_RELOCATION baseRelocation;
    std::vector<__IMAGE_RELOC_ENTRY> relocs;
};


////////////////////////////////

class PE
{
    class _MY_IMAGE_OPTIONAL_HEADER;

public:

    enum class AccessMethod
    {
        Arbitrary = 0,
        File_Begin,
        File_Current,
        File_End
    };

    enum class AnalysisType
    {
        None,
        File,
        MappedModule,
        Memory,
        Dump
    };

    bool                                hasImports;
    bool                                hasExports;
    bool                                hasRelocs;
    bool                                bReadOnly;
    bool                                bIsValidPE;

    AnalysisType                        analysisType;

    std::string                         szFileName;
    BY_HANDLE_FILE_INFORMATION          bhFileInformation;

    size_t                              sizeOfFile;                // actual size of file

    // PE Headers
    IMAGE_DOS_HEADER                    imgDosHdr;
    IMAGE_NT_HEADERS32                  imgNtHdrs32;
    IMAGE_NT_HEADERS64                  imgNtHdrs64;

    __IMAGE_EXPORT_DIRECTORY            imgExportDirectory;        // If this module provides
                                                                   // EAT, then this structure
                                                                   // will be filled correspondly

    size_t                              numOfNewSections;          // Number of added sections
                                                                   // (by CreateSection method)

    // DOS header & stub
    std::vector<uint8_t>                lpDOSStub;                 // DOS STUB

    // Vectors
    std::vector<__IMAGE_SECTION_HEADER>      vSections;
    std::vector< IMPORTED_FUNCTION>          vImports;
    std::vector<__IMAGE_IMPORT_DESCRIPTOR>   vImportDescriptors;
    std::vector< EXPORTED_FUNCTION>          vExports;
    std::vector<__IMAGE_RELOCATION>          vRelocations;

    // Address of mapped memory area
    LPBYTE                              lpMapOfFile;
    bool                                bUseRVAInsteadOfRAW;        // Used for analysis of a previously mapped
                                                                    // dump file.
    HANDLE                              hFileHandle;

    // Process analysis specific variables
    bool                                bPreferBaseAddressThanImageBase;
                                                                    // If parsing PIC injected shellcode, its allocation
                                                                    // base address may be different than its expected ImageBase.
                                                                    // In such scenario, prefer allocation base over its ImageBase.
    bool                                bMemoryAnalysis;            // PE interface is performing living
                                                                    // process/module analysis (memory).
                                                                    // This not flags actual memory
                                                                    // analysing, but in fact it's
                                                                    // switch used in recognizing
                                                                    // Process Memory operations.

    DWORD                               dwPID;                      // PID of the currently analysed process.


    //////////////////////////////        MEMBER METHODS        ////////////////////////////////////////////

    ~PE();

    // Implicit constructor. After you have to call PE::LoadFile member method to analyse an image
    PE() {  _initVars(); }

    // Explicit constructor. After initialization instantly runs PE image analysis
    PE(const std::string& _szFileName, bool bRunAnalysis = false) : szFileName(_szFileName)
    {
        _initVars();
        if (bRunAnalysis == true) {
            _bIsFileMapped = false;
            LoadFile();
        }
    }

    void close();


    //=========     Address / offset conversions

    size_t    RVA2RAW(size_t dwRVA, bool bForce = false) const;

    // Returns conversion from RVA to RAW.
    // If we set bForce to true, it will omit
    // usage of this->bUseRVAInsteadOfRAW variable
    DWORD    RAW2RVA(size_t dwRAW) const;
    DWORD    VA2RVA32(DWORD dwVA) const { return dwVA - GetIB32(); }
    DWORD    RVA2VA32(DWORD dwRVA) const { return dwRVA + GetIB32(); }
    ULONGLONG VA2RVA64(ULONGLONG dwVA) const { return dwVA - GetIB64(); }
    ULONGLONG RVA2VA64(ULONGLONG dwRVA) const { return dwRVA + GetIB64(); }


    //=========     Getting info

    DWORD                    GetEP()                const { return bIs86 ? imgNtHdrs32.OptionalHeader.AddressOfEntryPoint : imgNtHdrs64.OptionalHeader.AddressOfEntryPoint; }
    ULONGLONG                GetImageBase()         const { return bIs86 ? GetIB32() : GetIB64(); }
    size_t                   GetSectionsCount()     const { return vSections.size(); }
    __IMAGE_SECTION_HEADER&  GetSection(size_t u)   { return vSections[u]; }
    __IMAGE_SECTION_HEADER&  GetLastSection()       { return vSections.back(); }
	
    bool                     isArch86()             const { return bIs86; }
    bool                     HasOverlay()           const { return _bHasOverlay; }


    //=========     Checking errors

    DWORD GetError()                                const { return _dwLastError; }
    DWORD GetErrorLine()                            const { return _dwErrorLine; }
    std::wstring GetErrorFunc()                     const { std::wstring func(_szErrorFunction.begin(), _szErrorFunction.end()); return func; }
    std::wstring GetErrorString()                   const;
    
    bool operator!()                                const { return (this->GetError() != 0); }
    void SetError(DWORD dwErrCode) { SetLastError(dwErrCode); _dwLastError = dwErrCode; }


    //===========    Analysis methods    ============

    // Simple file reading & writing (and of course parsing)
    bool AnalyseFile(const std::wstring& _szFileName, bool readOnly, bool _bIsValidPEImage = true)
    {
        std::string _name(_szFileName.begin(), _szFileName.end());
        return AnalyseFile(_name, readOnly, _bIsValidPEImage);
    }

    bool AnalyseFile(const std::string& _szFileName, bool readOnly, bool _bIsValidPEImage = true)
    {
        this->szFileName = _szFileName;
        this->_bIsFileMapped = false;
        this->bUseRVAInsteadOfRAW = false;
        this->bReadOnly = readOnly;
        this->bIsValidPE = _bIsValidPEImage;
        this->analysisType = AnalysisType::File;

        return PE::LoadFile();
    }

    // Another type of analysis. This performs analysis from dump file which is aligned and
    // divided to sections. This means, that analysis must be RVA-based
    // and make file reading & writing on every I/O.
    // e.g. dump file may be a dumped process memory.
	// Simple file reading & writing (and of course parsing)
	bool AnalyseDump(const std::wstring& _szDump, bool readOnly)
	{
		std::string _name(_szDump.begin(), _szDump.end());
		return AnalyseDump(_name, readOnly);
	}

    bool AnalyseDump(const std::string& _szDump, bool readOnly)
    {
        this->bUseRVAInsteadOfRAW = this->bIsValidPE = true;
        this->_bIsFileMapped = false;
        this->bReadOnly = readOnly;
        this->analysisType = AnalysisType::Dump;

        szFileName = _szDump;

        return PE::LoadFile();
    }

    // Analyses current process memory treating input dwAddress as a base of
    // mapped image. This address should point to the mapped address of valid PE
    // file inside current process memory.
    // If analysed memory region is not a MEM_MAPPED or MEM_IMAGE, it may be PIC shellcode.
    // In such case, prefer dwAddress over expected ImageBase while calculating RVAs/VAs.
    // use isMapped=True if you plan to analyse memory mapped(or ordinarly loaded) PE module such as EXE/DLL,
    // or isMapped=False for PIC shellcode acting as a Reflective DLL injected one or PE-to-shellcode converted.
    bool AnalyseMemory(DWORD dwPID, LPBYTE dwAddress, size_t dwSize, bool readOnly, bool isMapped);

    // Below methods performs module analysis from specified process memory.
    // This works by reading process memory and parsing/analysing it.
    bool AnalyseProcessModule(DWORD dwPID, HMODULE hModule, bool readOnly);

    // This method performs process module analysis. Actually, it opens process,
    // enumerates process modules and compares it with the szModule name. Afterwards,
    // it sets module handle and launches analysis. By specifying szModule to nullptr user can
    // perform dwPID process analysis instead of one of it's modules.
    bool AnalyseProcessModule(DWORD dwPID, const std::wstring& szModule, bool readOnly)
    {
        std::string n(szModule.begin(), szModule.end());
        return AnalyseProcessModule(dwPID, n, readOnly);
    }

    bool AnalyseProcessModule(DWORD dwPID, const std::string& szModule, bool readOnly);

    // Simple wrapper to _AnalyseProcessModule for quick process analysis
    bool AnalyseProcess(DWORD dwPID, bool readOnly) { return this->AnalyseProcessModule(dwPID, "", readOnly); }

    bool ApplyRelocsInBuffer(ULONGLONG newBase, ULONGLONG bufferRVA, uint8_t *buffer, size_t sizeOfBuffer, ULONGLONG oldImageBase = 0);

    // This function actually opens the file, gathers headers from file, performs IAT parsing, and
    // if possible performs EAT parsing. Whole PE image analysis is beginning there.
    bool LoadFile();

    // I/O - read/writes opened file/process (PE::_hFileHandle) and returns
    bool ReadBytes(LPVOID, size_t dwSize, size_t dwOffset = 0, AccessMethod method = AccessMethod::File_Current, bool dontRestoreFilePointer = false);
    bool WriteBytes(LPVOID, size_t dwSize, size_t dwOffset = 0, AccessMethod method = AccessMethod::File_Current, bool dontRestoreFilePointer = false);

    std::vector<uint8_t> ReadOverlay();
    std::vector<uint8_t> ReadSection(const __IMAGE_SECTION_HEADER& section);

    // Writes PE headers back to the mapped file/memory.
    bool UpdateHeaders();

    DWORD InsertShellcode(uint8_t *shellcode, size_t sizeOfShellcode, const std::string& szSectionName = ".extra", BYTE* whereToReturn = 0);

    std::vector<uint8_t> getJumpPayload(BYTE* whereToJump);

    // This method hooks IAT/EAT routine by swapping original IAT/EAT thunk address with input hook address
    // Returns: 0 if szImportThunk/szExportThunk has not been found, -1 if there has
    // occured an error during WriteBytes, or non-zero if function succeed, and this value will
    // be previous thunk EntryPoint address.
    ULONGLONG HookIAT(const std::string& szImportThunk, ULONGLONG hookedVA);
    DWORD     HookEAT(const std::string& szExportThunk, DWORD hookedRVA);

    // Creates image section and appends it to the PE::pSectionHdrs table
    __IMAGE_SECTION_HEADER CreateSection(DWORD dwSizeOfSection, DWORD dwDesiredAccess, const std::string& szNameOfSection);
    __IMAGE_SECTION_HEADER RemoveSection(size_t index);

    static int64_t LECharTo64bitNum(char a[]) 
    {
        int64_t n = 0;
        n = (((int64_t)a[7] << 56) & 0xFF00000000000000U)
            | (((int64_t)a[6] << 48) & 0x00FF000000000000U)
            | (((int64_t)a[5] << 40) & 0x0000FF0000000000U)
            | (((int64_t)a[4] << 32) & 0x000000FF00000000U)
            | ((a[3] << 24) & 0x00000000FF000000U)
            | ((a[2] << 16) & 0x0000000000FF0000U)
            | ((a[1] << 8) & 0x000000000000FF00U)
            | (a[0] & 0x00000000000000FFU);
        return n;
    }

    static int32_t LECharTo32bitNum(char a[]) 
    {
        int32_t n = 0;
        n = (((int32_t)a[3] << 24) & 0xFF000000)
            | (((int32_t)a[2] << 16) & 0x00FF0000)
            | (((int32_t)a[1] << 8) & 0x0000FF00)
            | (((int64_t)a[0] << 0) & 0x000000FF);
        return n;
    }

    static void convert64ToLECharArray(uint8_t *arr, uint64_t a)
    {
        size_t i = 0;
        for (i = 7; i > 0; i--)
        {
            arr[i] = (uint8_t)((((uint64_t)a) >> (56 - (8 * i))) & 0xFFu);
        }
    }

    static void convert32ToLECharArray(uint8_t *arr, uint32_t a)
    {
        size_t i = 0;
        for (i = 3; i > 0; i--)
        {
            arr[i] = (uint8_t)((((uint32_t)a) >> (24 - (8 * i))) & 0xFFu);
        }
    }

private:
    // ==========================================

	void _initVars()
	{
		_bHasOverlay = _bIsFileMapped = _bIsIATFilled = bUseRVAInsteadOfRAW = bMemoryAnalysis = _selfProcessAnalysis = false;
		numOfNewSections = sizeOfFile = _dwCurrentOffset = _dwLastError = dwPID = 0;
		_hMapOfFile = hFileHandle = (HANDLE)INVALID_HANDLE_VALUE;
		lpMapOfFile = nullptr;
        analysisType = AnalysisType::None;
        if(!lpDOSStub.empty()) lpDOSStub.clear();
	}

	// More detailed SetError version
	void _SetError(DWORD dwErrCode, int iLine, const char* szFunc)
	{
        if (this->_dwLastError != 0) return;
		this->SetError(dwErrCode);
		this->_dwErrorLine = (DWORD)iLine;
		this->_szErrorFunction = std::string(szFunc);
	}

    void adjustOptionalHeader();

    std::string& trimQuote(std::string& szPath) const;    // Trims from file path quote chars '"'

    bool ReadEntireModuleSafely(LPVOID lpBuffer, size_t dwSize, size_t dwOffset);

    void AddNewSection(size_t sizeOfSection, DWORD flags, const std::string& szSectionName);
    bool AppendShellcode(BYTE* whereToReturn, uint8_t *shellcode, size_t sizeOfShellcode, __IMAGE_SECTION_HEADER *imgNewSection);

    bool ApplyAllRelocs(ULONGLONG newImageBase);
	DWORD GetSafeSectionSize(const __IMAGE_SECTION_HEADER& sect) const;

    bool _OpenFile();

    void SetFileMapped(LPBYTE _lpMapOfFile) 
    {
        lpMapOfFile = _lpMapOfFile;
        _bIsFileMapped = true;
        _bAutoMapOfFile = false;
    }

    // Simple CreateFileMappingA and MapViewOfFile function
    LPBYTE      MapFile();

    // Function fills IAT in mapped memory (with GetProcAddr addresses
    // if dwAddresses hasn't been specified, or with addresses from dwAddresses table.
    bool        FillIAT(DWORD *dwAddresses = nullptr, DWORD dwElements = 0);

    bool        ParseIAT(DWORD dwAddressOfIAT = 0);     // Function parses IAT (from input address, or if
                                                        //        not specified - from DataDirectory[1] )
    bool        ParseEAT(DWORD dwAddressOfEAT = 0);     // Function parses EAT (from input address, or if
                                                        //        not specified - from DataDirectory[0] )

    bool        ParseRelocs();
    bool        ParseResources();

    // Returns char intepretation of input, or '.' if it is not printable
    inline char _HexChar(int c);

    DWORD       GetIB32()  const;
    ULONGLONG   GetIB64()  const;

    bool        changeProtection(LPVOID address, size_t size, DWORD newProtection, LPDWORD oldProtection);

    bool        verifyAddressBounds(uintptr_t address, bool relative = true);
    bool        verifyAddressBounds(uintptr_t address, size_t upperBoundary, bool relative = true);
    bool        verifyAddressBounds(uintptr_t address, size_t lowerBoundary, size_t upperBoundary, bool relative = true);

    std::vector<MEMORY_BASIC_INFORMATION>
                collectProcessMemoryMap();


    /************************************/

    bool        bIs86;

    size_t      ptrSize;
    DWORD       _dwLastError;           // PE interface last error
                                        //    may be as well return of the
                                        //    GetLastError()
    DWORD       _dwErrorLine;           // Line in code where error occured
    std::string _szErrorFunction;       // Function name where error occured
    bool        _bIsIATFilled;          // Specifies wheter IAT has been
                                        //    filled

    size_t      _dwCurrentOffset;       // During process analysis
                                        // we cannot use SetFilePointer
                                        // routine to seek inside process
                                        // memory, so that's how we obey it
    intptr_t    _moduleStartPos;
    HANDLE      _hMapOfFile;
    bool        _bIsFileMapped;
    bool        _bAutoMapOfFile;
    bool        _selfProcessAnalysis;
    bool        _bHasOverlay;
};
