// In MS Compiler (with precompiled headers usage) you have to uncomment below line.
//#include "stdafx.h"

#include "PE.h"
#include "resolver.h"

#define        SET_ERROR            this->SetError( GetLastError() )
#define        SET_ERROR2(x)        this->_SetError( x, __LINE__, OBFI_ASCII(__FUNCTION__) );
#define        RETURN_ERROR2(x)     { this->_SetError( x, __LINE__, OBFI_ASCII(__FUNCTION__) ); return FALSE;}
#define        RETURN_ERROR         { this->_SetError( GetLastError(), __LINE__, OBFI_ASCII(__FUNCTION__) ); return FALSE;}
#define        READ_FAIL            { this->_SetError( ERROR_READ_LESS_THAN_SHOULD, __LINE__, OBFI_ASCII(__FUNCTION__) ); return FALSE; }
#define        WRITE_FAIL           { this->_SetError( ERROR_WRITE_LESS_THAN_SHOULD, __LINE__, OBFI_ASCII(__FUNCTION__) ); return FALSE; }


PE::~PE()
{
    close();
}

std::wstring PE::GetErrorString() const
{
    std::wostringstream woss;
    std::wstring func(_szErrorFunction.begin(), _szErrorFunction.end());
    if (func.empty()) func = OBFI(L"<no-func>");
    woss << L"PE(code: 0x" << std::hex << _dwLastError << L", line: " << std::dec << _dwErrorLine << L", func: " << func << L")";
    std::wstring out(woss.str());
    return out;
}

void PE::close()
{
    if (_bAutoMapOfFile && _bIsFileMapped)
    {
        if (lpMapOfFile != nullptr)
        {
            UnmapViewOfFile(lpMapOfFile);
            _bIsFileMapped = false;

            if (this->lpMapOfFile != nullptr)
            {
                VirtualFree(this->lpMapOfFile, 0, MEM_FREE | MEM_RELEASE);
            }
        }

        if (_hMapOfFile != (HANDLE)INVALID_HANDLE_VALUE && _hMapOfFile != nullptr)
        {
            CloseHandle(_hMapOfFile);
            _hMapOfFile = INVALID_HANDLE_VALUE;
            _bAutoMapOfFile = false;
        }
    }
    else
    {
        _bIsFileMapped = false;
        _bAutoMapOfFile = false;
        _hMapOfFile = INVALID_HANDLE_VALUE;
    }

    if (!_selfProcessAnalysis)
    {
        if (hFileHandle != INVALID_HANDLE_VALUE && hFileHandle != nullptr)
        {
            CloseHandle(hFileHandle);
        }
    }

    hFileHandle = INVALID_HANDLE_VALUE;
    if (!lpDOSStub.empty()) lpDOSStub.clear();

    _initVars();
}

DWORD PE::GetIB32() const
{
    if (this->bPreferBaseAddressThanImageBase)
    {
        return static_cast<DWORD>(reinterpret_cast<std::uintptr_t>(this->lpMapOfFile));
    }

    return imgNtHdrs32.OptionalHeader.ImageBase;
}

ULONGLONG PE::GetIB64() const
{
    if (this->bPreferBaseAddressThanImageBase)
    {
        return (ULONGLONG)this->lpMapOfFile;
    }

    return imgNtHdrs64.OptionalHeader.ImageBase;
}

///////////////////////////////////////////////////////////////////////////////////////
// Loads and analyses image/dump/memory .
// Gathers PE headers and launches IAT/EAT parsing

bool PE::LoadFile()
{
    // Fix file path
    trimQuote(szFileName);

    // Open a file
    if (!_OpenFile())
    {
        RETURN_ERROR
    }

    // If this is process, then we have to open process module to acquire by_handle_information.
    if (this->bMemoryAnalysis)
    {
    }
    else
    {
        GetFileInformationByHandle(hFileHandle, &bhFileInformation);

        sizeOfFile = bhFileInformation.nFileSizeLow; /* + bhFileInformation.nFileSizeHigh; */

        if (!this->bIsValidPE)
        {
            if (!_bIsFileMapped)
                MapFile();

            return TRUE;
        }
    }

    // Read DOS header
    if (!ReadBytes(reinterpret_cast<LPVOID>(&imgDosHdr), sizeof(IMAGE_DOS_HEADER)))
    {
        this->_dwCurrentOffset = 0;
        SetFilePointer(this->hFileHandle, 0, nullptr, FILE_BEGIN);
        READ_FAIL;
    }

    // Check if e_magic is 'ZM' or 'MZ' - Mark's Zbikowski signature
    if ((0x5A4D != imgDosHdr.e_magic && 0x4D5A != imgDosHdr.e_magic) || GetLastError())
    {
        RETURN_ERROR2(ERROR_INVALID_MAGIC)
    }

    // Retrieving DOS STUB
    DWORD dwActualPos;
    if (this->bMemoryAnalysis == false)
        dwActualPos = SetFilePointer(hFileHandle, 0, nullptr, FILE_CURRENT);
    else
        dwActualPos = sizeof(IMAGE_DOS_HEADER);

    if (imgDosHdr.e_lfanew < sizeof(IMAGE_DOS_HEADER) || imgDosHdr.e_lfanew > PE_MAX_ELFANEW_VALUE)
    {
        RETURN_ERROR2(ERROR_PE_HEADERS_CORRUPTED)
    }

    DWORD dwSizeOfDOSStub = imgDosHdr.e_lfanew - dwActualPos;

    // Read DOS stub
    lpDOSStub.resize(dwSizeOfDOSStub);
    if (!ReadBytes(lpDOSStub.data(), dwSizeOfDOSStub))
    {
        READ_FAIL
    }

    IMAGE_NT_HEADERS32 imgNtHdrs = { 0 };

    if (!ReadBytes(reinterpret_cast<LPVOID>(&imgNtHdrs), IMAGE_SIZEOF_FILE_HEADER)) { READ_FAIL }

    this->bIs86 = ((imgNtHdrs.FileHeader.Machine & IMAGE_FILE_MACHINE_I386) == IMAGE_FILE_MACHINE_I386);
    DWORD dwSectionCount;

    if (this->bIs86)
    {
        ptrSize = 4;
        if (!ReadBytes(reinterpret_cast<LPVOID>(&imgNtHdrs32), sizeof(IMAGE_NT_HEADERS32), imgDosHdr.e_lfanew, AccessMethod::File_Begin, true)) { READ_FAIL }

        if (('EP' != imgNtHdrs32.Signature))
        {
            RETURN_ERROR2(ERROR_INVALID_MAGIC)
        }

        dwSectionCount = imgNtHdrs32.FileHeader.NumberOfSections;

        if (dwSectionCount > PE_MAX_SECTIONS_COUNT)
        {
            dwSectionCount = imgNtHdrs32.FileHeader.NumberOfSections = PE_MAX_SECTIONS_COUNT;
        }
    }
    else
    {
        ptrSize = 8;
        if (!ReadBytes(reinterpret_cast<LPVOID>(&imgNtHdrs64), sizeof(IMAGE_NT_HEADERS64), imgDosHdr.e_lfanew, AccessMethod::File_Begin, true))
        {
            READ_FAIL
        }

        if (('EP' != imgNtHdrs64.Signature))
        {
            RETURN_ERROR2(ERROR_INVALID_MAGIC)
        }

        dwSectionCount = imgNtHdrs64.FileHeader.NumberOfSections;
        if (dwSectionCount > PE_MAX_SECTIONS_COUNT)
        {
            dwSectionCount = imgNtHdrs64.FileHeader.NumberOfSections = PE_MAX_SECTIONS_COUNT;
        }
    }

    if (dwSectionCount == 0)
    {
        RETURN_ERROR2(ERROR_PE_HEADERS_CORRUPTED)
    }

    // Gathering section names
    char szSectionName[PE_MAX_SECTION_NAME_LEN] = "";
    size_t endOfPEData = 0;

    for (size_t i = 0; i < dwSectionCount; i++)
    {
        IMAGE_SECTION_HEADER s;
        if (!ReadBytes(reinterpret_cast<LPVOID>(&s), IMAGE_SIZEOF_SECTION_HEADER))
        {
            READ_FAIL
        }

        memcpy(szSectionName, (const char*)s.Name, sizeof(szSectionName) - 1);
        for (size_t i = 0; i < sizeof(szSectionName); i++)
        {
            if (szSectionName[i] < 0x20 || szSectionName[i] > 0x7f)
            {
                szSectionName[i] = 0x00;
            }
        }

        __IMAGE_SECTION_HEADER d = { 0 };

        d.s = s;
        strncpy_s(d.szSectionName, szSectionName, PE_MAX_SECTION_NAME_LEN - 1);

        vSections.push_back(d);
        auto sectSize = GetSafeSectionSize(d);

        if (bMemoryAnalysis)
        {
            size_t alignedSize = 0;

            if (this->bIs86)
            {
                alignedSize = size_t((sectSize + imgNtHdrs32.OptionalHeader.SectionAlignment - 1) / imgNtHdrs32.OptionalHeader.SectionAlignment) * imgNtHdrs32.OptionalHeader.SectionAlignment;
            }
            else
            {
                alignedSize = size_t((sectSize + imgNtHdrs64.OptionalHeader.SectionAlignment - 1) / imgNtHdrs64.OptionalHeader.SectionAlignment) * imgNtHdrs64.OptionalHeader.SectionAlignment;
            }

            if ((d.s.VirtualAddress + alignedSize) > endOfPEData)
            {
                endOfPEData = d.s.VirtualAddress + alignedSize;
            }
        }
        else
        {
            if (((size_t)d.s.PointerToRawData + (size_t)sectSize) > endOfPEData)
            {
                endOfPEData = (size_t)d.s.PointerToRawData + (size_t)sectSize;
            }
        }
    }

    if (!_bIsFileMapped)
        MapFile();

    // Parse Export Address Table
    if (this->bIs86)
    {
        for (const auto& dir : this->imgNtHdrs32.OptionalHeader.DataDirectory)
        {
            const auto tmp = (bMemoryAnalysis) ? dir.VirtualAddress : RVA2RAW(dir.VirtualAddress);
            if ((tmp + dir.Size) > endOfPEData)
            {
                endOfPEData = tmp + dir.Size;
            }
        }

        try
        {
            if (this->imgNtHdrs32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0)
            {
                if (!ParseIAT())
                {
                    if (this->analysisType != AnalysisType::Dump) return false;
                }
            }
        }
        catch (...)
        {
            RETURN_ERROR2(ERROR_IAT_CORRUPTED);
        }

        try
        {
            if (this->imgNtHdrs32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0)
            {
                if (!ParseEAT())
                {
                    if (this->analysisType != AnalysisType::Dump) return false;
                }
            }
        }
        catch (...)
        {
            RETURN_ERROR2(ERROR_EAT_CORRUPTED);
        }

        try
        {
            if (this->imgNtHdrs32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
            {
                if (!ParseRelocs())
                {
                    if (this->analysisType != AnalysisType::Dump) return false;
                }
            }
        }
        catch (...)
        {
            RETURN_ERROR2(ERROR_RELOCS_CORRUPTED);
        }

        try
        {
            if (this->imgNtHdrs32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress != 0)
            {
                if (!ParseResources())
                {
                    if (this->analysisType != AnalysisType::Dump) return false;
                }
            }
        }
        catch (...)
        {
            RETURN_ERROR2(ERROR_RESOURCES_CORRUPTED);
        }
    }
    else
    {
        for (const auto& dir : this->imgNtHdrs64.OptionalHeader.DataDirectory)
        {
            const auto tmp = (bMemoryAnalysis) ? dir.VirtualAddress : RVA2RAW(dir.VirtualAddress);
            if ((tmp + dir.Size) > endOfPEData)
            {
                endOfPEData = tmp + dir.Size;
            }
        }

        try
        {
            if (this->imgNtHdrs64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0)
            {
                if (!ParseIAT())
                {
                    if (this->analysisType != AnalysisType::Dump) return false;
                }
            }
        }
        catch (...)
        {
            RETURN_ERROR2(ERROR_IAT_CORRUPTED);
        }

        try
        {
            if (this->imgNtHdrs64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0)
            {
                if (!ParseEAT())
                {
                    if (this->analysisType != AnalysisType::Dump) return false;
                }
            }
        }
        catch (...)
        {
            RETURN_ERROR2(ERROR_EAT_CORRUPTED);
        }

        try
        {
            if (this->imgNtHdrs64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
            {
                if (!ParseRelocs())
                {
                    if (this->analysisType != AnalysisType::Dump) return false;
                }
            }
        }
        catch (...)
        {
            RETURN_ERROR2(ERROR_RELOCS_CORRUPTED);
        }

        try
        {
            if (this->imgNtHdrs64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress != 0)
            {
                if (!ParseResources())
                {
                    if (this->analysisType != AnalysisType::Dump) return false;
                }
            }
        }
        catch (...)
        {
            RETURN_ERROR2(ERROR_RESOURCES_CORRUPTED);
        }
    }

    this->_bHasOverlay = (sizeOfFile > endOfPEData);

    return TRUE;
}

bool PE::_OpenFile()
{
    if (this->bMemoryAnalysis)
    {
        if (this->_selfProcessAnalysis)
        {
            hFileHandle = GetCurrentProcess();
            return true;
        }

        return (hFileHandle != (HANDLE)-1 && hFileHandle != (HANDLE)0);
    }

    if (hFileHandle != (HANDLE)-1 && hFileHandle != (HANDLE)0)
        return TRUE;

    /* Open the file */
    RESOLVE_NO_UNHOOK(kernel32, CreateFileA);
    if (this->bReadOnly)
    {
        hFileHandle = _CreateFileA(szFileName.c_str(), GENERIC_READ,
            FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, 0, nullptr);
    }
    else
    {
        hFileHandle = _CreateFileA(szFileName.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
    }

    if (hFileHandle == INVALID_HANDLE_VALUE || ::GetLastError()) {
        RETURN_ERROR2(GetLastError());
    }
    return TRUE;
}

bool PE::UpdateHeaders()
{
    if (!this->bIsValidPE)
    {
        RETURN_ERROR2(ERROR_INVALID_PE)
    }

    if (this->bReadOnly)
    {
        RETURN_ERROR2(ERROR_OPENED_FOR_READ_ONLY)
    }

    this->_dwCurrentOffset = 0;

    if (!WriteBytes(reinterpret_cast<LPVOID>(&imgDosHdr), sizeof(IMAGE_DOS_HEADER), 0, AccessMethod::File_Begin))
    {
        this->_dwCurrentOffset = 0;
        SetFilePointer(this->hFileHandle, 0, nullptr, FILE_BEGIN);
        WRITE_FAIL;
    }

    if (!WriteBytes(lpDOSStub.data(), lpDOSStub.size()))
    {
        this->_dwCurrentOffset = 0;
        SetFilePointer(this->hFileHandle, 0, nullptr, FILE_BEGIN);
        WRITE_FAIL;
    }

    if (this->bIs86)
    {
        imgNtHdrs32.FileHeader.NumberOfSections = static_cast<WORD>(GetSectionsCount());
        if (!WriteBytes(reinterpret_cast<LPVOID>(&imgNtHdrs32), sizeof(IMAGE_NT_HEADERS32), imgDosHdr.e_lfanew, AccessMethod::File_Begin, true))
        {
            WRITE_FAIL
        }
    }
    else
    {
        imgNtHdrs64.FileHeader.NumberOfSections = static_cast<WORD>(GetSectionsCount());
        if (!WriteBytes(reinterpret_cast<LPVOID>(&imgNtHdrs64), sizeof(IMAGE_NT_HEADERS64), imgDosHdr.e_lfanew, AccessMethod::File_Begin, true))
        {
            WRITE_FAIL
        };
    }

    for (size_t i = 0; i < GetSectionsCount(); i++)
    {
        if (!WriteBytes(reinterpret_cast<LPVOID>(&vSections[i].s), IMAGE_SIZEOF_SECTION_HEADER))
        {
            WRITE_FAIL
        }
    }

    // TODO:
    //  - implement IAT & EAT rebuilding
    //  - implement relocations updating

    return true;
}


///////////////////////////////////////////////////////////////////////////////////////

size_t PE::RVA2RAW(size_t dwRVA, bool bForce) const
{
    if (!this->bIsValidPE)
        return dwRVA;

    auto dwSections = static_cast<WORD>(GetSectionsCount());
    size_t dwRAW = dwRVA;

    if (!bForce && bUseRVAInsteadOfRAW)
        return dwRVA;

    if (this->bIs86)
    {
        if (dwRVA > this->GetIB32())
            dwRVA -= this->GetIB32();
    }
    else
    {
        if (dwRVA > this->GetIB64())
            dwRVA -= static_cast<size_t>(this->GetIB64());
    }

    for (size_t i = 0; i < dwSections; i++)
    {
        if (dwRVA >= vSections[i].s.VirtualAddress &&
            dwRVA < ((size_t)vSections[i].s.VirtualAddress
                + (size_t)vSections[i].s.Misc.VirtualSize)) {
            dwRAW = dwRVA - vSections[i].s.VirtualAddress
                + vSections[i].s.PointerToRawData;
            break;
        }
    }
    return dwRAW;
}

///////////////////////////////////////////////////////////////////////////////////////
// RAW address to RVA conversion routine
// Return: converted RAW to RVA, or RAW if couldn't convert (i.e address outside sections)

DWORD PE::RAW2RVA(size_t dwRAW) const
{
    if (!this->bIsValidPE)
        return static_cast<DWORD>(dwRAW);

    size_t dwRVA = dwRAW;
    int i = 0;

    if (this->bIs86)
    {
        if (dwRVA > this->GetIB32())
            dwRVA -= this->GetIB32();
    }
    else
    {
        if (dwRVA > this->GetIB64())
            dwRVA -= static_cast<size_t>(this->GetIB64());
    }

    auto sections = (this->bIs86) ? imgNtHdrs32.FileHeader.NumberOfSections : imgNtHdrs64.FileHeader.NumberOfSections;

	while (i < sections)
	{
		auto sectSize = GetSafeSectionSize(vSections[i]);

		if (vSections[i].s.PointerToRawData <= dwRAW &&
			((size_t)vSections[i].s.PointerToRawData
				+ (size_t)sectSize) > dwRAW)
		{
			dwRVA = dwRAW + vSections[i].s.VirtualAddress
				- vSections[i].s.PointerToRawData;
		}
		i++;
	}
    return static_cast<DWORD>(dwRVA);
}


///////////////////////////////////////////////////////////////////////////////////////
// Function parses Import Address Table.
// Additional argument dwAddressOfIAT could be used as a different base of the IAT (useful when
// on start program hasn't got a valid IAT in DataDirectory[1] ).


bool PE::ParseIAT(DWORD dwAddressOfIAT)
{
    if (!this->bIsValidPE)
    {
        RETURN_ERROR2(ERROR_INVALID_PE)
    }

    // Computing virtual address of Import Address Table
    IMAGE_DATA_DIRECTORY* pIddIAT;

    if (this->bIs86)
    {
        pIddIAT = (IMAGE_DATA_DIRECTORY*)&(imgNtHdrs32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    }
    else
    {
        pIddIAT = (IMAGE_DATA_DIRECTORY*)&(imgNtHdrs64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    }

    std::vector<uint8_t> iatBuffer;

    // Specifying address of IAT
    size_t posIAT;

    if (dwAddressOfIAT == 0)
    {
        if (this->bMemoryAnalysis)
        {
            posIAT = pIddIAT->VirtualAddress;
        }
        else
        {
            posIAT = RVA2RAW(pIddIAT->VirtualAddress);
        }
    }
    else
    {
        if (this->bMemoryAnalysis)
        {
            posIAT = dwAddressOfIAT;
        }
        else
        {
            posIAT = RVA2RAW(dwAddressOfIAT);
        }
    }

    // Validating import DataDirectory
    if (dwAddressOfIAT == 0)
    {
        if (pIddIAT->VirtualAddress == 0 || pIddIAT->Size == 0)
        {
            RETURN_ERROR2(ERROR_IAT_UNACCESSIBLE)
        }

        if (posIAT > this->sizeOfFile || (size_t)posIAT + (size_t)pIddIAT->Size > this->sizeOfFile)
        {
            if (!this->bMemoryAnalysis || (!verifyAddressBounds(posIAT) || !verifyAddressBounds((size_t)posIAT + (size_t)pIddIAT->Size)))
            {
                RETURN_ERROR2(ERROR_IAT_CORRUPTED)
            }

            size_t sizeOfIAT = pIddIAT->Size;
            if (sizeOfIAT > PE_MAX_IAT_SIZE)
            {
                RETURN_ERROR2(ERROR_IAT_TOO_BIG)
            }

            iatBuffer.resize(sizeOfIAT);
            if (!ReadBytes(iatBuffer.data(), sizeOfIAT, (GetImageBase() + pIddIAT->VirtualAddress), AccessMethod::Arbitrary))
            {
                READ_FAIL;
            }
        }
    }

    if (!verifyAddressBounds(posIAT))
    {
        RETURN_ERROR2(ERROR_IAT_CORRUPTED)
    }

    LPVOID lpBuffer;
    size_t dwSizeOfIAT = 0;

    // Here we read from the process memory entire Import Address Table
    if (this->bMemoryAnalysis)
    {
        for (size_t u = 0; u < vSections.size(); u++)
        {
            auto ptr = vSections[u].s;
			if (pIddIAT->VirtualAddress > ptr.VirtualAddress && pIddIAT->VirtualAddress < (ptr.VirtualAddress + GetSafeSectionSize(vSections[u]))) {
                dwSizeOfIAT = pIddIAT->Size;
                break;
            }
        }

        lpBuffer = lpMapOfFile;
    }
    else
    {
        lpBuffer = lpMapOfFile;
    }

    DWORD fix = 0;

    if (!iatBuffer.empty())
    {
        lpBuffer = iatBuffer.data();
        fix = (DWORD)posIAT;
        posIAT = 0;
    }

    IMAGE_IMPORT_DESCRIPTOR _iidTmp = *((IMAGE_IMPORT_DESCRIPTOR*)(reinterpret_cast<intptr_t>(lpBuffer) + posIAT));
    IMAGE_IMPORT_DESCRIPTOR* iidTmp = &_iidTmp;

    IMAGE_THUNK_DATA32* itdTmp32 = nullptr, itdTmp232;
    IMAGE_THUNK_DATA64* itdTmp64 = nullptr, itdTmp264;
    IMAGE_IMPORT_BY_NAME* iibnTmp;
    unsigned                u = 0, b = 0, c = 0;

    // This loop iterates on import descriptors
    size_t num = 0;
    while (num++ < PE_MAX_IAT_DESCRIPTORS)
    {
        if (iidTmp->FirstThunk == 0 && iidTmp->OriginalFirstThunk == 0 && iidTmp->Name == 0)
            break;

        bool fixNeeded = false;
        DWORD _posIAT = (DWORD)posIAT;

        if (fix != 0)
        {
            if (iidTmp->FirstThunk > fix)
            {
                fixNeeded = true;
                iidTmp->FirstThunk -= (fix);
            }

            if (iidTmp->OriginalFirstThunk > fix)
            {
                fixNeeded = true;
                iidTmp->OriginalFirstThunk -= (fix);
            }

            if (iidTmp->Name > fix)
            {
                fixNeeded = true;
                iidTmp->Name -= (fix);
            }

            if (!fixNeeded)
            {
                lpBuffer = lpMapOfFile;
                //_posIAT = 0;
            }
        }

        __IMAGE_IMPORT_DESCRIPTOR iid = {};

        iid.d = *iidTmp;

        if (this->bMemoryAnalysis)
        {
            size_t upper = pIddIAT->Size;
            if (!verifyAddressBounds(iidTmp->FirstThunk, upper)
                || !verifyAddressBounds(iidTmp->Name, upper)
                || !verifyAddressBounds(iidTmp->OriginalFirstThunk, upper))
            {
                break;
            }
        }
        else
        {
            auto FirstThunk = RVA2RAW(iidTmp->FirstThunk);
            auto Name = RVA2RAW(iidTmp->Name);
            auto OriginalFirstThunk = RVA2RAW(iidTmp->OriginalFirstThunk);

            if (FirstThunk > this->sizeOfFile
                || Name > this->sizeOfFile
                || OriginalFirstThunk > this->sizeOfFile)
            {
                break;
            }
        }

        // Copy import descriptor name
        if (this->bMemoryAnalysis) strncpy_s(iid.szName, (const char*)(reinterpret_cast<intptr_t>(lpBuffer) + iidTmp->Name), sizeof(iid.szName) - 1);
        else strncpy_s(iid.szName, (const char*)(reinterpret_cast<intptr_t>(lpBuffer) + RVA2RAW(iidTmp->Name)), sizeof(iid.szName) - 1);

        for (size_t i = 0; i < sizeof(iid.szName); i++)
        {
            if (iid.szName[i] < 0x20 || iid.szName[i] > 0x7f)
            {
                iid.szName[i] = 0x00;
            }
        }

        vImportDescriptors.push_back(iid);
        b = 0;

        // time to iterate on its (import descriptor) imports
        size_t num2 = 0;
        while (num2++ < PE_MAX_IAT_THUNKS)
        {
            IMPORTED_FUNCTION impFunc = {};
            impFunc.uImpDescriptorIndex = u;

            if (!this->bMemoryAnalysis || !iatBuffer.empty())
            {
                if (this->bIs86)
                {
                    memcpy((void*)&itdTmp232, (const void*)(reinterpret_cast<intptr_t>(lpBuffer) + RVA2RAW(iidTmp->FirstThunk)
                        + b * sizeof(IMAGE_THUNK_DATA32)), sizeof(itdTmp232));
                }
                else
                {
                    memcpy((void*)&itdTmp264, (const void*)(reinterpret_cast<intptr_t>(lpBuffer) + RVA2RAW(iidTmp->FirstThunk)
                        + b * sizeof(IMAGE_THUNK_DATA64)), sizeof(itdTmp264));
                }
            }
            else
            {
                // During process/module/memory analysis we have to perform
                // process memory reading to collect valid IMAGE_THUNK_DATA with import address
                if (this->bIs86)
                {
                    if (!ReadBytes(reinterpret_cast<LPVOID>(&itdTmp232), sizeof(itdTmp232),
                        (iidTmp->FirstThunk + b * sizeof(IMAGE_THUNK_DATA32)), AccessMethod::File_Begin))
                    {
                        READ_FAIL;
                    }
                }
                else
                {
                    if (!ReadBytes(reinterpret_cast<LPVOID>(&itdTmp264), sizeof(itdTmp264),
                        (iidTmp->FirstThunk + b * sizeof(IMAGE_THUNK_DATA64)), AccessMethod::File_Begin))
                    {
                        READ_FAIL;
                    }
                }
            }

            if (this->bMemoryAnalysis)
            {
                if (this->bIs86) itdTmp32 = (IMAGE_THUNK_DATA32*)(reinterpret_cast<intptr_t>(lpBuffer) + iidTmp->OriginalFirstThunk + b * sizeof(IMAGE_THUNK_DATA32));
                else itdTmp64 = (IMAGE_THUNK_DATA64*)(reinterpret_cast<intptr_t>(lpBuffer) + iidTmp->OriginalFirstThunk + b * sizeof(IMAGE_THUNK_DATA64));
            }
            else
            {
                if (this->bIs86) itdTmp32 = (IMAGE_THUNK_DATA32*)(reinterpret_cast<intptr_t>(lpBuffer) + RVA2RAW(iidTmp->OriginalFirstThunk) + b * sizeof(IMAGE_THUNK_DATA32));
                else itdTmp64 = (IMAGE_THUNK_DATA64*)(reinterpret_cast<intptr_t>(lpBuffer) + RVA2RAW(iidTmp->OriginalFirstThunk) + b * sizeof(IMAGE_THUNK_DATA64));
            }


            // Checking Image Import Thunk & Descriptor structs
            if (this->bIs86)
            {
                if (iidTmp->OriginalFirstThunk == 0) itdTmp32 = &itdTmp232;
                if (itdTmp32->u1.Function == 0 && itdTmp32->u1.Ordinal == 0) break;

                bool importByOrdinal = (itdTmp32->u1.Function & IMAGE_ORDINAL_FLAG32) != 0;

                if (!fixNeeded)
                {
                    if (!importByOrdinal && itdTmp32->u1.Function > (reinterpret_cast<intptr_t>(lpBuffer) + this->sizeOfFile))
                    {
                        // skip invalid thunk
                        b++;
                        //continue;
                        break;
                    }
                }
                else
                {
                    if ((!importByOrdinal) && (itdTmp32->u1.Function > iatBuffer.size() || ((itdTmp32->u1.Function & 0xfffff) > 0xffff)))
                    {
                        // skip invalid thunk
                        b++;
                        //continue;
                        break;
                    }
                }

                // Rewriting (but firstly getting) address of procedure
                if (importByOrdinal)
                {
                    impFunc.wOrdinal = IMAGE_ORDINAL64(itdTmp32->u1.Ordinal);
                    impFunc.dwPtrValueVA = impFunc.dwPtrValueRVA = 0;
                    memset(impFunc.szFunction, 0, sizeof(impFunc.szFunction) - 1);
                }
                else
                {
                    // Image Import By Name struct
                    iibnTmp = (IMAGE_IMPORT_BY_NAME*)(reinterpret_cast<intptr_t>(lpBuffer) + RVA2RAW(static_cast<size_t>(itdTmp32->u1.Function)));

                    if (iibnTmp->Name == 0 && !importByOrdinal)
                    {
                        // skip invalid thunk
                        b++;
                        //continue;
                        break;
                    }

                    if (!(*(const char*)iibnTmp->Name >= 0x30 && *(const char*)iibnTmp->Name <= 0x7A))
                    {
                        // skip invalid thunk
                        b++;
                        //continue;
                        break;
                    }

                    impFunc.wOrdinal = 0;
                    impFunc.dwPtrValueRVA = itdTmp32->u1.Function;
                    impFunc.dwPtrValueVA = RVA2VA64(itdTmp32->u1.Function);

                    strncpy_s(impFunc.szFunction, (const char*)iibnTmp->Name, sizeof(impFunc.szFunction) - 1);
                    for (size_t i = 0; i < sizeof(impFunc.szFunction); i++)
                    {
                        if (impFunc.szFunction[i] < 0x20 || impFunc.szFunction[i] > 0x7f)
                        {
                            impFunc.szFunction[i] = 0x00;
                        }
                    }

                    impFunc.dwHint = iibnTmp->Hint;
                }
            }
            else
            {
                if (iidTmp->OriginalFirstThunk == 0) itdTmp64 = &itdTmp264;
                if (itdTmp64->u1.Function == 0 && itdTmp64->u1.Ordinal == 0) break;

                bool importByOrdinal = (itdTmp64->u1.Function & IMAGE_ORDINAL_FLAG64) != 0;

                if (!fixNeeded)
                {
                    if (!importByOrdinal && itdTmp64->u1.Function > (reinterpret_cast<intptr_t>(lpBuffer) + this->sizeOfFile))
                    {
                        // skip invalid thunk
                        b++;
                        //continue;
                        break;
                    }
                }
                else
                {
                    if ((!importByOrdinal) && (itdTmp64->u1.Function > iatBuffer.size() || ((itdTmp64->u1.Function & 0xfffff) > 0xffff)))
                    {
                        // skip invalid thunk
                        b++;
                        //continue;
                        break;
                    }
                }

                // Rewriting (but firstly getting) address of procedure
                if (importByOrdinal)
                {
                    impFunc.wOrdinal = IMAGE_ORDINAL64(itdTmp64->u1.Ordinal);
                    impFunc.dwPtrValueVA = impFunc.dwPtrValueRVA = 0;
                    memset(impFunc.szFunction, 0, sizeof(impFunc.szFunction) - 1);
                }
                else
                {
                    // Image Import By Name struct
                    iibnTmp = (IMAGE_IMPORT_BY_NAME*)(reinterpret_cast<intptr_t>(lpBuffer) + RVA2RAW(static_cast<size_t>(itdTmp64->u1.Function)));

                    if (iibnTmp->Name == 0 && !importByOrdinal)
                    {
                        // skip invalid thunk
                        b++;
                        //continue;
                        break;
                    }

                    if (!(*(const char*)iibnTmp->Name >= 0x30 && *(const char*)iibnTmp->Name <= 0x7A))
                    {
                        // skip invalid thunk
                        b++;
                        //continue;
                        break;
                    }

                    impFunc.wOrdinal = 0;
                    impFunc.dwPtrValueRVA = itdTmp64->u1.Function;
                    impFunc.dwPtrValueVA = RVA2VA64(itdTmp64->u1.Function);

                    strncpy_s(impFunc.szFunction, (const char*)iibnTmp->Name, sizeof(impFunc.szFunction) - 1);
                    for (size_t i = 0; i < sizeof(impFunc.szFunction); i++)
                    {
                        if (impFunc.szFunction[i] < 0x20 || impFunc.szFunction[i] > 0x7f)
                        {
                            impFunc.szFunction[i] = 0x00;
                        }
                    }

                    impFunc.dwHint = iibnTmp->Hint;
                }
            }

            // Filing import function structure fields
            impFunc.dwThunkRVA = (iidTmp->FirstThunk + b * sizeof(IMAGE_THUNK_DATA));
            impFunc.uImportIndex = b;

            vImports.push_back(impFunc);
            vImportDescriptors[u].vImports.push_back(impFunc);

            b++;
            c++;
        }

        // Aiming next import descriptor structure
        u++;
        _iidTmp = *((IMAGE_IMPORT_DESCRIPTOR*)(reinterpret_cast<intptr_t>(lpBuffer)
            + _posIAT + (u * sizeof(IMAGE_IMPORT_DESCRIPTOR))));
    }

    if (u == 0 && c == 0)
    {
        RETURN_ERROR2(ERROR_IAT_UNACCESSIBLE)
    }

    this->hasImports = true;
    return TRUE;
}




///////////////////////////////////////////////////////////////////////////////////////
// This function list all EAT (Export Address Table) entries.
// Additional argument dwAddressOfEAT could be used as a different base of the EAT (useful when
// on start program hasn't got a valid EAT in DataDirectory[0] ).

bool PE::ParseEAT(DWORD dwAddressOfEAT)
{
	size_t offset = 0;
	LPVOID lpBuffer = this->lpMapOfFile;
	EXPORTED_FUNCTION expFunc;
	DWORD dwAddr;
	int f = 0;
	WORD wOrdinal = 0;
	ULONGLONG dwRVA = 0, dwNameRAW = 0;
	WORD* aOrdinals;
	DWORD* aAddresses, * aNamesRVA;
	DWORD dwBufSize = 0;

	if (!this->bIsValidPE)
	{
		RETURN_ERROR2(ERROR_INVALID_PE)
	}

	auto codeSection = std::find_if(
		vSections.begin(), vSections.end(), [](const __IMAGE_SECTION_HEADER& ish) {
			return (ish.s.Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE;
		}
	);

	if (codeSection == vSections.end())
	{
		return false;
	}

	// Validating Export Address Table (directory)
	if (dwAddressOfEAT == 0)
	{
		IMAGE_DATA_DIRECTORY* pIddEAT;

		if (this->bIs86)
		{
			pIddEAT = (IMAGE_DATA_DIRECTORY*)&imgNtHdrs32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			dwAddr = imgNtHdrs32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		}
		else
		{
			pIddEAT = (IMAGE_DATA_DIRECTORY*)&imgNtHdrs64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			dwAddr = imgNtHdrs64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		}

		if (pIddEAT->VirtualAddress == 0)
			RETURN_ERROR2(ERROR_EAT_UNACCESSIBLE);

		if ((!verifyAddressBounds(pIddEAT->VirtualAddress) || !verifyAddressBounds((size_t)pIddEAT->VirtualAddress + (size_t)pIddEAT->Size)))
		{
			RETURN_ERROR2(ERROR_EAT_CORRUPTED);
		}
	}
	else
	{
		dwAddr = dwAddressOfEAT;
	}

	if (this->_bIsFileMapped == false)
		MapFile();

	ZeroMemory((void*)&expFunc, sizeof(expFunc));

	const DWORD dwSizeOfEAT = (this->bIs86) ? imgNtHdrs32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size :
		imgNtHdrs64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	offset = reinterpret_cast<intptr_t>(lpBuffer) + this->RVA2RAW(dwAddr);
	this->imgExportDirectory.d = *reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(offset);

	// Validating image_export_directory
	if (imgExportDirectory.d.AddressOfFunctions == 0 &&
		imgExportDirectory.d.AddressOfNameOrdinals == 0 &&
		imgExportDirectory.d.AddressOfNames == 0 &&
		imgExportDirectory.d.Name == 0)
	{
		RETURN_ERROR2(ERROR_EAT_UNACCESSIBLE);
	}

	if (imgExportDirectory.d.NumberOfFunctions > PE_MAX_EXPORTS_NUMBER)
	{
		RETURN_ERROR2(ERROR_TOO_MANY_EXPORTS);
	}

	// Computing offset of a module name
	offset = this->RVA2RAW(imgExportDirectory.d.Name);
	offset += reinterpret_cast<intptr_t>(lpBuffer);

	memset(this->imgExportDirectory.szName, 0, sizeof(this->imgExportDirectory.szName));

	if (verifyAddressBounds(imgExportDirectory.d.Name))
	{
		const char* addr = RVA2RAW(imgExportDirectory.d.Name) + (const char*)lpBuffer;
		size_t len = strlen(addr);
		strncpy_s(this->imgExportDirectory.szName,
			addr, min(sizeof(this->imgExportDirectory.szName), len)
		);
	}

	// Preparing name of exported module.
	if (this->RVA2RAW(dwAddr) > this->sizeOfFile)
	{
		RETURN_ERROR2(ERROR_EAT_CORRUPTED);
	}

	size_t addressOfFunctions;
	if (this->bMemoryAnalysis)
	{
		aOrdinals = (WORD*)(reinterpret_cast<intptr_t>(lpBuffer) + (imgExportDirectory.d.AddressOfNameOrdinals));
		addressOfFunctions = (imgExportDirectory.d.AddressOfFunctions);
		aAddresses = reinterpret_cast<DWORD*>(reinterpret_cast<intptr_t>(lpBuffer) + addressOfFunctions);
		aNamesRVA = reinterpret_cast<DWORD*>(reinterpret_cast<intptr_t>(lpBuffer) + (imgExportDirectory.d.AddressOfNames));
	}
	else
	{
		aOrdinals = (WORD*)(reinterpret_cast<intptr_t>(lpBuffer) +
			this->RVA2RAW(imgExportDirectory.d.AddressOfNameOrdinals));
		addressOfFunctions = this->RVA2RAW(imgExportDirectory.d.AddressOfFunctions);
		aAddresses = reinterpret_cast<DWORD*>(reinterpret_cast<intptr_t>(lpBuffer) + addressOfFunctions);
		aNamesRVA = reinterpret_cast<DWORD*>(reinterpret_cast<intptr_t>(lpBuffer) + this->RVA2RAW(imgExportDirectory.d.AddressOfNames));
	}

	WORD byOrdinal = 0;

	// Iterating all exported functions from this module
	for (f = 0; unsigned(f) < imgExportDirectory.d.NumberOfFunctions; f++)
	{
		ZeroMemory((void*)&expFunc, sizeof(expFunc));

		expFunc.bIsOrdinal = false;
		expFunc.dwOrdinal = 0;
		expFunc.uExportIndex = f;

		if (static_cast<DWORD>(f) >= imgExportDirectory.d.NumberOfNames)
		{
			expFunc.bIsOrdinal = true;
			expFunc.wOrdinal = byOrdinal + static_cast<WORD>(imgExportDirectory.d.Base);
			byOrdinal++;
		}
		else
		{
			expFunc.wOrdinal = aOrdinals[f] + static_cast<WORD>(imgExportDirectory.d.Base);
		}

		wOrdinal = expFunc.wOrdinal;
		size_t eatIndex = static_cast<DWORD>(wOrdinal) - imgExportDirectory.d.Base;

		if (this->bMemoryAnalysis)
		{
			if (!expFunc.bIsOrdinal)
				dwNameRAW = (aNamesRVA[f]) + reinterpret_cast<intptr_t>(lpBuffer);
			expFunc.dwPtrValue = (aAddresses[eatIndex]) + _moduleStartPos;
		}
		else
		{
			if (!expFunc.bIsOrdinal)
				dwNameRAW = this->RVA2RAW(aNamesRVA[f]) + reinterpret_cast<intptr_t>(lpBuffer);

			ULONGLONG imageBase = GetImageBase();
			expFunc.dwPtrValue = (aAddresses[eatIndex]) + (imageBase);
		}

		expFunc.dwPtrValueRVA = aAddresses[eatIndex];
		expFunc.dwThunkRVA = static_cast<DWORD>(addressOfFunctions + eatIndex * sizeof(DWORD));

		if ((dwNameRAW - offset) > this->sizeOfFile)
			break;

		if (expFunc.bIsOrdinal)
		{
		}
		else if (_HexChar(*((char*)dwNameRAW)) == '.') // Parsing name of an export thunk
		{
			expFunc.bIsOrdinal = true;
		}
		else
		{
			strncpy_s(expFunc.szFunction, (const char*)(dwNameRAW), sizeof(expFunc.szFunction) - 1);
		}

		if (expFunc.dwPtrValueRVA > (codeSection->s.VirtualAddress + GetSafeSectionSize(*codeSection)))
		{
			// forwarder
			expFunc.bIsForwarded = true;
			const char* ptr = nullptr;

			if (this->bMemoryAnalysis)
			{
				ptr = reinterpret_cast<const char*>(expFunc.dwPtrValueRVA + reinterpret_cast<intptr_t>(lpBuffer));
			}
			else
			{
				ptr = reinterpret_cast<const char*>(this->RVA2RAW(expFunc.dwPtrValueRVA) + reinterpret_cast<intptr_t>(lpBuffer));
			}

			strncpy_s(expFunc.szForwarder, ptr, sizeof(expFunc.szForwarder));
		}

		if (expFunc.dwPtrValue != 0) vExports.push_back(expFunc);
	}

	this->hasExports = true;
	return TRUE;
}

DWORD PE::GetSafeSectionSize(const __IMAGE_SECTION_HEADER& sect) const
{
	DWORD size = 0;

	if (sect.s.SizeOfRawData > 0)
	{
		size = sect.s.SizeOfRawData;
		if (size > sizeOfFile) size = sizeOfFile;
	}
	else
	{
		for (const auto& nextSect : vSections)
		{
			if (nextSect.s.PointerToRawData > sect.s.PointerToRawData)
			{
				size = nextSect.s.PointerToRawData - sect.s.PointerToRawData;
				break;
			}
		}
	}

	return size;
}

bool PE::ParseRelocs()
{
    LPVOID lpBuffer = this->lpMapOfFile;
    DWORD dwAddr;
    DWORD dwSizeOfRelocs;

    if (!this->bIsValidPE)
    {
        RETURN_ERROR2(ERROR_INVALID_PE)
    }

    // Validating Export Address Table (directory)
    PIMAGE_DATA_DIRECTORY pIddRelocs;

    if (this->bIs86)
    {
        pIddRelocs = (PIMAGE_DATA_DIRECTORY)&imgNtHdrs32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        dwAddr = imgNtHdrs32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        dwSizeOfRelocs = imgNtHdrs32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    }
    else
    {
        pIddRelocs = (PIMAGE_DATA_DIRECTORY)&imgNtHdrs64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        dwAddr = imgNtHdrs64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        dwSizeOfRelocs = imgNtHdrs64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    }

    if (pIddRelocs->VirtualAddress == 0 || dwSizeOfRelocs == 0)
    {
        RETURN_ERROR2(ERROR_NO_RELOCS);
    }

    size_t fileAddr = dwAddr;
    if (!this->bMemoryAnalysis)
    {
        fileAddr = this->RVA2RAW(fileAddr);
    }

    if (fileAddr > this->sizeOfFile
        || dwSizeOfRelocs > this->sizeOfFile
        || this->RVA2RAW(dwAddr) + dwSizeOfRelocs > this->sizeOfFile)
    {
        RETURN_ERROR2(ERROR_RELOCS_CORRUPTED);
    }

    if (this->_bIsFileMapped == false)
        MapFile();

    std::vector<uint8_t> relocsSection;

    // Here we read from the process memory entire Import Address Table
    DWORD sizeOfRelocsFromSectionTable = 0;
    if (this->bMemoryAnalysis)
    {
        for (size_t u = 0; u < vSections.size(); u++)
        {
            auto ptr = vSections[u].s;
			if (pIddRelocs->VirtualAddress >= ptr.VirtualAddress && pIddRelocs->VirtualAddress < (ptr.VirtualAddress + GetSafeSectionSize(vSections[u]))) {
                sizeOfRelocsFromSectionTable = pIddRelocs->Size;
                break;
            }
        }

        if (!sizeOfRelocsFromSectionTable)
        {
            RETURN_ERROR2(ERROR_NO_RELOCS)
        }

        if (sizeOfRelocsFromSectionTable != dwSizeOfRelocs)
        {
            dwSizeOfRelocs = (dwSizeOfRelocs < sizeOfRelocsFromSectionTable) ? dwSizeOfRelocs : sizeOfRelocsFromSectionTable;
        }
    }

    relocsSection.resize((size_t)dwSizeOfRelocs + 1);
    memset(relocsSection.data(), 0, (size_t)dwSizeOfRelocs + 1);

    lpBuffer = relocsSection.data();

    if (!ReadBytes(lpBuffer, dwSizeOfRelocs, fileAddr, AccessMethod::File_Begin))
    {
        READ_FAIL;
    }

    _dwCurrentOffset = dwAddr;
    PIMAGE_BASE_RELOCATION relocsBuffer = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint8_t*>(lpBuffer));

    if (!relocsBuffer->SizeOfBlock || relocsBuffer->SizeOfBlock > sizeof(IMAGE_BASE_RELOCATION) * PE_MAX_BASE_RELOCATIONS)
    {
        RETURN_ERROR2(ERROR_TOO_MANY_RELOCS);
    }

    if (!relocsBuffer->VirtualAddress || !verifyAddressBounds(relocsBuffer->VirtualAddress))
    {
        RETURN_ERROR2(ERROR_RELOCS_CORRUPTED);
    }

    size_t parsedBytes = 0;
    size_t num = 0;
    while (parsedBytes < dwSizeOfRelocs && num++ < PE_MAX_RELOCS_LIMIT)
    {
        PIMAGE_BASE_RELOCATION baseReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint8_t*>(relocsBuffer) + parsedBytes);

        if (baseReloc->VirtualAddress == 0 || baseReloc->SizeOfBlock == 0) break;

        fileAddr = baseReloc->VirtualAddress;
        if (!this->bMemoryAnalysis)
        {
            fileAddr = this->RVA2RAW(baseReloc->VirtualAddress);
        }

        if (fileAddr > this->sizeOfFile
            || baseReloc->SizeOfBlock > dwSizeOfRelocs
            || this->RVA2RAW(baseReloc->VirtualAddress) + baseReloc->SizeOfBlock > this->sizeOfFile)
        {
            continue;
        }

        size_t numOfEntries = (baseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(__IMAGE_RELOC_ENTRY);

        if (numOfEntries > PE_MAX_RELOCS_LIMIT)
        {
            numOfEntries = PE_MAX_RELOCS_LIMIT;
        }

        __IMAGE_RELOCATION relocationObject = { 0 };
        relocationObject.baseRelocation = *baseReloc;

        __IMAGE_RELOC_ENTRY* firstEntryPtr = reinterpret_cast<__IMAGE_RELOC_ENTRY*>(reinterpret_cast<uint8_t*>(baseReloc) + sizeof(IMAGE_BASE_RELOCATION));

        for (size_t relocNum = 0; relocNum < numOfEntries; relocNum++)
        {
            __IMAGE_RELOC_ENTRY* entry = &firstEntryPtr[relocNum];

            if ((entry->offset != 0 || entry->type != 0) && this->RVA2RAW(entry->offset) + 4 < this->sizeOfFile)
            {
                relocationObject.relocs.push_back(*entry);
            }
        }

        if (!relocationObject.relocs.empty())
        {
            vRelocations.push_back(relocationObject);
        }

        parsedBytes += baseReloc->SizeOfBlock;
    }

    if (this->bMemoryAnalysis)
    {
        ApplyAllRelocs(reinterpret_cast<ULONGLONG>(this->lpMapOfFile));
    }

    this->hasRelocs = !vRelocations.empty();
    return true;
}

bool PE::ParseResources()
{
    //
    // PE Resources parsing NOT YET IMPLEMENTED
    //
    return true;


    LPVOID lpBuffer = this->lpMapOfFile;
    DWORD dwAddr;
    DWORD dwSizeOfResources;

    if (!this->bIsValidPE)
    {
        RETURN_ERROR2(ERROR_INVALID_PE)
    }

    // Validating Export Address Table (directory)
    PIMAGE_DATA_DIRECTORY pIddResources;

    if (this->bIs86)
    {
        pIddResources = (PIMAGE_DATA_DIRECTORY)&imgNtHdrs32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
        dwAddr = imgNtHdrs32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        dwSizeOfResources = imgNtHdrs32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
    }
    else
    {
        pIddResources = (PIMAGE_DATA_DIRECTORY)&imgNtHdrs64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
        dwAddr = imgNtHdrs64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        dwSizeOfResources = imgNtHdrs64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
    }

    if (pIddResources->VirtualAddress == 0 || dwSizeOfResources == 0)
    {
        RETURN_ERROR2(ERROR_NO_RESOURCES)
    }

    size_t fileAddr = dwAddr;
    if (!this->bMemoryAnalysis)
    {
        fileAddr = this->RVA2RAW(fileAddr);
    }

    if (fileAddr > this->sizeOfFile
        || dwSizeOfResources > this->sizeOfFile
        || this->RVA2RAW(dwAddr) + dwSizeOfResources > this->sizeOfFile)
    {
        RETURN_ERROR2(ERROR_RESOURCES_CORRUPTED)
    }

    if (this->_bIsFileMapped == false)
        MapFile();

    // Here we read from the process memory entire Import Address Table
    DWORD sizeOfResourcesFromSectionTable = 0;
    if (this->bMemoryAnalysis)
    {
        for (size_t u = 0; u < vSections.size(); u++)
        {
            auto ptr = vSections[u].s;
			if (pIddResources->VirtualAddress >= ptr.VirtualAddress && pIddResources->VirtualAddress < (ptr.VirtualAddress + GetSafeSectionSize(vSections[u]))) {
                sizeOfResourcesFromSectionTable = pIddResources->Size;
                break;
            }
        }

        if (!sizeOfResourcesFromSectionTable)
        {
            RETURN_ERROR2(ERROR_NO_RELOCS)
        }

        if (sizeOfResourcesFromSectionTable != dwSizeOfResources)
        {
            dwSizeOfResources = (dwSizeOfResources < sizeOfResourcesFromSectionTable) ? dwSizeOfResources : sizeOfResourcesFromSectionTable;
        }
    }

    std::vector<uint8_t> resourcesSection;

    resourcesSection.resize((size_t)dwSizeOfResources + 1);
    memset(resourcesSection.data(), 0, (size_t)dwSizeOfResources + 1);

    lpBuffer = resourcesSection.data();

    if (!ReadBytes(resourcesSection.data(), dwSizeOfResources, fileAddr, AccessMethod::File_Begin))
    {
        RETURN_ERROR2(ERROR_READ_LESS_THAN_SHOULD)
    }

    _dwCurrentOffset = dwAddr;
    /*
    PIMAGE_BASE_RELOCATION relocsBuffer = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint8_t*>(lpBuffer));

    if (!relocsBuffer->SizeOfBlock) // || relocsBuffer->SizeOfBlock > sizeof(IMAGE_BASE_RELOCATION) * PE_MAX_BASE_RELOCATIONS )
    {
        return false;
    }

    if (!relocsBuffer->VirtualAddress || relocsBuffer->VirtualAddress > this->sizeOfFile)
    {
        return false;
    }

    */

    //
    // Here comes rest of PE Resources processing logic
    //

    return true;
}

bool PE::ApplyAllRelocs(ULONGLONG newImageBase)
{
    if (!newImageBase)
    {
        return false;
    }

    if (this->bReadOnly)
    {
        return true;
    }

    const ULONGLONG newBase = newImageBase - GetImageBase();

    for (auto imageReloc : vRelocations)
    {
        for (auto reloc : imageReloc.relocs)
        {
            const ULONGLONG fullRVA = (size_t)imageReloc.baseRelocation.VirtualAddress + (size_t)reloc.offset;
            if (fullRVA >= this->sizeOfFile) continue;

            const size_t mapOffset = static_cast<size_t>(fullRVA);
            auto ptr = &this->lpMapOfFile[mapOffset];

            DWORD oldProtection;
            if (!changeProtection(ptr, 8, PAGE_EXECUTE_READWRITE, &oldProtection))
            {
                continue;
            }

            switch (reloc.type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
            {
                break;
            }
            case IMAGE_REL_BASED_DIR64:
            {
                if (mapOffset + sizeof(DWORD64) <= this->sizeOfFile)
                {
                    *reinterpret_cast<DWORD64*>(ptr) += newBase;
                }
                break;
            }
            case IMAGE_REL_BASED_HIGHLOW:
            {
                if (mapOffset + sizeof(DWORD) <= this->sizeOfFile)
                {
                    *reinterpret_cast<DWORD*>(ptr) += static_cast<DWORD>(newBase);
                }
                break;
            }
            case IMAGE_REL_BASED_HIGH:
            {
                if (mapOffset + sizeof(WORD) <= this->sizeOfFile)
                {
                    *reinterpret_cast<WORD*>(ptr) += HIWORD(newBase);
                }
                break;
            }
            case IMAGE_REL_BASED_LOW:
            {
                if (mapOffset + sizeof(WORD) <= this->sizeOfFile)
                {
                    *reinterpret_cast<WORD*>(ptr) += LOWORD(newBase);
                }
                break;
            }
            }

            changeProtection(ptr, 8, oldProtection, nullptr);
        }
    }

    return true;
}

bool PE::ApplyRelocsInBuffer(ULONGLONG newImageBase, ULONGLONG bufferRVA, uint8_t* buffer, size_t sizeOfBuffer, ULONGLONG oldImageBase)
{
    if (!buffer || !sizeOfBuffer || !newImageBase)
    {
        return false;
    }

    const ULONGLONG newBase = newImageBase - ((oldImageBase != 0) ? oldImageBase : GetImageBase());

    for (auto imageReloc : vRelocations)
    {
        for (auto reloc : imageReloc.relocs)
        {
            const ULONGLONG fullRVA = (size_t)imageReloc.baseRelocation.VirtualAddress + (size_t)reloc.offset;
            const ULONGLONG upperBufferRVA = (bufferRVA + static_cast<ULONGLONG>(sizeOfBuffer));

            if (fullRVA >= bufferRVA && fullRVA < upperBufferRVA)
            {
                const size_t bufferOffset = static_cast<size_t>(fullRVA - bufferRVA);
                auto ptr = &buffer[bufferOffset];

                switch (reloc.type)
                {
                case IMAGE_REL_BASED_ABSOLUTE:
                {
                    break;
                }
                case IMAGE_REL_BASED_DIR64:
                {
                    if (bufferOffset + sizeof(DWORD64) <= sizeOfBuffer)
                    {
                        *reinterpret_cast<DWORD64*>(ptr) += newBase;
                    }
                    break;
                }
                case IMAGE_REL_BASED_HIGHLOW:
                {
                    if (bufferOffset + sizeof(DWORD) <= sizeOfBuffer)
                    {
                        *reinterpret_cast<DWORD*>(ptr) += static_cast<DWORD>(newBase);
                    }
                    break;
                }
                case IMAGE_REL_BASED_HIGH:
                {
                    if (bufferOffset + sizeof(WORD) <= sizeOfBuffer)
                    {
                        *reinterpret_cast<WORD*>(ptr) += HIWORD(newBase);
                    }
                    break;
                }
                case IMAGE_REL_BASED_LOW:
                {
                    if (bufferOffset + sizeof(WORD) <= sizeOfBuffer)
                    {
                        *reinterpret_cast<WORD*>(ptr) += LOWORD(newBase);
                    }
                    break;
                }
                }
            }
        }
    }

    return true;
}


///////////////////////////////////////////////////////////////////////////////////////
// Function fills whole IAT in memory (by collecting thunk address through GetProcAddress)
// Additional parameters: dwAddresses and dwElements can be used as an independent
// addresses table. During IAT filling normally routine gains thunks addresses by calling
// GetProcAddress. Instead, user can put his own table with thunk addresses, but this
// table must have EXACTLY every address to every thunk. In other words speaking,
// dwAddresses must point to table which will contain address to all thunks.
// dwElements specifies elements in dwAddresses table. Of course, dwElements must be equal to
// actual imports quanity.

bool PE::FillIAT(DWORD* dwAddresses, DWORD dwElements)
{
    if (!this->bIsValidPE)
        RETURN_ERROR2(ERROR_INVALID_PE)

        HMODULE    hModule;
    DWORD64    addr = 0;
    int        i = 0;

    // If there is not enough addresses in dwAddresses table, then return false
    if (dwAddresses != nullptr)
        if (vImportDescriptors.size() != dwElements)
            return FALSE;

    for (size_t u = 0; u < vImportDescriptors.size(); u++)
    {
        hModule = LoadLibraryA(vImportDescriptors[u].szName);

        // Couldn't load library, omit
        if (hModule == nullptr)
            continue;

        for (size_t n = 0; n < vImportDescriptors[u].vImports.size(); n++)
        {
            if (dwAddresses != nullptr)
                addr = dwAddresses[n];
            else
            {
                if (vImportDescriptors[u].vImports[n].wOrdinal != 0)
                {
                    if (this->bIs86)
                    {
                        auto nthdrs = reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<intptr_t>(hModule) + reinterpret_cast<PIMAGE_DOS_HEADER>(hModule)->e_lfanew);
                        auto exportdir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&nthdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
                        auto exportdirVA = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<intptr_t>(hModule) + exportdir->VirtualAddress);
                        auto arrayOfAddressesVA = reinterpret_cast<intptr_t>(hModule) + exportdirVA->AddressOfFunctions;
                        arrayOfAddressesVA += IMAGE_ORDINAL32((vImportDescriptors[u].vImports[n].wOrdinal) - (exportdirVA->Base) * ptrSize);
                        addr = reinterpret_cast<intptr_t>(hModule) + *reinterpret_cast<DWORD*>(arrayOfAddressesVA);
                    }
                    else
                    {
                        auto nthdrs = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<intptr_t>(hModule) + reinterpret_cast<PIMAGE_DOS_HEADER>(hModule)->e_lfanew);
                        auto exportdir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&nthdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
                        auto exportdirVA = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<intptr_t>(hModule) + exportdir->VirtualAddress);
                        auto arrayOfAddressesVA = reinterpret_cast<intptr_t>(hModule) + exportdirVA->AddressOfFunctions;
                        arrayOfAddressesVA += IMAGE_ORDINAL64((vImportDescriptors[u].vImports[n].wOrdinal) - (exportdirVA->Base) * ptrSize);
                        addr = reinterpret_cast<intptr_t>(hModule) + *reinterpret_cast<ULONGLONG*>(arrayOfAddressesVA);
                    }
                }
                else
                {
                    addr = reinterpret_cast<intptr_t>(GetProcAddress(hModule, vImportDescriptors[u].vImports[n].szFunction));
                }
            }

            // Couldn't gain address of thunk, omit
            if (addr == 0)
                continue;

            vImportDescriptors[u].vImports[n].dwPtrValueVA = addr;
            vImportDescriptors[u].vImports[n].dwPtrValueRVA = addr - reinterpret_cast<intptr_t>(hModule);
            vImports[i].dwPtrValueVA = addr;
            vImports[i].dwPtrValueRVA = addr - reinterpret_cast<intptr_t>(hModule);

            i++;
            if (this->bIs86)
            {
                DWORD* dwAddr2 = reinterpret_cast<DWORD*>(reinterpret_cast<intptr_t>(lpMapOfFile) + RVA2RAW(vImportDescriptors[u].d.FirstThunk
                    + n * ptrSize));

                *dwAddr2 = static_cast<DWORD>(addr);
            }
            else
            {
                DWORD64* dwAddr2 = reinterpret_cast<DWORD64*>(reinterpret_cast<intptr_t>(lpMapOfFile) + RVA2RAW(vImportDescriptors[u].d.FirstThunk
                    + n * ptrSize));

                *dwAddr2 = static_cast<DWORD64>(addr);
            }
        }

        FreeLibrary(hModule);
    }

    // I don't know why exactly I've crafted this variable?
    _bIsIATFilled = true;
    return TRUE;
}

///////////////////////////////////////////////////////////////////////////////////////
// Function appends new section to the file/memory.

__IMAGE_SECTION_HEADER
PE::CreateSection(DWORD dwSizeOfSection, DWORD dwDesiredAccess, const std::string& szNameOfSection)
{
    __IMAGE_SECTION_HEADER   ish;
    DWORD                    dwFileAlignment = 0,
        dwNewVirtualAddress = 0,
        dwSectionAlignment = 0;

    memset((void*)&ish, 0, sizeof(ish));

    if (!this->bIsValidPE)
    {
        SET_ERROR2(ERROR_INVALID_PE);
        return {};
    }

    dwFileAlignment = (this->bIs86) ? imgNtHdrs32.OptionalHeader.FileAlignment : imgNtHdrs64.OptionalHeader.FileAlignment;
    dwSectionAlignment = (this->bIs86) ? imgNtHdrs32.OptionalHeader.SectionAlignment : imgNtHdrs64.OptionalHeader.SectionAlignment;

	//dwNewVirtualAddress     =   (GetSafeSectionSize(GetLastSection()) / dwSectionAlignment)
	//                            * dwSectionAlignment + GetLastSection()->VirtualAddress;

	dwNewVirtualAddress = GetSafeSectionSize(GetLastSection()) + GetLastSection().s.VirtualAddress;

	// section name
	if (szNameOfSection.size() < IMAGE_SIZEOF_SHORT_NAME)
		strcpy_s(reinterpret_cast<char*>(ish.s.Name), sizeof(ish.s.Name), szNameOfSection.c_str());
	else
		memcpy((char*)ish.s.Name, szNameOfSection.c_str(), IMAGE_SIZEOF_SHORT_NAME);

	ish.s.SizeOfRawData = dwSizeOfSection;
	ish.s.VirtualAddress = dwNewVirtualAddress;
	ish.s.Misc.VirtualSize = (dwSizeOfSection / dwFileAlignment + 1) * dwFileAlignment;
	ish.s.Characteristics = dwDesiredAccess;

	//ish.PointerToRawData    =    GetLastSection()->PointerToRawData + GetSafeSectionSize(GetLastSection());
	ish.s.PointerToRawData = static_cast<DWORD>(this->sizeOfFile);

	this->numOfNewSections++;
	DWORD sectionSizeRounded = (dwSizeOfSection / dwSectionAlignment + 1) * dwSectionAlignment;
	DWORD numOfSections;

    if (this->bIs86)
    {
        imgNtHdrs32.FileHeader.NumberOfSections++;
        imgNtHdrs32.OptionalHeader.SizeOfImage += sectionSizeRounded;
        numOfSections = imgNtHdrs32.FileHeader.NumberOfSections;
    }
    else
    {
        imgNtHdrs64.OptionalHeader.SizeOfImage += sectionSizeRounded;
        imgNtHdrs64.FileHeader.NumberOfSections++;
        numOfSections = imgNtHdrs64.FileHeader.NumberOfSections;
    }

    strncpy_s(ish.szSectionName, PE_MAX_SECTION_NAME_LEN, szNameOfSection.c_str(), szNameOfSection.size());
    adjustOptionalHeader();

    return ish;
}

__IMAGE_SECTION_HEADER PE::RemoveSection(size_t index)
{
    if (index > this->vSections.size() || index < 0) return {};
    auto sect = this->vSections[index];

    this->vSections.erase(this->vSections.begin() + index);

    adjustOptionalHeader();
    return sect;
}

///////////////////////////////////////////////////////////////////////////////////////
// Function prepares additional shellcode and loads specified shellcode from the file.
// In shellcode user is not obliged to write JMP back instructions, this function
// takes care about it. It simply appends szAdditionalShellcode to the user's shellcode
// which makes a far jmp to the Original image Entry Point.
//
// If dwOEP == 0 -> will enter infinite loop after running the shellcode.

bool PE::AppendShellcode(BYTE* whereToReturn, uint8_t* shellcode, size_t sizeOfShellcode, __IMAGE_SECTION_HEADER* imgNewSection)
{
    if (!this->bIsValidPE)
    {
        RETURN_ERROR2(ERROR_INVALID_PE)
    }

    if (this->bReadOnly)
    {
        RETURN_ERROR2(ERROR_OPENED_FOR_READ_ONLY)
    }

    uint8_t szAdditionalShellcode[32] = { 0x90 };

    if (whereToReturn != 0)
    {
        auto jmp = getJumpPayload(reinterpret_cast<BYTE*>(whereToReturn));
        size_t size = jmp.size() < sizeof(szAdditionalShellcode) ? jmp.size() : sizeof(szAdditionalShellcode);
        memcpy(szAdditionalShellcode, &jmp[0], size);
    }

    std::vector<uint8_t> buf;
    buf.resize(sizeOfShellcode + sizeof(szAdditionalShellcode) + 1);

    memset(buf.data(), 0x90, sizeOfShellcode + sizeof(szAdditionalShellcode) + 1);

    memcpy(buf.data(), shellcode, sizeOfShellcode);
    memcpy(&buf[sizeOfShellcode], szAdditionalShellcode, sizeof(szAdditionalShellcode));

    DWORD dwTmp = (this->bIs86) ? imgNtHdrs32.OptionalHeader.SizeOfImage : imgNtHdrs64.OptionalHeader.SizeOfImage;
    dwTmp += static_cast<DWORD>(sizeOfShellcode + sizeof(szAdditionalShellcode) + 1);

    // Align actual size of image
    DWORD sectionAlignment = (this->bIs86) ? imgNtHdrs32.OptionalHeader.SectionAlignment : imgNtHdrs64.OptionalHeader.SectionAlignment;
    DWORD dwTmp2 = (dwTmp / sectionAlignment + 1) * sectionAlignment;

    // Set new, aligned size of image
    if (this->bIs86)
    {
        imgNtHdrs32.OptionalHeader.SizeOfImage = dwTmp2;
    }
    else
    {
        imgNtHdrs64.OptionalHeader.SizeOfImage = dwTmp2;
    }

    bool bRes = TRUE;

    if (this->bUseRVAInsteadOfRAW)
    {
        bRes = WriteBytes(buf.data(), buf.size() - 1, imgNewSection->s.VirtualAddress, AccessMethod::File_Begin);
    }
    else
    {
        bRes = WriteBytes(buf.data(), buf.size() - 1, imgNewSection->s.PointerToRawData, AccessMethod::File_Begin);
    }

    if (!bRes)
    {
        WRITE_FAIL;
    }

    return TRUE;
}

std::vector<uint8_t> PE::getJumpPayload(BYTE* whereToJump)
{
    /* Below shellcode does:
     *
     *      B8(dwRelocatedEP)   MOV eax, dwRelocatedEP
     *      FFE0                JMP eax
    **/

    if (this->bIs86)
    {
        uint8_t tmp[4] = { 0 };

#pragma warning(suppress: 4311)
#pragma warning(suppress: 4302)
        convert32ToLECharArray(tmp, reinterpret_cast<uint32_t>(whereToJump));

        uint8_t _szAdditionalShellcode[] = {
            0xB8, tmp[3], tmp[2], tmp[1], tmp[0], 0xFF, 0xE0,
        };

        return std::vector<uint8_t>(_szAdditionalShellcode, _szAdditionalShellcode + sizeof(_szAdditionalShellcode));
    }
    else
    {
        uint8_t tmp[8] = { 0 };
        convert64ToLECharArray(tmp, reinterpret_cast<uint64_t>(whereToJump));

        uint8_t _szAdditionalShellcode[] = {
            0x48, 0xB8,
            tmp[7], tmp[6], tmp[5], tmp[4], tmp[3], tmp[2], tmp[1], tmp[0],
            0xFF, 0xE0
        };

        return std::vector<uint8_t>(_szAdditionalShellcode, _szAdditionalShellcode + sizeof(_szAdditionalShellcode));
    }
}

void PE::AddNewSection(size_t sizeOfSection, DWORD flags, const std::string& szSectionName)
{
    __IMAGE_SECTION_HEADER ish;

    ish = CreateSection(
        static_cast<DWORD>(sizeOfSection),
        flags,
        szSectionName
    );

    vSections.push_back(ish);
}


///////////////////////////////////////////////////////////////////////////////////////
// Inserts shellcode to the file/memory

DWORD PE::InsertShellcode(uint8_t* shellcode, size_t sizeOfShellcode, const std::string& szSectionName, BYTE* returnAddress)
{
    if (!this->bIsValidPE)
    {
        RETURN_ERROR2(ERROR_INVALID_PE)
    }

    if (this->bReadOnly)
    {
        RETURN_ERROR2(ERROR_OPENED_FOR_READ_ONLY)
    }

    AddNewSection(
        static_cast<DWORD>(sizeOfShellcode + 32),
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        szSectionName
    );

    auto ish = GetLastSection();

    if (!AppendShellcode(returnAddress, shellcode, sizeOfShellcode, &ish))
        return 0;

    if (!UpdateHeaders())
    {
        return 0;
    }

    if (this->bMemoryAnalysis)
        return GetLastSection().s.VirtualAddress;

    return GetLastSection().s.PointerToRawData;
}

bool PE::changeProtection(LPVOID address, size_t size, DWORD newProtection, LPDWORD oldProtection)
{
    //if (this->bReadOnly) return true;
    if (this->hFileHandle == nullptr) return false;

    RESOLVE_NO_UNHOOK(kernel32, VirtualProtectEx);
    DWORD _oldProtection;

    auto out = _VirtualProtectEx(
        this->hFileHandle,
        address,
        static_cast<DWORD>(size),
        PAGE_READWRITE,
        &_oldProtection
    );

    if (oldProtection != nullptr)
    {
        *oldProtection = _oldProtection;
    }

    return out;
}

///////////////////////////////////////////////////////////////////////////////////////
// This routine performs file/memory READING.

bool PE::ReadBytes(LPVOID lpBuffer, size_t dwSize, size_t dwOffset, AccessMethod method, bool dontRestoreFilePointer)
{
    DWORD    dwRead = 0;
    size_t    sizeRead = 0;
    LONG    offsetHigh;
    DWORD    dwLastOffs = 0;
    DWORD    dwOldProtect = 0;

    if (!lpBuffer || dwSize == 0)
    {
        RETURN_ERROR2(ERROR_INVALID_PARAMETER);
    }

    SetLastError(0);

    if (!this->bMemoryAnalysis)
    {
        // Save file pointer
        if (dwOffset != 0)
        {
            offsetHigh = (dwOffset & 0xFFFFFFFF00000000) >> 32;
            LONG offsetLow = (dwOffset & 0xFFFFFFFF);
            DWORD dwMethod = 0;

            switch (method)
            {
            case AccessMethod::File_Current: dwMethod = FILE_CURRENT; break;
            case AccessMethod::File_Begin: dwMethod = FILE_BEGIN; break;
            case AccessMethod::File_End:
            {
                dwMethod = FILE_END;
                offsetLow = -static_cast<LONG>(dwOffset);
                break;
            }
            default: dwMethod = FILE_BEGIN; break;
            }

            dwLastOffs = SetFilePointer(hFileHandle, offsetLow, &offsetHigh, dwMethod);
            if (dwLastOffs == 0xFFFFFFFF || ::GetLastError() || dwLastOffs == INVALID_SET_FILE_POINTER)
                RETURN_ERROR
        }
    }
    else
    {
        dwLastOffs = static_cast<DWORD>(_dwCurrentOffset);

        if (method != AccessMethod::Arbitrary)
        {
            if (method == AccessMethod::File_Current)
            {
                _dwCurrentOffset += dwOffset;
            }
            else if (method == AccessMethod::File_Begin)
            {
                _dwCurrentOffset = dwOffset;
            }
            else if (method == AccessMethod::File_End)
            {
                _dwCurrentOffset = sizeOfFile - dwOffset;
            }
        }
        else
        {
            _dwCurrentOffset = dwOffset;
        }
    }

    bool bRes;
    if (this->bMemoryAnalysis /*&& this->bIsValidPE */)
    {
        auto addr = reinterpret_cast<intptr_t>(lpMapOfFile) + _dwCurrentOffset;
        auto addr2 = _moduleStartPos + _dwCurrentOffset;

        RESOLVE_NO_UNHOOK(kernel32, ReadProcessMemory);
        if (method == AccessMethod::Arbitrary)
        {
            changeProtection(reinterpret_cast<LPVOID>(_dwCurrentOffset), dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

            if (this->_selfProcessAnalysis)
            {
                memcpy(lpBuffer, reinterpret_cast<LPCVOID>(_dwCurrentOffset), dwSize);
                sizeRead = dwSize;
                bRes = true;
            }
            else
            {
                bRes = _ReadProcessMemory(this->hFileHandle, reinterpret_cast<LPCVOID>(_dwCurrentOffset),
                    lpBuffer, dwSize, reinterpret_cast<SIZE_T*>(&sizeRead));
            }

            changeProtection(reinterpret_cast<LPVOID>(_dwCurrentOffset), dwSize, dwOldProtect, &dwRead);

            auto err = GetLastError();
            if (!bRes)
            {
                RETURN_ERROR2(err);
            }
            else if (dwSize != sizeRead)
            {
                RETURN_ERROR2(ERROR_READ_LESS_THAN_SHOULD);
            }

            SetLastError(0);
        }
        else if (addr2 < static_cast<ULONGLONG>(_moduleStartPos) || addr2 > static_cast<ULONGLONG>(_moduleStartPos + sizeOfFile))
        {
            changeProtection(reinterpret_cast<LPVOID>(addr2), dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

            if (this->_selfProcessAnalysis)
            {
                memcpy(lpBuffer, reinterpret_cast<LPCVOID>(addr2), dwSize);
                sizeRead = dwSize;
                bRes = true;
            }
            else
            {
                bRes = _ReadProcessMemory(this->hFileHandle, reinterpret_cast<LPCVOID>(addr2),
                    lpBuffer, dwSize, reinterpret_cast<SIZE_T*>(&sizeRead));
            }

            auto err = GetLastError();

            changeProtection(reinterpret_cast<LPVOID>(addr2), dwSize, dwOldProtect, &dwRead);

            if (!bRes)
            {
                RETURN_ERROR2(err);
            }
            else if (dwSize != sizeRead)
            {
                RETURN_ERROR2(ERROR_READ_LESS_THAN_SHOULD)
            }

            SetLastError(0);
        }
        else
        {
            memcpy(lpBuffer, (LPCVOID)(addr), dwSize);
            sizeRead = dwSize;
        }
    }
    else
    {
        bRes = ReadFile(hFileHandle, lpBuffer, static_cast<DWORD>(dwSize), &dwRead, nullptr);
        if (!bRes || ::GetLastError())
        {
            RETURN_ERROR;
        }
        else if (dwSize != dwRead)
        {
            RETURN_ERROR2(ERROR_READ_LESS_THAN_SHOULD);
        }
    }

    if (!this->bMemoryAnalysis)
    {
        // Restore last file pointer
        if (dwOffset != 0 && !dontRestoreFilePointer)
        {
            LONG offsetLow = (dwLastOffs & 0xFFFFFFFF);
            dwLastOffs = SetFilePointer(hFileHandle, offsetLow, &offsetHigh, FILE_BEGIN);
            if (dwLastOffs == 0xFFFFFFFF || ::GetLastError())
            {
                RETURN_ERROR;
            }
        }
    }
    else
    {
        if (!dontRestoreFilePointer)
        {
            _dwCurrentOffset = dwLastOffs;
        }
    }

    if (this->bIsValidPE) _dwCurrentOffset += dwSize;

    SetLastError(0);
    return TRUE;
}



///////////////////////////////////////////////////////////////////////////////////////
// This routine performs file/memory WRITING.

bool PE::WriteBytes(LPVOID lpBuffer, size_t dwSize, size_t dwOffset, AccessMethod method, bool dontRestoreFilePointer)
{
    size_t    sizeWritten = 0;
    DWORD   dwWritten = 0;
    LONG    offsetHigh = 0;
    DWORD    dwLastOffs = 0;
    DWORD    dwOldProtect = 0;

    if (this->bReadOnly)
    {
        RETURN_ERROR2(ERROR_OPENED_FOR_READ_ONLY)
    }

    if (!lpBuffer || dwSize == 0)
    {
        RETURN_ERROR2(ERROR_INVALID_PARAMETER);
    }

    SetLastError(0);

    // Save current file pointer
    if (!this->bMemoryAnalysis)
    {
        // Save file pointer
        if (dwOffset != 0)
        {
            offsetHigh = (dwOffset & 0xFFFFFFFF00000000) >> 32;
            LONG offsetLow = (dwOffset & 0xFFFFFFFF);
            DWORD dwMethod = 0;

            switch (method)
            {
            case AccessMethod::File_Current: dwMethod = FILE_CURRENT; break;
            case AccessMethod::File_Begin: dwMethod = FILE_BEGIN; break;
            case AccessMethod::File_End: dwMethod = FILE_END; break;
            default: dwMethod = FILE_BEGIN; break;
            }

            dwLastOffs = SetFilePointer(hFileHandle, offsetLow, &offsetHigh, dwMethod);
            if (dwLastOffs == 0xFFFFFFFF || ::GetLastError())
            {
                RETURN_ERROR
            }
        }
    }
    else
    {
        dwLastOffs = static_cast<DWORD>(_dwCurrentOffset);

        if (method != AccessMethod::Arbitrary)
        {
            if (method == AccessMethod::File_Current)
            {
                _dwCurrentOffset += dwOffset;
            }
            else if (method == AccessMethod::File_Begin)
            {
                _dwCurrentOffset = dwOffset;
            }
            else if (method == AccessMethod::File_End)
            {
                _dwCurrentOffset = sizeOfFile - dwOffset;
            }
        }
        else
        {
            _dwCurrentOffset = dwOffset;
        }
    }

    bool bRes;

    if (this->bMemoryAnalysis && this->bIsValidPE)
    {
        auto addr = reinterpret_cast<intptr_t>(lpMapOfFile) + _dwCurrentOffset;
        auto addr2 = _moduleStartPos + _dwCurrentOffset;

        RESOLVE_NO_UNHOOK(kernel32, WriteProcessMemory);
        if (method == AccessMethod::Arbitrary)
        {
            changeProtection(reinterpret_cast<LPVOID>(_dwCurrentOffset), dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
            auto err = GetLastError();

            if (this->_selfProcessAnalysis)
            {
                memcpy(reinterpret_cast<LPVOID>(_dwCurrentOffset), lpBuffer, dwSize);
                sizeWritten = dwSize;
                bRes = true;
            }
            else
            {
                bRes = _WriteProcessMemory(this->hFileHandle, reinterpret_cast<LPVOID>(_dwCurrentOffset),
                    lpBuffer, dwSize, reinterpret_cast<SIZE_T*>(&sizeWritten));
            }

            err = GetLastError();

            changeProtection(reinterpret_cast<LPVOID>(_dwCurrentOffset), dwSize, dwOldProtect, &dwWritten);
            err = GetLastError();
            if (!bRes)
            {
                RETURN_ERROR2(err)
            }
            else if (dwSize != sizeWritten)
            {
                RETURN_ERROR2(ERROR_READ_LESS_THAN_SHOULD)
            }

            SetLastError(0);
        }
        else if (addr2 > static_cast<ULONGLONG>(_moduleStartPos) || addr2 < static_cast<ULONGLONG>(_moduleStartPos + sizeOfFile))
        {
            changeProtection(reinterpret_cast<LPVOID>(addr2), dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

            if (this->_selfProcessAnalysis)
            {
                memcpy(reinterpret_cast<LPVOID>(addr2), lpBuffer, dwSize);
                sizeWritten = dwSize;
                bRes = true;
            }
            else
            {
                bRes = _WriteProcessMemory(this->hFileHandle, reinterpret_cast<LPVOID>(addr2),
                    lpBuffer, dwSize, reinterpret_cast<SIZE_T*>(&sizeWritten));
            }

            auto err = GetLastError();

            changeProtection(reinterpret_cast<LPVOID>(addr2), dwSize, dwOldProtect, &dwWritten);

            if (!bRes)
            {
                RETURN_ERROR2(err);
            }
            else if (dwSize != sizeWritten)
            {
                RETURN_ERROR2(ERROR_READ_LESS_THAN_SHOULD);
            }

            SetLastError(0);
        }

        if (method != AccessMethod::Arbitrary && (addr > reinterpret_cast<uintptr_t>(lpMapOfFile) || addr < (reinterpret_cast<uintptr_t>(lpMapOfFile) + sizeOfFile)))
        {
            if (reinterpret_cast<intptr_t>(lpMapOfFile) != _moduleStartPos) memcpy((LPVOID)(addr), lpBuffer, dwSize);
            sizeWritten = dwSize;
        }
    }
    else
    {
        bRes = WriteFile(this->hFileHandle, lpBuffer, static_cast<DWORD>(dwSize), &dwWritten, nullptr);

        if (hFileHandle || ::GetLastError())
        {
            RETURN_ERROR
        }
        else if (dwSize != dwWritten)
        {
            RETURN_ERROR2(ERROR_WRITE_LESS_THAN_SHOULD)
        }
    }

    if (!this->bMemoryAnalysis)
    {
        // Restore last file pointer
        if (dwOffset != 0 && !dontRestoreFilePointer)
        {
            LONG offsetLow = (dwLastOffs & 0xFFFFFFFF);
            dwLastOffs = SetFilePointer(hFileHandle, offsetLow, &offsetHigh, FILE_BEGIN);
            if (dwLastOffs == 0xFFFFFFFF || ::GetLastError())
            {
                RETURN_ERROR
            }
        }
    }
    else
    {
        if (!dontRestoreFilePointer)
        {
            _dwCurrentOffset = dwLastOffs;
        }
    }

    if (this->bIsValidPE) _dwCurrentOffset += dwSize;

    return TRUE;
}



///////////////////////////////////////////////////////////////////////////////////////
// This method simply maps file in the memory.

LPBYTE PE::MapFile()
{
    if (_bIsFileMapped || lpMapOfFile != 0)
        return lpMapOfFile;

    if (hFileHandle == nullptr)
        _OpenFile();

    const DWORD page = (this->bReadOnly) ? PAGE_READONLY : PAGE_READWRITE;

    RESOLVE_NO_UNHOOK(kernel32, CreateFileMappingA);
    _hMapOfFile = _CreateFileMappingA(
        hFileHandle,
        nullptr,
        page | SEC_COMMIT,
        bhFileInformation.nFileSizeHigh,
        bhFileInformation.nFileSizeLow,
        nullptr
    );

    if (_hMapOfFile == nullptr || ::GetLastError())
    {
        RETURN_ERROR
    }

    _bAutoMapOfFile = true;

    RESOLVE_NO_UNHOOK(kernel32, MapViewOfFile);

    const DWORD mapFlags = (this->bReadOnly) ? FILE_MAP_READ : FILE_MAP_ALL_ACCESS;
    lpMapOfFile = (LPBYTE)_MapViewOfFile(_hMapOfFile, mapFlags, 0, 0, 0);
    if (lpMapOfFile == nullptr || ::GetLastError())
    {
        RETURN_ERROR
    }

    _bIsFileMapped = true;
    this->lpMapOfFile = lpMapOfFile;

    return (LPBYTE)lpMapOfFile;
}

///////////////////////////////////////////////////////////////////////////////////////
// This functions examine sended as parameter char code, and returns it or dot code

inline char PE::_HexChar(int c)
{
    if (c >= 0x20 /* space */ && c <= 0x7D /* '}' */)return (char)c;
    //if( c > 0x1F && c != 0x7F && c != 0x81 && c < 0xFF) return (char)c;
    else return '.';
}


bool PE::AnalyseMemory(DWORD dwPID, LPBYTE dwAddress, size_t dwSize, bool readOnly, bool isMapped)
{
    this->bUseRVAInsteadOfRAW = this->bIsValidPE =
        this->_bIsFileMapped = this->bMemoryAnalysis = true;
    this->lpMapOfFile = dwAddress;
    this->sizeOfFile = dwSize;
    this->bPreferBaseAddressThanImageBase = !isMapped;
    this->_bAutoMapOfFile = false;
    this->bReadOnly = readOnly;

    if (isMapped) this->analysisType = AnalysisType::MappedModule;
    else this->analysisType = AnalysisType::Memory;

    DWORD flags = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

    if (!readOnly) flags |= PROCESS_VM_WRITE | PROCESS_VM_OPERATION;

    if (dwPID == 0 || dwPID == GetCurrentProcessId())
    {
        this->hFileHandle = GetCurrentProcess();
        this->_selfProcessAnalysis = true;
        this->dwPID = GetCurrentProcessId();
    }
    else
    {
        RESOLVE_NO_UNHOOK(kernel32, OpenProcess);
        this->hFileHandle = _OpenProcess(flags, FALSE, dwPID);
    }

    auto err = ::GetLastError();
    if (this->hFileHandle == nullptr)
    {
        RETURN_ERROR
    }

    if (dwSize == 0)
    {
        RESOLVE_NO_UNHOOK(kernel32, VirtualQueryEx);

        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (!_VirtualQueryEx(this->hFileHandle, dwAddress, &mbi, sizeof(mbi)))
        {
            RETURN_ERROR
        }

        dwSize = mbi.RegionSize;
        uint8_t buf[1024] = { 0 };
        DWORD dwOldProtect, dwRead;
        bool success = false;

        changeProtection(reinterpret_cast<LPVOID>(dwAddress), _countof(buf), PAGE_EXECUTE_READWRITE, &dwOldProtect);

        if (this->_selfProcessAnalysis)
        {
            memcpy(buf, reinterpret_cast<LPCVOID>(dwAddress), _countof(buf));
            success = true;
        }
        else
        {
            SIZE_T sizeRead = 0;
            RESOLVE_NO_UNHOOK(kernel32, ReadProcessMemory);

            bool bRes = _ReadProcessMemory(this->hFileHandle, reinterpret_cast<LPCVOID>(dwAddress),
                buf, _countof(buf), reinterpret_cast<SIZE_T*>(&sizeRead));
            success = bRes;
        }

        changeProtection(reinterpret_cast<LPVOID>(dwAddress), _countof(buf), dwOldProtect, &dwRead);

        if (success)
        {
            auto imgDos = reinterpret_cast<PIMAGE_DOS_HEADER>(buf);
            auto imgFileHdr = reinterpret_cast<PIMAGE_FILE_HEADER>(&buf[imgDos->e_lfanew + 4]);
            if ((imgFileHdr->Machine & IMAGE_FILE_MACHINE_AMD64) == 0)
            {
                auto ntHdrs = reinterpret_cast<PIMAGE_NT_HEADERS32>(&buf[imgDos->e_lfanew]);
                this->sizeOfFile = dwSize = ntHdrs->OptionalHeader.SizeOfImage;
            }
            else
            {
                auto ntHdrs = reinterpret_cast<PIMAGE_NT_HEADERS64>(&buf[imgDos->e_lfanew]);
                this->sizeOfFile = dwSize = max(this->sizeOfFile, ntHdrs->OptionalHeader.SizeOfImage);
            }
        }
    }

    this->bIsValidPE = true;

    if (!this->_selfProcessAnalysis)
    {
        SetLastError(0);
        this->lpMapOfFile = reinterpret_cast<LPBYTE>(VirtualAlloc(nullptr, this->sizeOfFile + 1,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (this->lpMapOfFile == nullptr)
        {
            RETURN_ERROR
        }

        _moduleStartPos = reinterpret_cast<intptr_t>(dwAddress);

        if (!ReadEntireModuleSafely(this->lpMapOfFile, sizeOfFile, _moduleStartPos))
        {
            RETURN_ERROR2(ERROR_READ_LESS_THAN_SHOULD)
        }
    }
    else
    {
        this->lpMapOfFile = dwAddress;
        _moduleStartPos = reinterpret_cast<size_t>(dwAddress);
    }

    _dwCurrentOffset = 0;
    char fileName[MAX_PATH] = { 0 };
    strncpy_s(fileName, MAX_PATH, szFileName.c_str(), MAX_PATH);

    GetModuleFileNameA(GetModuleHandle(nullptr), fileName, sizeof szFileName);

    SetLastError(0);
    _dwLastError = 0;

    return PE::LoadFile();
}

///////////////////////////////////////////////////////////////////////////////////////
// Launches process module analysis by specifying desired module HMODULE handle

bool PE::AnalyseProcessModule(DWORD dwPID, HMODULE hModule, bool readOnly)
{
    this->bMemoryAnalysis = true;
    this->_bIsFileMapped = true;
    this->dwPID = dwPID;
    this->bUseRVAInsteadOfRAW = true;
    this->bReadOnly = readOnly;
    this->analysisType = AnalysisType::MappedModule;


    DWORD flags = PROCESS_VM_READ | PROCESS_VM_OPERATION;

    if (!readOnly) flags |= PROCESS_VM_WRITE;

    if (dwPID == 0 || dwPID == GetCurrentProcessId())
    {
        this->hFileHandle = GetCurrentProcess();
        this->_selfProcessAnalysis = true;
    }
    else
    {
        RESOLVE_NO_UNHOOK(kernel32, OpenProcess);
        this->hFileHandle = _OpenProcess(flags, FALSE, dwPID);
    }

    auto err = ::GetLastError();
    if (this->hFileHandle == nullptr)
    {
        RETURN_ERROR
    }

    if (dwPID == 0 || dwPID == GetCurrentProcessId())
    {
        MODULEINFO modInfo = { 0 };
        if (!GetModuleInformation(this->hFileHandle, hModule, &modInfo, sizeof(MODULEINFO)))
        {
            RETURN_ERROR
        }

        this->lpMapOfFile = reinterpret_cast<LPBYTE>(modInfo.lpBaseOfDll);
        if (this->lpMapOfFile == nullptr)
        {
            RETURN_ERROR
        }

        sizeOfFile = modInfo.SizeOfImage;
        _moduleStartPos = reinterpret_cast<intptr_t>(modInfo.lpBaseOfDll);
        _dwCurrentOffset = 0;
        _selfProcessAnalysis = true;
        this->bIsValidPE = true;
        this->_bAutoMapOfFile = false;
    }
    else
    {
        if (this->hFileHandle == nullptr || ::GetLastError())
        {
            RETURN_ERROR
        }

        RESOLVE_NO_UNHOOK(kernel32, CreateToolhelp32Snapshot);
        RESOLVE_NO_UNHOOK(kernel32, Module32FirstW);
        RESOLVE_NO_UNHOOK(kernel32, Module32NextW);

        HANDLE hSnap = _CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
        if (hSnap == nullptr || hSnap == (HANDLE)INVALID_HANDLE_VALUE ||
            ::GetLastError())
        {
            RETURN_ERROR
        }

        MODULEENTRY32W me32 = { 0 };
        me32.dwSize = sizeof(MODULEENTRY32W);
        bool found = false;

        if (!_Module32FirstW(hSnap, &me32))
        {
            CloseHandle(hSnap);
            SET_ERROR;
            return FALSE;
        }

        do
        {
            auto modBase = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
            auto hModulePtr = reinterpret_cast<uintptr_t>(hModule);

            if (me32.hModule == hModule || modBase == hModulePtr)
            {
                found = true;
                break;
            }

            if (!_Module32NextW(hSnap, &me32))
            {
                if (::GetLastError() != ERROR_NO_MORE_FILES)
                {
                    RETURN_ERROR;
                }

                break;
            }
        } while (true);

        if (found)
        {
            auto a = std::wstring(me32.szExePath);
            szFileName = std::string(a.begin(), a.end());
            this->bIsValidPE = true;

            SetLastError(0);
            sizeOfFile = me32.modBaseSize;
            _moduleStartPos = reinterpret_cast<intptr_t>(me32.modBaseAddr);

            if (!this->_selfProcessAnalysis)
            {
                this->lpMapOfFile = reinterpret_cast<LPBYTE>(VirtualAlloc(nullptr, this->sizeOfFile + 1,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
                if (this->lpMapOfFile == nullptr)
                {
                    RETURN_ERROR
                }

                if (!ReadEntireModuleSafely(this->lpMapOfFile, sizeOfFile, _moduleStartPos))
                {
                    RETURN_ERROR2(ERROR_READ_LESS_THAN_SHOULD)
                }
            }
            else
            {
                this->lpMapOfFile = reinterpret_cast<LPBYTE>(_moduleStartPos);
            }

            _dwCurrentOffset = 0;
        }

        CloseHandle(hSnap);

        auto err = ::GetLastError();
        if (this->lpMapOfFile == nullptr)
        {
            RETURN_ERROR
        }
    }

    return LoadFile();
}

///////////////////////////////////////////////////////////////////////////////////////
// Launches process module analysis by specifying desired module name/path

bool PE::AnalyseProcessModule(DWORD dwPID, const std::string& szModule, bool readOnly)
{
    this->bMemoryAnalysis = true;
    this->_bIsFileMapped = true;
    this->dwPID = dwPID;
    this->bUseRVAInsteadOfRAW = true;
    this->bReadOnly = readOnly;
    this->analysisType = AnalysisType::MappedModule;

    std::wstring desiredModuleName;
    size_t desiedModuleSize = 0;
    BYTE* desiredModuleBaseAddress = nullptr;

    DWORD flags = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

    if (!readOnly) flags |= PROCESS_VM_WRITE | PROCESS_VM_OPERATION;

    if (dwPID == 0 || dwPID == GetCurrentProcessId())
    {
        this->hFileHandle = GetCurrentProcess();
        this->_selfProcessAnalysis = true;
        if (!szModule.empty()) dwPID = GetCurrentProcessId();
        this->_bAutoMapOfFile = false;
    }
    else
    {
        RESOLVE_NO_UNHOOK(kernel32, OpenProcess);
        this->hFileHandle = _OpenProcess(flags, FALSE, dwPID);
    }

    auto err = ::GetLastError();
    if (this->hFileHandle == nullptr)
    {
        RETURN_ERROR
    }

    // Get process module name - hereby we have to enumerate process's modules :-)
    HANDLE hSnap = nullptr;
    if (dwPID != 0)
    {
        RESOLVE_NO_UNHOOK(kernel32, CreateToolhelp32Snapshot);
        hSnap = _CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
        err = GetLastError();
    }

    if ((err == ERROR_PARTIAL_COPY || dwPID == 0) && szModule.empty())
    {
        // Failed creating a toolhelp of loaded process modules. Most likely the module
        // is suspended at the moment. If we are trying to analyse main executable image,
        // a call for it's PEB and related ImageBase would be sufficient to proceed.
        BOOL success;
        PROCESS_BASIC_INFORMATION pbi = { 0 };
        DWORD retLen;
        SIZE_T bytesRead;

        uint8_t buf[1024] = { 0 };
        wchar_t dst[MAX_PATH] = { 0 };
        GetModuleFileNameExW(this->hFileHandle, NULL, dst, MAX_PATH);

        desiredModuleName = std::wstring(dst);
        desiedModuleSize = 0;

        // Read the PEB from the target process
        if (this->hFileHandle == GetCurrentProcess())
        {
            PPEB ppebLocal = nullptr;
#if defined(_WIN64)
            ppebLocal = (PPEB)__readgsqword(0x60);
#else
            ppebLocal = (PPEB)__readfsdword(0x30);
#endif

            if (ppebLocal == nullptr)
            {
                return false;
            }
            success = true;

            desiredModuleBaseAddress = reinterpret_cast<BYTE*>(ppebLocal->Reserved3[1]);
            memcpy(buf, reinterpret_cast<LPCVOID>(desiredModuleBaseAddress), sizeof(buf));

        }
        else
        {
            PEB pebLocal = { 0 };

            RESOLVE_NO_UNHOOK(ntdll, NtQueryInformationProcess);
            RESOLVE_NO_UNHOOK(kernel32, ReadProcessMemory);

            /*

            using fn_NtQueryInformationProcess = NTSTATUS NTAPI(
                HANDLE ProcessHandle,
                DWORD ProcessInformationClass,
                PVOID ProcessInformation,
                DWORD ProcessInformationLength,
                PDWORD ReturnLength
            );

            auto _NtQueryInformationProcess = reinterpret_cast<fn_NtQueryInformationProcess*>(
                ::GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess")
                );

            */

            _NtQueryInformationProcess(
                this->hFileHandle,
                ProcessBasicInformation,
                &pbi,
                sizeof(pbi),
                &retLen
            );

            success = _ReadProcessMemory(
                this->hFileHandle,
                reinterpret_cast<LPCVOID>(pbi.PebBaseAddress),
                &pebLocal,
                sizeof(PEB),
                &bytesRead
            );
            if (!success) {
                return false;
            }

            desiredModuleBaseAddress = reinterpret_cast<BYTE*>(pebLocal.Reserved3[1]);

            success = _ReadProcessMemory(
                this->hFileHandle,
                reinterpret_cast<LPCVOID>(desiredModuleBaseAddress),
                buf,
                sizeof(buf),
                &bytesRead
            );
            if (!success) {
                return false;
            }
        }

        IMAGE_DOS_HEADER* imgdos = reinterpret_cast<PIMAGE_DOS_HEADER>(&buf[0]);
        if (imgdos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > (sizeof(buf)))
        {
            return false;
        }

        bool bIs86 = (((reinterpret_cast<PIMAGE_NT_HEADERS32>(&buf[0] + imgdos->e_lfanew)->FileHeader.Machine) & IMAGE_FILE_MACHINE_I386) == IMAGE_FILE_MACHINE_I386);

        if (bIs86)
        {
            desiedModuleSize = reinterpret_cast<PIMAGE_NT_HEADERS32>(&buf[0] + imgdos->e_lfanew)->OptionalHeader.SizeOfImage;
        }
        else
        {
            desiedModuleSize = reinterpret_cast<PIMAGE_NT_HEADERS64>(&buf[0] + imgdos->e_lfanew)->OptionalHeader.SizeOfImage;
        }

        this->bIsValidPE = true;
    }
    else  if (hSnap == nullptr || hSnap == (HANDLE)INVALID_HANDLE_VALUE)
    {
        RETURN_ERROR
    }
    else
    {
        RESOLVE_NO_UNHOOK(kernel32, Module32FirstW);
        RESOLVE_NO_UNHOOK(kernel32, Module32NextW);

        MODULEENTRY32W me32 = { 0 };
        memset((void*)&me32, 0, sizeof me32);
        me32.dwSize = sizeof(MODULEENTRY32W);

        if (!_Module32FirstW(hSnap, &me32))
        {
            CloseHandle(hSnap);
            SET_ERROR;
            return FALSE;
        }

        auto a = std::wstring(me32.szModule);
        std::string iterMod(a.begin(), a.end());
        if (iterMod.find(szModule) != std::string::npos || szModule.find(iterMod) != std::string::npos)
        {
            szFileName = iterMod;
        }
        else
        {
            a = std::wstring(me32.szModule);
            iterMod = std::string(a.begin(), a.end());

            std::transform(iterMod.begin(), iterMod.end(), iterMod.begin(),
                [](unsigned char c) { return std::tolower(c); });

            while (iterMod.find(szModule) == std::string::npos && szModule.find(iterMod) == std::string::npos)
            {
                if (!_Module32NextW(hSnap, &me32))
                {
                    RETURN_ERROR
                }

                a = std::wstring(me32.szModule);
                iterMod = std::string(a.begin(), a.end());

                std::transform(iterMod.begin(), iterMod.end(), iterMod.begin(),
                    [](unsigned char c) { return std::tolower(c); });
            }
        }

        desiredModuleName = std::wstring(iterMod.begin(), iterMod.end());
        desiredModuleBaseAddress = reinterpret_cast<BYTE*>(me32.modBaseAddr);
        desiedModuleSize = me32.modBaseSize;
    }

    if (!desiredModuleName.empty() && desiredModuleBaseAddress != nullptr && desiedModuleSize != 0)
    {
        auto a = std::wstring(desiredModuleName);
        szFileName = std::string(a.begin(), a.end());

        this->bIsValidPE = true;

        if (this->hFileHandle != GetCurrentProcess())
        {
            SetLastError(0);
            this->lpMapOfFile = reinterpret_cast<LPBYTE>(VirtualAlloc(nullptr, desiedModuleSize + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
            if (this->lpMapOfFile == nullptr)
            {
                RETURN_ERROR
            }

            this->sizeOfFile = desiedModuleSize;
            _moduleStartPos = reinterpret_cast<intptr_t>(desiredModuleBaseAddress);

            if (!ReadEntireModuleSafely(this->lpMapOfFile, sizeOfFile, _moduleStartPos))
            {
                RETURN_ERROR2(ERROR_READ_LESS_THAN_SHOULD)
            }

            _dwCurrentOffset = 0;
        }
        else
        {
            this->lpMapOfFile = desiredModuleBaseAddress;
            this->sizeOfFile = desiedModuleSize;
            _moduleStartPos = reinterpret_cast<size_t>(desiredModuleBaseAddress);
        }
    }

    if (hSnap != nullptr) CloseHandle(hSnap);

    err = ::GetLastError();
    if (this->lpMapOfFile == nullptr)
    {
        RETURN_ERROR2(err);
    }

    return LoadFile();
}

bool PE::ReadEntireModuleSafely(LPVOID lpBuffer, size_t dwSize, size_t dwOffset)
{
    if (!this->bMemoryAnalysis)
    {
        return false;
    }

    BYTE* address = reinterpret_cast<BYTE*>(dwOffset);
    MEMORY_BASIC_INFORMATION mbi = {};
    RESOLVE_NO_UNHOOK(kernel32, VirtualQueryEx);

    size_t bytesRead = 0;

    while (address < reinterpret_cast<BYTE*>(dwOffset + dwSize))
    {
        if (!_VirtualQueryEx(this->hFileHandle, address, &mbi, sizeof(mbi)))
        {
            RETURN_ERROR;
        }

        auto toRead = mbi.RegionSize;
        if ((bytesRead + mbi.RegionSize) > dwSize)
        {
            toRead = dwSize - ((bytesRead + mbi.RegionSize));
        }

        std::vector<uint8_t> buf;
        buf.resize(toRead + 1);

        memset(buf.data(), 0, toRead + 1);

        auto test = address - dwOffset;

        if (!ReadBytes(buf.data(), toRead, reinterpret_cast<size_t>(address), AccessMethod::Arbitrary))
        {
            memset(buf.data(), 0, toRead);
        }

        //memcpy(&reinterpret_cast<BYTE*>(lpBuffer)[reinterpret_cast<intptr_t>(mbi.BaseAddress)], buf, toRead);
        BYTE* ptr = reinterpret_cast<BYTE*>(lpBuffer);
        ptr += bytesRead;

        memcpy(ptr, buf.data(), toRead);

        bytesRead += toRead;
        address += toRead;
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////////////
// Trims from input string every quote '"' character. Useful during obfuscating
// file paths.

std::string& PE::trimQuote(std::string& path) const
{
    path.erase(
        std::remove(path.begin(), path.end(), '\"'),
        path.end()
    );;

    return path;
}

///////////////////////////////////////////////////////////////////////////////////////
// Hooks IAT thunk

ULONGLONG PE::HookIAT(const std::string& szImportThunk, ULONGLONG hookedVA)
{
    if (!this->bIsValidPE)
    {
        RETURN_ERROR2(ERROR_INVALID_PE)
    }

    ULONGLONG dwOEP = 0;

    for (size_t u = 0; u < vImports.size(); u++)
    {
        if (0 != szImportThunk.compare(vImports[u].szFunction))
            continue;

        dwOEP = vImports[u].dwPtrValueVA;

        __IMAGE_IMPORT_DESCRIPTOR* importDescriptor = &this->vImportDescriptors[vImports[u].uImpDescriptorIndex];

        vImports[u].dwPtrValueVA = hookedVA;
        vImports[u].dwPtrValueRVA = 0;
        size_t whereToPatch = importDescriptor->d.FirstThunk + u * ptrSize;

        // Exact hooking
        if (!WriteBytes(reinterpret_cast<LPVOID>(&hookedVA), ptrSize, whereToPatch, AccessMethod::File_Begin))
        {
            WRITE_FAIL;
        }

        break;
    }

    return dwOEP;
}


///////////////////////////////////////////////////////////////////////////////////////
// Hooks EAT thunk.

DWORD PE::HookEAT(const std::string& szExportThunk, DWORD hookedRVA)
{
    if (!this->bIsValidPE)
    {
        RETURN_ERROR2(ERROR_INVALID_PE);
    }

    if (!this->hasExports)
    {
        return 0;
    }

    for (size_t u = 0; u < vExports.size(); u++)
    {
        if (0 != szExportThunk.compare(vExports[u].szFunction))
            continue;

        DWORD dwOEP = static_cast<DWORD>(vExports[u].dwThunkRVA);

        size_t addressOfFunctions = 0;
        if (this->bMemoryAnalysis)
        {
            addressOfFunctions = (this->imgExportDirectory.d.AddressOfFunctions);
        }
        else
        {
            addressOfFunctions = this->RVA2RAW(this->imgExportDirectory.d.AddressOfFunctions);
        }

        vExports[u].dwPtrValue = (vExports[u].dwPtrValue - vExports[u].dwThunkRVA) + hookedRVA;
        vExports[u].dwPtrValueRVA = hookedRVA;

        size_t whereToPatch = addressOfFunctions + u * sizeof(DWORD);

        // Exact hooking
        if (!WriteBytes(reinterpret_cast<LPVOID>(&hookedRVA), sizeof(DWORD), whereToPatch, AccessMethod::File_Begin))
        {
            WRITE_FAIL;
        }

        return dwOEP;
    }

    return 0;
}

std::vector<uint8_t> PE::ReadOverlay()
{
	const size_t pos = (size_t)GetLastSection().s.PointerToRawData + (size_t)GetSafeSectionSize(GetLastSection());

    if (pos > sizeOfFile)
    {
        _dwLastError = (ERROR_READ_LESS_THAN_SHOULD);
        return {};
    }

    size_t num = sizeOfFile - pos;
    std::shared_ptr<uint8_t> buffer(new uint8_t[num + 2]);
    memset(buffer.get(), 0, num + 2);

    if (!ReadBytes(buffer.get(), num, pos, AccessMethod::File_Begin))
    {
        return {};
    }

    return { buffer.get(), buffer.get() + num };
}

std::vector<uint8_t> PE::ReadSection(const __IMAGE_SECTION_HEADER& section)
{
	const size_t num = GetSafeSectionSize(section);
	const size_t pos = (bMemoryAnalysis) ? section.s.VirtualAddress : section.s.PointerToRawData;

    if (pos > sizeOfFile)
    {
        _dwLastError = (ERROR_READ_LESS_THAN_SHOULD);
        return {};
    }

    std::shared_ptr<uint8_t> buffer(new uint8_t[num + 2]);
    memset(buffer.get(), 0, num + 2);

    if (!ReadBytes(buffer.get(), num, pos, AccessMethod::File_Begin))
    {
        return {};
    }

    return { buffer.get(), buffer.get() + num };
}

bool PE::verifyAddressBounds(uintptr_t address, bool relative)
{
    return verifyAddressBounds(address, 0, this->sizeOfFile, relative);
}

bool PE::verifyAddressBounds(uintptr_t address, size_t upperBoundary, bool relative)
{
    return verifyAddressBounds(address, 0, upperBoundary, relative);
}

bool PE::verifyAddressBounds(uintptr_t address, size_t lowerBoundary, size_t upperBoundary, bool relative)
{
    const size_t addr = static_cast<size_t>(address);

    if (!this->bMemoryAnalysis)
    {
        if (addr < lowerBoundary) return false;

        if (relative)
        {
            auto raw = RVA2RAW(addr);
            if (raw > upperBoundary) return false;
            if (raw == addr) return false;          // address is outside of any section
        }
        else
        {
            if (addr > upperBoundary) return false;
        }
    }
    else
    {
        if (this->analysisType == AnalysisType::MappedModule)
        {
            size_t addr2 = addr;

            if (relative)
            {
                if (ptrSize == 4)
                {
                    addr2 = this->RVA2VA32((DWORD)addr);
                }
                else
                {
                    addr2 = this->RVA2VA64((DWORD)addr);
                }
            }

            auto memoryMap = collectProcessMemoryMap();
            for (const auto& m : memoryMap)
            {
                if (addr2 > reinterpret_cast<uintptr_t>(m.BaseAddress)
                    && addr2 < (reinterpret_cast<uintptr_t>(m.BaseAddress) + m.RegionSize))
                {
                    if ((m.Protect & PAGE_READONLY) == 0 && (m.Protect & PAGE_EXECUTE_READWRITE) == 0 &&
                        (m.Protect & PAGE_READWRITE) == 0)
                    {
                        return false;
                    }
                }
            }
        }
        else
        {
            if (addr > upperBoundary) return false;
        }
    }

    return true;
}

std::vector<MEMORY_BASIC_INFORMATION> PE::collectProcessMemoryMap()
{
    static std::vector<MEMORY_BASIC_INFORMATION> out;

    if (!out.empty()) return out;

    const size_t MaxSize = (sizeof(ULONG_PTR) == 4) ? ((1ULL << 31) - 1) : ((1ULL << 63) - 1);

    uint8_t* address = 0;
    RESOLVE_NO_UNHOOK(kernel32, VirtualQueryEx);
    while (reinterpret_cast<size_t>(address) < MaxSize)
    {
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (!_VirtualQueryEx(this->hFileHandle, address, &mbi, sizeof(mbi)))
        {
            break;
        }

        out.push_back(mbi);
        address += mbi.RegionSize;
    }

    return out;
}

void PE::adjustOptionalHeader()
{
	if (this->bIs86)
	{
		PIMAGE_OPTIONAL_HEADER32 phdr = &imgNtHdrs32.OptionalHeader;
		phdr->SizeOfImage = this->vSections.back().s.VirtualAddress + this->vSections.back().s.Misc.VirtualSize;
		phdr->SizeOfCode = phdr->SizeOfUninitializedData = phdr->SizeOfInitializedData = 0;

		for (const auto& sect : this->vSections)
		{
			auto sectSize = GetSafeSectionSize(sect);
			if (sect.s.Characteristics & IMAGE_SCN_CNT_CODE) phdr->SizeOfCode += sectSize;
			if (sect.s.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) phdr->SizeOfInitializedData += sectSize;
			if (sect.s.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) phdr->SizeOfUninitializedData += sectSize;
		}
	}
	else
	{
		PIMAGE_OPTIONAL_HEADER64 phdr = &imgNtHdrs64.OptionalHeader;
		phdr->SizeOfImage = this->vSections.back().s.VirtualAddress + this->vSections.back().s.Misc.VirtualSize;
		phdr->SizeOfCode = phdr->SizeOfUninitializedData = phdr->SizeOfInitializedData = 0;

		for (const auto& sect : this->vSections)
		{
			auto sectSize = GetSafeSectionSize(sect);
			if (sect.s.Characteristics & IMAGE_SCN_CNT_CODE) phdr->SizeOfCode += sectSize;
			if (sect.s.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) phdr->SizeOfInitializedData += sectSize;
			if (sect.s.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) phdr->SizeOfUninitializedData += sectSize;
		}
	}
}