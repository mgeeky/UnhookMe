#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <functional>
#include <map>

#include "PE.h"
#include "usings.h"

#pragma warning(disable: 6387)
#pragma warning(disable: 4005)

//
// Helper macrodefintions to easily plug ADVobfuscator/MetaString.h
// 


#define OBF(x) x
#define OBFI(x) x
#define OBF_ASCII(x) x
#define OBFI_ASCII(x) x
#define ADV_OBF(x) x
#define ADV_OBF_W(x) x
#define OBF_WSTR(x) std::wstring(x)
#define OBF_STR(x) std::string(x)

/*
    In order to use Resolver a function pointer type must be first declared
    with "using" statement of strict form:

        using fn_FunctionName = ReturnType WINAPI (
            ParamType1 paramName1,
            ...,
            ParamTypeN paramNameN,
        );

    The FunctionName will correspond to the WinAPI that we want to have ImportResolver resolve
    and that function pointer must be marked as having WINAPI call convention (__stdcall on 
    x86 and __fastcall on x64). The ReturnType must precede "WINAPI" type modifier.

    Having function pointer type defined like specified above, we will be able to use it in 
    the following manner:

        RESOLVE(libraryName, FunctionName);
        ReturnType output = _FunctionName(param1, ..., paramN);

    The macro `RESOLVE` takes care of instantiating ImportResolver templated object,
    adjust given library's name.
    
    Resolver's constructor:

        template<typename Ret, typename ...Args>
        ImportResolver<Ret WINAPI(Args...)>(
                std::string dllName,
                std::string funcName,
                bool _unhook = false,
                bool *_wasItHooked = nullptr
            )
*/

//
// Macrodefinition Parameters:
//   - mod:     library name exporting specified function
//   - func:    function to import
//   - unhook:  whether to do function anti-splicing/unhooking if it was hooked
//
#define RESOLVE_PARAMETERIZED(mod, func, unhook)                           \
    static auto _ ## func = UnhookingImportResolver::ImportResolver<fn_ ## func>(   \
        UnhookingImportResolver::adjustPathA(OBFI_ASCII(#mod)), OBFI_ASCII(#func),  \
        unhook);

#define RESOLVE(mod, func)  RESOLVE_PARAMETERIZED(mod, func, true)
#define RESOLVE_NO_UNHOOK(mod, func)  RESOLVE_PARAMETERIZED(mod, func, false)


namespace UnhookingImportResolver
{
    template <typename T>
    class ImportResolver {};

	template<typename T>
	bool stringicompare(const T& a, const T& b)
	{
		if (a.length() != b.length()) return false;

		return std::equal(
			a.begin(),
			a.end(),
			b.begin(),
			[](const unsigned short& a, const unsigned short& b)
			{
				return (std::tolower(a) == std::tolower(b));
			}
		);
	}

    template<typename T>
    struct ImportResolverCache
    {
        ImportResolverCache() : cachedResolvedImports{}, cachedModuleBases{} {};

        std::map<T, uint32_t> functionResolutionCount;
        std::map<std::pair<T, T>, FARPROC> cachedResolvedImports;
        std::map<T, HINSTANCE> cachedModuleBases;

        T getModuleName(const T& dllName)
        {
            std::string name = dllName;
            std::string suffix = ".dll";

            if (0 != name.compare(name.size() - suffix.size(), suffix.size(), suffix)) name += suffix;

            static std::map<T, T> cachedNames;
            if (cachedNames.count(name) != 0)
            {
                return cachedNames[name];
            }

            const auto lastBackslash = name.rfind(static_cast<typename T::value_type>('\\'));
            if (lastBackslash != T::npos)
            {
                cachedNames[name] = T(name, lastBackslash + 1);
                return cachedNames[name];
            }

            return name;
        }

        FARPROC getCached(const T& dllName, const T& funcName)
        {
            const auto name = getModuleName(dllName);
            const auto tmp = std::make_pair<const T&, const T&>(name, funcName);
            if (cachedResolvedImports.count(tmp) != 0)
            {
                functionResolutionCount[funcName]++;
                return cachedResolvedImports[tmp];
            }

            return nullptr;
        }

        void setCachedFunction(const T& dllName, const T& funcName, FARPROC func)
        {
            const auto name = getModuleName(dllName);
            cachedResolvedImports[std::make_pair(name, funcName)] = func;
            functionResolutionCount[funcName] = 1;
        }

        HINSTANCE getModule(const T& dllName)
        {
            const auto name = getModuleName(dllName);
            if (cachedModuleBases.count(name) != 0)
            {
                return cachedModuleBases[name];
            }

            cachedModuleBases[name] = ::GetModuleHandleA(dllName.c_str());
            return cachedModuleBases[name];
        }

        void invalidateModule(const T& dllName)
        {
            auto name = getModuleName(dllName);
            if (cachedModuleBases.count(name) != 0)
            {
                cachedModuleBases[name] = nullptr;
                cachedModuleBases.erase(name);
            }

            std::vector<std::string> funcs;
            for (auto const& moduleFuncPair : cachedResolvedImports)
            {
                std::string mod = moduleFuncPair.first.first;
                if(stringicompare(mod, name)) funcs.push_back(moduleFuncPair.first.second);
            }

            for (auto const& func : funcs) {
                invalidateFunction(name, func);
            }
        }

        void invalidateFunction(const T& dllName, const T& funcName)
        {
            const auto name = getModuleName(dllName);
            const auto tmp = std::make_pair<const T&, const T&>(name, funcName);
            if (cachedResolvedImports.count(tmp) != 0)
            {
                cachedResolvedImports[tmp] = nullptr;
                cachedResolvedImports.erase(tmp);
            }
        }

        void setCachedModuleBase(const T& dllName, HINSTANCE mod)
        {
            const auto name = getModuleName(dllName);
            cachedModuleBases[name] = mod;
        }
    };


	//
	// =======================================================================================
	//

	template<typename T>
	std::vector<T> split(const T& s, T seperator)
	{
		std::vector<T> output;
		size_t prev_pos = 0, pos = 0;

		while ((pos = s.find(seperator, pos)) != T::npos)
		{
			T substring(s.substr(prev_pos, pos - prev_pos));
			output.push_back(substring);
			prev_pos = ++pos;
		}

		output.push_back(s.substr(prev_pos, pos - prev_pos)); // Last word
		return output;
	}

	std::wstring adjustPath(
		const std::wstring& szPath
	);

	std::wstring _adjustPath(
		const std::wstring& szPath
	);

	std::string adjustPathA(
		const std::string& szPath
	);

	void die();


	//
	// =======================================================================================
	//


    // Cannot make this ImportResolver's a class member, since ImportResolver is a template and gets various
    // instantiations per each function pointer type.
    extern ImportResolverCache<std::string> globalResolverCache;

    template <typename Ret, typename ...Args>
    class ImportResolver <Ret WINAPI(Args...)>
    {
    public:

        auto operator()(Args... args) { return call(args...); }

		auto getAddress()       const { return resolvedFuncAddress; }
		auto getModule()        const { return hModule; }
		auto getDllName()       const { return dllName; }
		auto getDllNameShort()  const { return dllNameShort; }
		auto getFuncName()      const { return funcName; }

        ImportResolver(
            std::string dllName,
            std::string funcName,
            bool _unhook = false,
            bool *_wasItHooked = nullptr
        )
            : unhook(_unhook), wasItHooked(_wasItHooked),
            hModule(nullptr), dllNameShort()
        {
            std::transform(dllName.begin(), dllName.end(), dllName.begin(),
                [](unsigned char c) { return std::tolower(c); });

            this->dllName = dllName;
            this->funcName = funcName;
            this->dllNameShort = split(dllName, std::string("\\")).back();

            FARPROC cached = globalResolverCache.getCached(dllName, funcName);
            if (cached != nullptr)
            {
                try
                {
                    const char* ptr = reinterpret_cast<const char*>(cached);
                    for (size_t i = 0; i < 32; ptr[i++]);

                    resolvedFuncAddress = cached;
                    return;
                }
                catch (...)
                {
                    globalResolverCache.invalidateFunction(dllName, funcName);
                    cached = nullptr;
                }
            }

            this->hModule = globalResolverCache.getModule(dllName);
            try
            {
                const char* ptr = reinterpret_cast<const char*>(this->hModule);
                for (size_t i = 0; i < 32; ptr[i++]);
            }
            catch (...)
            {
                this->hModule = nullptr;
                globalResolverCache.invalidateModule(dllName);
            }

            assertLibraryLoaded();

            //
            // GlobalAddAtomA despite being exported by Kernel32.dll requries user32.dll to be preloaded & initialized
            // in the first place to work fine, as originally experienced by Alex Ionescu:
            // http://www.tech-archive.net/Archive/Development/microsoft.public.win32.programmer.kernel/2004-03/0851.html
            // and revisited here:
            // https://stackoverflow.com/questions/3577077/globaladdatom-returns-0-and-getlasterror-0x5-on-win7-works-on-xp
            // We are in position to apply hot-fix for that here
            //
            if (!funcName.rfind(OBFI_ASCII("GlobalAddAtom"), 0) || !funcName.rfind(OBFI_ASCII("GlobalGetAtomName")))
            {
                const auto u = std::string(OBFI_ASCII("user32.dll"));
                globalResolverCache.setCachedModuleBase(u, ::LoadLibraryA(u.c_str()));
            }

            if (this->hModule == nullptr) {
                die();
            }

            FARPROC func, funcOriginal = ::GetProcAddress(this->hModule, funcName.c_str());
            if (unhook)
            {
                func = manualExportLookup();

                //
                // Assert module is still loaded. There were cases where for instance advapi32.dll got 
                // unloaded after resolving ReadProcMemory/VirtualQueryEx/others, leading to a crash.
                //
                auto prevModule = this->hModule;
                uintptr_t offset = reinterpret_cast<uintptr_t>(funcOriginal)
                    - reinterpret_cast<uintptr_t>(this->hModule);

                assertLibraryLoaded();

                if (this->hModule != prevModule)
                {
                    auto a = (uintptr_t)(this->hModule);
                    auto b = (uintptr_t)(offset);
                    func = FARPROC(a + b);
                }
            }
            else
            {
                func = funcOriginal;
            }

            if (!func) {
                //
                // DID YOU SPECIFY CORRECT DLL LIBRARY NAME THAT EXPORTS GIVEN FUNCTION?
                //
                // This error may indicate that you were trying to resolve a function from a library that doesn't export it, like:
                //
                //      RESOLVE(kernel32, MessageBoxA);     // kernel32 doesn't export MessageBoxA, there should be user32 instead.
                //

                //die();

                func = funcOriginal;
                if (!func)
                {
                    auto mod = GetModuleHandleA(dllName.c_str());
                    if (!mod)
                    {
                        mod = ::LoadLibraryA(dllName.c_str());
                    }

                    if (mod)
                    {
                        func = ::GetProcAddress(mod, funcName.c_str());
                    }

                    if (!func)
                    {
                        die();
                    }
                }

                unhook = false;
            }

            if (unhook)
            {
                if(!checkIsAddressAvailable((uintptr_t)func))
                {
                    func = funcOriginal;
                    unhook = false;
                }

                if (func != funcOriginal)
                {
                    unhookImport(funcOriginal);
                }

                if(!unhookImport(func))
                {
                }
            }

            globalResolverCache.setCachedFunction(dllName, funcName, func);
            resolvedFuncAddress = func;
        }

        bool checkIsAddressAvailable(uintptr_t address)
        {
            static auto _VirtualQuery = reinterpret_cast<fn_VirtualQuery*>(nullptr);

            if (!_VirtualQuery)
            {
                _VirtualQuery = reinterpret_cast<fn_VirtualQuery*>(::GetProcAddress(
                    GetModuleHandleW(L"kernel32.dll"),
                    OBFI_ASCII("VirtualQuery")
                ));
            }

            MEMORY_BASIC_INFORMATION mbi = { 0 };

            LPCVOID addr = (LPCVOID)address;

            if (_VirtualQuery != NULL && _VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)
                || mbi.State == MEM_FREE || mbi.RegionSize < 0x1000
                || (mbi.Type != MEM_IMAGE && mbi.Type != MEM_MAPPED))
            {
                return false;
            }

            return true;
        }

        void assertLibraryLoaded()
        {
            static const char* kernel = "kernel32.dll";
            static const char* ntdll = "ntdll.dll";

            auto dllNamePtr = strrchr(dllName.c_str(), '\\');
            if (dllNamePtr == nullptr) dllNamePtr = dllName.c_str();
            else dllNamePtr++;

            if (this->hModule != nullptr && (strcmp(dllNamePtr, kernel) != 0 && strcmp(dllNamePtr, ntdll) != 0))
            {
                // Check if library is still loaded (despite having it's cached ImageBase)
                if (!checkIsAddressAvailable((uintptr_t)this->hModule))
                {
                    // If not, invalidate the cache entry and reload it.
                    this->hModule = nullptr;
                }
            }

            if(!this->hModule)
            {
                bool loaded = false;

                {
                    static auto _CreateToolhelp32Snapshot = reinterpret_cast<fn_CreateToolhelp32Snapshot*>(nullptr);
                    if (!_CreateToolhelp32Snapshot)
                    {
                        _CreateToolhelp32Snapshot = reinterpret_cast<fn_CreateToolhelp32Snapshot*>(::GetProcAddress(
                            GetModuleHandleW(L"kernel32.dll"),
                            OBFI_ASCII("CreateToolhelp32Snapshot")
                        ));
                    }

                    static auto _Module32FirstW = reinterpret_cast<fn_Module32FirstW*>(nullptr);
                    if (!_Module32FirstW)
                    {
                        _Module32FirstW = reinterpret_cast<fn_Module32FirstW*>(::GetProcAddress(
                            GetModuleHandleW(L"kernel32.dll"),
                            OBFI_ASCII("Module32FirstW")
                        ));
                    }

                    static auto _Module32NextW = reinterpret_cast<fn_Module32NextW*>(nullptr);
                    if (!_Module32NextW)
                    {
                        _Module32NextW = reinterpret_cast<fn_Module32NextW*>(::GetProcAddress(
                            GetModuleHandleW(L"kernel32.dll"),
                            OBFI_ASCII("Module32NextW")
                        ));
                    }

                    HANDLE hSnap = _CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
                    if (hSnap == nullptr || hSnap == (HANDLE)INVALID_HANDLE_VALUE)
                    {
                        return;
                    }

                    MODULEENTRY32W me32 = { 0 };
                    me32.dwSize = sizeof(MODULEENTRY32W);

                    if (!_Module32FirstW(hSnap, &me32))
                    {
                        CloseHandle(hSnap);
                        return;
                    }

                    std::wstring wdllName(dllName.begin(), dllName.end());

                    do
                    {
                        auto modBase = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
                        auto hModulePtr = reinterpret_cast<uintptr_t>(hModule);

                        if (stringicompare(std::wstring(me32.szExePath), wdllName))
                        {
                            loaded = true;
                            size_t a = (size_t)me32.modBaseAddr;
                            size_t b = (size_t)this->hModule;

                            if (a != b)
                            {
                                this->hModule = (HINSTANCE)me32.modBaseAddr;
                                break;
                            }
                        }

                        if (!_Module32NextW(hSnap, &me32))
                        {
                            if (::GetLastError() != ERROR_NO_MORE_FILES)
                            {
                                return;
                            }

                            break;
                        }
                    } while (true);

                    CloseHandle(hSnap);
                }

                if (!loaded)
                {
                    this->hModule = ::LoadLibraryA(dllName.c_str());

                    globalResolverCache.setCachedModuleBase(dllName, this->hModule);
                }
            }
        }

        auto call(Args... args)
        {
            auto test = ::GetModuleHandleA(dllName.c_str());
            if (test == nullptr)
            {
                this->hModule = ::LoadLibraryA(dllName.c_str());
                globalResolverCache.setCachedModuleBase(dllName, this->hModule);
            }

            return reinterpret_cast<typename std::add_pointer_t<Ret WINAPI(Args...)>>(resolvedFuncAddress)(args...);
        }

    private:

        FARPROC resolvedFuncAddress;
        HINSTANCE hModule;
        std::string dllName;
        std::string dllNameShort;
        std::string funcName;

        bool unhook;
        bool *wasItHooked;

        inline std::wstring str_to_wstr(std::string input)
        {
            std::wstring out(input.begin(), input.end());
            wchar_t tmp[128] = { 0 };
            wcscpy_s(tmp, out.c_str());
            return OBFI(tmp);
        }

        FARPROC manualExportLookup()
        {
            PE peModule;
            bool res = peModule.AnalyseProcessModule(0, hModule, true, true);

            if(!res)
            {
                return nullptr;
            }

            EXPORTED_FUNCTION exportEntry;

            if (!peModule.getExport(this->funcName.c_str(), &exportEntry))
            {
                return nullptr;
            }

            auto resolved = reinterpret_cast<uintptr_t>(hModule) + exportEntry.dwPtrValueRVA;
            if (exportEntry.bIsForwarded)
            {
                auto fwd = std::string(exportEntry.szForwarder);

                std::string moduleFwd(split(std::string(exportEntry.szForwarder), std::string(".")).front());
                moduleFwd += OBFI_ASCII(".dll");

                auto importDesc = std::find_if(
                    peModule.vImportDescriptors.begin(),
                    peModule.vImportDescriptors.end(),
                    [&moduleFwd](const __IMAGE_IMPORT_DESCRIPTOR& f) {
                        return (!strcmp(f.szName, moduleFwd.c_str()));
                    }
                );

                if (importDesc == peModule.vImportDescriptors.end())
                {
                    return nullptr;
                }

                IMPORTED_FUNCTION fwdImport;
                if (!peModule.getImport(this->funcName.c_str(), &fwdImport))
                {
                    return nullptr;
                }

                auto path = split(dllName, std::string("\\"));
                path.pop_back();

                this->dllName.clear();
                for (auto p : path)
                {
                    this->dllName += p + "\\";
                }

                if (moduleFwd.find(OBFI_ASCII("api-ms-win-core-"), 0) == 0)
                {
                    auto _dllNameShort = this->dllNameShort;
                    auto _dllName = this->dllName;
                    auto _hModule = this->hModule;

                    this->dllNameShort = OBFI_ASCII("kernelbase.dll");
                    this->dllName += this->dllNameShort;
                    this->hModule = LoadLibraryA(this->dllNameShort.c_str());

                    auto out = manualExportLookup();
                    if (!out)
                    {
                        this->dllNameShort = _dllNameShort;
                        this->dllName = _dllName + _dllNameShort;
                        this->hModule = _hModule;
                        unhook = false;

                        return ::GetProcAddress(_hModule, this->funcName.c_str());
                    }

                    return out;
                }
                else
                {
                    auto _dllNameShort = this->dllNameShort;
                    auto _dllName = this->dllName;
                    auto _hModule = this->hModule;

                    this->dllNameShort = std::move(moduleFwd);
                    this->dllName += this->dllNameShort;
                    this->hModule = LoadLibraryA(this->dllNameShort.c_str());

                    auto out = manualExportLookup();
                    if (!out)
                    {
                        this->dllNameShort = _dllNameShort;
                        this->dllName = _dllName + _dllNameShort;
                        this->hModule = _hModule;
                        unhook = false;

                        return ::GetProcAddress(_hModule, this->funcName.c_str());
                    }

                    return out;
                }
            }

            return reinterpret_cast<FARPROC>(resolved);
        }

        

        bool flipPageGuards(bool disable, uintptr_t hModule, std::vector<MEMORY_BASIC_INFORMATION>* guardedAllocs)
        {
#ifdef _DEBUG
            // DEBUG!!!
            return true;
#endif

            if (hModule == 0) hModule = (uintptr_t)GetModuleHandle(NULL);

            PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)hModule;
            PIMAGE_NT_HEADERS32 ntHdr = (PIMAGE_NT_HEADERS32)((uintptr_t)dosHdr->e_lfanew + hModule);

            DWORD sizeOfImage = 0;
            if (ntHdr->FileHeader.Machine & IMAGE_FILE_MACHINE_I386)
            {
                sizeOfImage = ntHdr->OptionalHeader.SizeOfImage;
            }
            else
            {
                PIMAGE_NT_HEADERS64 ntHdr = (PIMAGE_NT_HEADERS64)((uintptr_t)dosHdr->e_lfanew + hModule);
                sizeOfImage = ntHdr->OptionalHeader.SizeOfImage;
            }

            uint8_t* address = 0;
            const size_t MaxSize = (sizeof(ULONG_PTR) == 4) ? ((1ULL << 31) - 1) : ((1ULL << 63) - 1);

            if (disable)
            {
                while (reinterpret_cast<size_t>(address) < MaxSize)
                {
                    MEMORY_BASIC_INFORMATION mbi = { 0 };
                    if (!VirtualQuery(address, &mbi, sizeof(mbi)))
                    {
                        break;
                    }

                    if ((uintptr_t)mbi.BaseAddress >= (uintptr_t)hModule
                        && (uintptr_t)((uintptr_t)mbi.BaseAddress + mbi.RegionSize) < (uintptr_t)((uintptr_t)hModule + sizeOfImage))
                    {
                        if (mbi.Protect & PAGE_GUARD)
                        {
                            DWORD oldProtect = 0;
                            DWORD newProtect = mbi.Protect & (~PAGE_GUARD);

                            VirtualProtect(mbi.BaseAddress, mbi.RegionSize, newProtect, &oldProtect);
                            if (guardedAllocs != nullptr) guardedAllocs->push_back(mbi);
                        }
                    }

                    address += mbi.RegionSize;
                }
            }
            else
            {
                if (guardedAllocs != nullptr && guardedAllocs->size() > 0)
                {
                    for (const auto &mbi : *guardedAllocs)
                    {
                        DWORD oldProtect = 0;
                        VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &oldProtect);
                    }
                }
            }

            return true;
        }

        bool unhookImport(FARPROC funcAddress)
        {
            const size_t Max_Bytes_Of_Function_To_Check = 32;

            uint8_t currentImportStub[Max_Bytes_Of_Function_To_Check] = { 0 };
            uint8_t inFileImportStub[Max_Bytes_Of_Function_To_Check] = { 0 };

            memcpy(currentImportStub, funcAddress, sizeof(currentImportStub));

            PE peLibraryFile;
            if (!peLibraryFile.AnalyseFile(dllName, true))
            {
                return false;
            }

            EXPORTED_FUNCTION exportEntry;

            if (peLibraryFile.getExport(this->funcName.c_str(), &exportEntry))
            {
                DWORD funcAddr = 0;
                if (!peLibraryFile.ReadBytes(&funcAddr, sizeof(DWORD), exportEntry.dwThunkRVA, PE::AccessMethod::File_Begin))
                {
                    return false;
                }

                if (!peLibraryFile.ReadBytes(inFileImportStub, sizeof(inFileImportStub), peLibraryFile.RVA2RAW(funcAddr), PE::AccessMethod::File_Begin))
                {
                    return false;
                }
            }
            else
            {
                return false;
            }

            // Step 1: Inspect current process' IAT entry
            {
                std::vector<MEMORY_BASIC_INFORMATION> flippedPages;
                if (!flipPageGuards(true, 0, &flippedPages))
                {
                    return false;
                }

                PE currProcess;
                if (!currProcess.AnalyseProcess(0, false))
                {
                    flipPageGuards(false, 0, &flippedPages);
                    return false;
                }

                IMPORTED_FUNCTION importedFunc;

                if (currProcess.getImport(this->funcName.c_str(), &importedFunc))
                {
                    const DWORD origExportRVA = exportEntry.dwPtrValueRVA;
                    const DWORD currThunkRVA = static_cast<DWORD>(reinterpret_cast<uintptr_t>(funcAddress) - reinterpret_cast<uintptr_t>(hModule));

                    if (origExportRVA != currThunkRVA)
                    {
                        if (wasItHooked != nullptr)
                        {
                            *wasItHooked = true;
                        }

                        // IAT hijacked
                        const ULONGLONG restore = reinterpret_cast<uintptr_t>(hModule) + origExportRVA;

                        currProcess.HookIAT(funcName, restore);
                    }
                }
                else
                {
                    // Possibly we're not importing this function explicitly, that's fine.
                }

                if (!flipPageGuards(false, 0, &flippedPages))
                {
                    return false;
                }
            }

            // Step 2: Check for hijacked EAT entries.
            {
                std::vector<MEMORY_BASIC_INFORMATION> flippedPages;
                if (!flipPageGuards(true, (uintptr_t)hModule, &flippedPages))
                {
                    return false;
                }

                PE mappedLib;
                if (!mappedLib.AnalyseProcessModule(0, hModule, false, true))
                {
                    flipPageGuards(false, (uintptr_t)hModule, &flippedPages);
                    return false;
                }

                EXPORTED_FUNCTION inMemoryExportEntry;

                if (mappedLib.getExport(funcName.c_str(), &inMemoryExportEntry))
                {
                    auto addr = static_cast<DWORD>(mappedLib.RVA2RAW(inMemoryExportEntry.dwThunkRVA));
                    const DWORD origExportRVA = exportEntry.dwPtrValueRVA;
                    //const DWORD currThunkRVA = static_cast<DWORD>(reinterpret_cast<uintptr_t>(funcAddress) - reinterpret_cast<uintptr_t>(hModule));
                    const DWORD currThunkRVA = inMemoryExportEntry.dwPtrValueRVA;

                    if (origExportRVA != currThunkRVA && !inMemoryExportEntry.bIsForwarded)
                    {
                        if (wasItHooked != nullptr)
                        {
                            *wasItHooked = true;
                        }

                        // EAT hijacked
                        const DWORD restore = origExportRVA;
                        mappedLib.HookEAT(funcName, restore);
                    }
                }
                else
                {
                    flipPageGuards(false, (uintptr_t)hModule, &flippedPages);
                    return false;
                }

                if (!flipPageGuards(false, (uintptr_t)hModule, &flippedPages))
                {
                    return false;
                }
            }

            // Step 3: Check for hooked import's stub.
            if (memcmp(currentImportStub, inFileImportStub, Max_Bytes_Of_Function_To_Check) != 0)
            {
                if (wasItHooked != nullptr)
                {
                    *wasItHooked = true;
                }

                DWORD old, old2;
                if (VirtualProtect(funcAddress, Max_Bytes_Of_Function_To_Check, PAGE_EXECUTE_READWRITE, &old))
                {
                    if (peLibraryFile.ApplyRelocsInBuffer(reinterpret_cast<ULONGLONG>(hModule), 
                        exportEntry.dwThunkRVA, inFileImportStub, Max_Bytes_Of_Function_To_Check))
                    {
                        for (size_t u = 0; u < Max_Bytes_Of_Function_To_Check; u++)
                        {
                            if (currentImportStub[u] != inFileImportStub[u])
                            {
                                reinterpret_cast<uint8_t*>(funcAddress)[u] = inFileImportStub[u];
                            }
                        }
                    }

                    return VirtualProtect(funcAddress, Max_Bytes_Of_Function_To_Check, old, &old2);
                }
            }

            if (wasItHooked != nullptr)
            {
                *wasItHooked = false;
            }

            return true;
        }
    };
}