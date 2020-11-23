#pragma once

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
                bool _verbose = false,
                bool _unhook = false,
                bool *_wasItHooked = nullptr
            )
 
Author:
    Mariusz Banach / mgeeky (@mariuszbit)
*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <functional>
#include <map>

#include "PE.h"
#include "usings.h"

//
// Helper macrodefintions to easily plug ADVobfuscator/MetaString.h
// 
#define OBF(x) x
#define OBFI(x) x
#define ADV_OBF(x) x
#define ADV_OBF_W(x) x
#define OBF_WSTR(x) std::wstring(x)
#define OBF_STR(x) std::string(x)

//
// Macrodefinition Parameters:
//   - mod:     library name exporting specified function
//   - func:    function to import
//   - verbose: whether to print verbose output
//   - unhook:  whether to do function anti-splicing/unhooking if it was hooked
//

#define RESOLVE_PARAMETERIZED(mod, func, verbose, unhook)                           \
    static auto _ ## func = UnhookingImportResolver::ImportResolver<fn_ ## func>(   \
        UnhookingImportResolver::adjustPathA(ADV_OBF(#mod)), ADV_OBF(#func),        \
        verbose, unhook);

extern bool globalVerboseOption;
extern bool globalAntiSplicingOption;

#define RESOLVE(mod, func)                    RESOLVE_PARAMETERIZED(mod, func, ::globalVerboseOption, ::globalAntiSplicingOption)
#define RESOLVE_NO_UNHOOK(mod, func)          RESOLVE_PARAMETERIZED(mod, func, ::globalVerboseOption, false)

#define RESOLVE_VERBOSE_UNHOOK(mod, func)     RESOLVE_PARAMETERIZED(mod, func, true, true)
#define RESOLVE_VERBOSE_NOUNHOOK(mod, func)   RESOLVE_PARAMETERIZED(mod, func, true, false)
#define RESOLVE_NOVERBOSE_UNHOOK(mod, func)   RESOLVE_PARAMETERIZED(mod, func, false, true)
#define RESOLVE_NOVERBOSE_NOUNHOOK(mod, func) RESOLVE_PARAMETERIZED(mod, func, false, false)

namespace UnhookingImportResolver
{
    template <typename T>
    class ImportResolver {};

    template<typename T>
    struct ImportResolverCache
    {
        ImportResolverCache() : cachedResolvedImports{}, cachedModuleBases{} {};

        std::map<T, uint32_t> functionResolutionCount;
        std::map<std::pair<T, T>, FARPROC> cachedResolvedImports;
        std::map<T, HINSTANCE> cachedModuleBases;

        T getModuleName(const T& dllName)
        {
            static std::map<T, T> cachedNames;
            if (cachedNames.count(dllName) != 0)
            {
                return cachedNames[dllName];
            }

            const auto lastBackslash = dllName.rfind(static_cast<typename T::value_type>('\\'));
            if (lastBackslash != T::npos)
            {
                cachedNames[dllName] = T(dllName, lastBackslash + 1);
                return cachedNames[dllName];
            }

            return dllName;
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

        void setCachedModuleBase(const T& dllName, HINSTANCE mod)
        {
            const auto name = getModuleName(dllName);
            cachedModuleBases[name] = mod;
        }
    };


    extern bool globalQuietOption;
    extern bool globalVerboseOption;
    extern bool globalDontPrintoutLogsYet;
    extern wchar_t globalLogFilePath[MAX_PATH];

    template<class... Args>
    std::string formatLogline(Args... args)
    {
        std::wostringstream woss;
        (woss << ... << args);

        auto a = woss.str();
        std::string out(a.begin(), a.end());
        out += "\r\n";

        return out;
    }

    void _output(bool verbose, const std::string& out);

    template<class... Args>
    void info(Args... args)
    {
        const auto out = formatLogline(args...);
        _output(false, out);
    }

    template<class... Args>
    void output(bool verbose, Args... args)
    {
        if (!verbose) return;
        const auto out = formatLogline(args...);
        _output(verbose, out);
    }

    template<class... Args>
    void verbose(Args... args)
    {
        if (globalVerboseOption)
        {
            const auto out = formatLogline(args...);
            _output(true, out);
        }
    }

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

        ImportResolver(
            std::string dllName,
            std::string funcName,
            bool _verbose = false,
            bool _unhook = false,
            bool *_wasItHooked = nullptr
        )
            : verbose(_verbose), unhook(_unhook), wasItHooked(_wasItHooked),
            hModule(nullptr), dllNameShort("")
        {
            this->dllName = dllName;
            this->funcName = funcName;
            this->dllNameShort = split(dllName, std::string("\\")).back();

            FARPROC cached = globalResolverCache.getCached(dllName, funcName);
            if (cached != nullptr)
            {
                resolvedFuncAddress = cached;
                return;
            }

            this->hModule = globalResolverCache.getModule(dllName);

            static const char *kernel = "kernel32.dll";
            static const char *ntdll = "ntdll.dll";
            
            auto dllNamePtr = strrchr(dllName.c_str(), '\\');
            if (dllNamePtr == nullptr) dllNamePtr = dllName.c_str();
            else dllNamePtr++;

            if (this->hModule != nullptr && (strcmp(dllNamePtr, kernel) != 0 && strcmp(dllNamePtr, ntdll) != 0))
            {
                // Check if library is still loaded (despite having it's cached ImageBase)
                static auto _VirtualQuery = reinterpret_cast<fn_VirtualQuery*>(::GetProcAddress(
                    ::GetModuleHandleW(L"kernel32.dll"), 
                    ADV_OBF("VirtualQuery")
                ));

                MEMORY_BASIC_INFORMATION mbi = { 0 };

                if (_VirtualQuery != NULL && _VirtualQuery(this->hModule, &mbi, sizeof(mbi)) != sizeof(mbi)
                    || mbi.State == MEM_FREE || mbi.RegionSize < 0x1000
                    || (mbi.Type != MEM_IMAGE && mbi.Type != MEM_MAPPED))
                {
                    // If not, invalidate the cache entry and reload it.
                    this->hModule = nullptr;
                }
            }

            if (!this->hModule)
            {
                output(verbose, OBF(L"[.] Loading library: "), str_to_wstr(dllName), OBF(L""));
                this->hModule = ::LoadLibraryA(dllName.c_str());

                globalResolverCache.setCachedModuleBase(dllName, this->hModule);
            }

            //
            // GlobalAddAtomA despite being exported by Kernel32.dll requries user32.dll to be preloaded & initialized
            // in the first place to work fine, as originally experienced by Alex Ionescu:
            // http://www.tech-archive.net/Archive/Development/microsoft.public.win32.programmer.kernel/2004-03/0851.html
            // and revisited here:
            // https://stackoverflow.com/questions/3577077/globaladdatom-returns-0-and-getlasterror-0x5-on-win7-works-on-xp
            // We are in position to apply hot-fix for that here
            //
            if (!funcName.rfind(ADV_OBF("GlobalAddAtom"), 0) || !funcName.rfind(ADV_OBF("GlobalGetAtomName")))
            {
                const auto u = std::string(ADV_OBF("user32.dll"));
                globalResolverCache.setCachedModuleBase(u, ::LoadLibraryA(u.c_str()));
            }

            if (this->hModule == nullptr) {
                output(verbose, OBF(L"[!] Resolver(unhook="), unhook, OBF(L"): FATAL. Could not load module: "), str_to_wstr(dllName));
                die();
            }

            FARPROC func;
            if (unhook)
            {
                func = manualExportLookup();
            }
            else
            {
                func = ::GetProcAddress(this->hModule, funcName.c_str());
            }

            if (!func) {
                //
                // DID YOU SPECIFY CORRECT DLL LIBRARY NAME THAT EXPORTS GIVEN FUNCTION?
                //
                // This error make indicate that you were trying to resolve a function from a library that doesn't export it, like:
                //
                //      RESOLVE(kernel32, MessageBoxA);     // kernel32 doesn't export MessageBoxA, there should be user32 instead.
                //

                output(verbose, OBF(L"[-] Resolver(unhook="), unhook, OBF(L"): WARNING. Could not resolve symbol "), str_to_wstr(dllName), OBF(L"!"), str_to_wstr(funcName));
                output(verbose, OBF(L"    I should die here, but will fall back to GetProcAddress and carry on instead."));
                //die();

                func = ::GetProcAddress(this->hModule, funcName.c_str());
                if (!func)
                {
                    output(verbose, OBF(L"[!] GetProcAddress too was not able to resolve that symbol! That's more than FATAL. Sorry :("));
                    die();
                }

                unhook = false;
            }

            if (unhook)
            {
                if (!unhookImport(func))
                {
                    output(verbose, OBF(L"[!] Resolver(unhook="), unhook, OBF(L"): FATAL. Could not unhook symbol "), str_to_wstr(dllName), OBF(L"!"), str_to_wstr(funcName));
                    output(verbose, OBF(L"    I should die here, but will pretend nothing happen and carry on instead."));
                    //die();
                }
            }

            if (wasItHooked != nullptr && *wasItHooked)
            {
                output(true, OBF(L"[#] Resolver: WARNING. Symbol "), str_to_wstr(dllName), OBF(L"!"), str_to_wstr(funcName), OBF(L" was hooked."));
            }

            globalResolverCache.setCachedFunction(dllName, funcName, func);
            output(verbose, OBF(L"[~] Resolved symbol "), str_to_wstr(dllNameShort), OBF(L"!"), str_to_wstr(funcName));

            resolvedFuncAddress = func;
        }

        auto operator()(Args... args)
        {
            return reinterpret_cast<typename std::add_pointer_t<Ret WINAPI(Args...)>>(resolvedFuncAddress)(args...);
        }

    private:

        FARPROC resolvedFuncAddress;
        HINSTANCE hModule;
        std::string dllName;
        std::string dllNameShort;
        std::string funcName;

        bool verbose;
        bool unhook;
        bool *wasItHooked;

        inline std::wstring str_to_wstr(std::string input)
        {
            std::wstring out(input.begin(), input.end());
            wchar_t tmp[128] = { 0 };
            wcscpy_s(tmp, out.c_str());
            return ADV_OBF_W(tmp);
        }

        FARPROC manualExportLookup()
        {
            PE peModule;
            if (!peModule.AnalyseProcessModule(0, hModule, true))
            {
                output(verbose, OBF(L"[!] Resolver(unhook="), unhook, OBF(L"): FATAL. Could not parse module's PE headers: "), str_to_wstr(dllName));
                return nullptr;
            }

            auto funcName = this->funcName;
            auto exportEntry = std::find_if(
                peModule.vExports.begin(),
                peModule.vExports.end(),
                [&funcName](const EXPORTED_FUNCTION& f) {
                    return (!strcmp(f.szFunction, funcName.c_str()));
                }
            );

            if (exportEntry == peModule.vExports.end())
            {
                return nullptr;
            }

            auto resolved = reinterpret_cast<uintptr_t>(hModule) + exportEntry->dwPtrValueRVA;
            if (exportEntry->bIsForwarded)
            {
                auto fwd = std::string(exportEntry->szForwarder);
                output(verbose, OBF(L"[.] Following forward chain of symbol: "), str_to_wstr(fwd));

                std::string moduleFwd(split(std::string(exportEntry->szForwarder), std::string(".")).front());
                moduleFwd += ADV_OBF(".dll");

                auto importDesc = std::find_if(
                    peModule.vImportDescriptors.begin(),
                    peModule.vImportDescriptors.end(),
                    [&moduleFwd](const __IMAGE_IMPORT_DESCRIPTOR& f) {
                        return (!strcmp(f.szName, moduleFwd.c_str()));
                    }
                );

                if (importDesc == peModule.vImportDescriptors.end())
                {
                    output(verbose, OBF(L"[!] Could not find forwarded module's descriptor: "), str_to_wstr(fwd));
                    return nullptr;
                }

                auto fwdImport = std::find_if(
                    peModule.vImports.begin(),
                    peModule.vImports.end(),
                    [&moduleFwd, &funcName, &importDesc, &peModule](const IMPORTED_FUNCTION& f) {
                        return (!strcmp(peModule.vImportDescriptors[f.uImpDescriptorIndex].szName, moduleFwd.c_str()) && (!strcmp(f.szFunction, funcName.c_str())));
                    }
                );

                if (fwdImport == peModule.vImports.end())
                {
                    output(verbose, OBF(L"[!] Could not find forwarded module's import entry: "), str_to_wstr(fwd));
                    return nullptr;
                }

                auto path = split(dllName, std::string("\\"));
                path.pop_back();

                this->dllName = "";
                for (auto p : path)
                {
                    this->dllName += p + "\\";
                }

                if (moduleFwd.find(ADV_OBF("api-ms-win-core-"), 0) == 0)
                {
                    this->dllNameShort = ADV_OBF("kernelbase.dll");
                    this->dllName += this->dllNameShort;
                    this->hModule = LoadLibraryA(this->dllNameShort.c_str());

                    return manualExportLookup();
                }
                else
                {
                    output(verbose, OBF(L"[.] Loading and parsing forwarded module: "), str_to_wstr(moduleFwd));

                    this->dllNameShort = moduleFwd;
                    this->dllName += this->dllNameShort;
                    this->hModule = LoadLibraryA(this->dllNameShort.c_str());

                    return manualExportLookup();
                }
            }

#ifdef _DEBUG
            FARPROC trueAddr = ::GetProcAddress(this->hModule, funcName.c_str());

            if (resolved != reinterpret_cast<uintptr_t>(trueAddr))
            {
                output(verbose, OBF(L"[dbg] Resolver: true address of "), str_to_wstr(dllName), OBF(L"!"),
                    str_to_wstr(funcName), OBF(L": 0x"),
                    std::hex, std::setw(8), std::nouppercase, trueAddr,
                    OBF(L" vs. resolved: 0x"),
                    std::hex, std::setw(8), std::nouppercase, resolved
                );

                output(true, OBF(L"[dbg] Incorrect symbol resolution!"));
                die();
            }
#endif

            return reinterpret_cast<FARPROC>(resolved);
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
                output(verbose, OBF(L"[!] Resolver(unhook="), unhook, OBF(L"): FATAL. Could not parse module's PE headers: "), str_to_wstr(dllName));
                return false;
            }

            auto funcName = this->funcName;
            auto exportEntry = std::find_if(
                peLibraryFile.vExports.begin(),
                peLibraryFile.vExports.end(),
                [&funcName](const EXPORTED_FUNCTION& f) {
                    return (!strcmp(f.szFunction, funcName.c_str()));
                }
            );

            auto addr = static_cast<DWORD>((exportEntry->dwThunkRVA));

            if (exportEntry != peLibraryFile.vExports.end())
            {
                DWORD funcAddr = 0;
                if (!peLibraryFile.ReadBytes(&funcAddr, sizeof(DWORD), addr, PE::File_Begin))
                {
                    return false;
                }

                if (!peLibraryFile.ReadBytes(inFileImportStub, sizeof(inFileImportStub), peLibraryFile.RVA2RAW(funcAddr), PE::File_Begin))
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
                PE currProcess;
                if (!currProcess.AnalyseProcess(0, false))
                {
                    return false;
                }

                auto importEntry = std::find_if(
                    currProcess.vImports.begin(),
                    currProcess.vImports.end(),
                    [&funcName](const IMPORTED_FUNCTION& f) {
                        return (!strcmp(f.szFunction, funcName.c_str()));
                    }
                );

                if (importEntry != currProcess.vImports.end())
                {
                    const DWORD origExportRVA = exportEntry->dwPtrValueRVA;
                    const DWORD currThunkRVA = static_cast<DWORD>(reinterpret_cast<uintptr_t>(funcAddress) - reinterpret_cast<uintptr_t>(hModule));

                    if (origExportRVA != currThunkRVA)
                    {
                        if (wasItHooked != nullptr)
                        {
                            *wasItHooked = true;
                        }

                        // IAT hijacked
                        const ULONGLONG restore = reinterpret_cast<uintptr_t>(hModule) + origExportRVA;

                        output(verbose, OBF(L"[#] Found IAT hijacking on symbol: "), str_to_wstr(funcName),
                            OBF(L" (orig: 0x"), std::hex, origExportRVA, OBF(L" -> hook: 0x"), std::hex, currThunkRVA, OBF(L")"));

                        currProcess.HookIAT(funcName, restore);

                        output(verbose, OBF(L"\tAttempted to restore it."));
                    }
                }
                else
                {
                    // Possibly we're not importing this function explicitly, that's fine.
                }
            }

            // Step 2: Check for hijacked EAT entries.
            {
                PE ntdllInMemory;
                if (!ntdllInMemory.AnalyseProcessModule(0, hModule, false))
                {
                    return false;
                }

                auto inMemoryExportEntry = std::find_if(
                    ntdllInMemory.vExports.begin(),
                    ntdllInMemory.vExports.end(),
                    [&funcName](const EXPORTED_FUNCTION& f) {
                        return (!strcmp(f.szFunction, funcName.c_str()));
                    }
                );

                auto addr = static_cast<DWORD>(ntdllInMemory.RVA2RAW(inMemoryExportEntry->dwThunkRVA));

                if (inMemoryExportEntry != ntdllInMemory.vExports.end())
                {
                    const DWORD origExportRVA = inMemoryExportEntry->dwPtrValueRVA;
                    const DWORD currThunkRVA = static_cast<DWORD>(reinterpret_cast<uintptr_t>(funcAddress) - reinterpret_cast<uintptr_t>(hModule));

                    if (origExportRVA != currThunkRVA && !inMemoryExportEntry->bIsForwarded)
                    {
                        if (wasItHooked != nullptr)
                        {
                            *wasItHooked = true;
                        }

                        // IAT hijacked
                        const DWORD restore = origExportRVA;
                        output(verbose, OBF(L"[#] Found EAT hijacking on symbol: "), str_to_wstr(funcName), OBF(L" (orig: 0x"),
                            std::hex, origExportRVA, OBF(L" -> hook: 0x"), std::hex, currThunkRVA, OBF(L")"));

                        ntdllInMemory.HookEAT(funcName, restore);

                        output(verbose, OBF(L"\tAttempted to restore it."));
                    }
                }
                else
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
                    if (peLibraryFile.ApplyRelocsInBuffer(reinterpret_cast<ULONGLONG>(hModule), addr, inFileImportStub, Max_Bytes_Of_Function_To_Check))
                    {
                        for (size_t u = 0; u < Max_Bytes_Of_Function_To_Check; u++)
                        {
                            if (currentImportStub[u] != inFileImportStub[u])
                            {
                                reinterpret_cast<uint8_t*>(funcAddress)[u] = inFileImportStub[u];
                            }
                        }

                        output(verbose, OBF(L"[#] Found trampoline hook in symbol: "), str_to_wstr(funcName), OBF(L" . Restored original bytes from file."));
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