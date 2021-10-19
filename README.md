## UnhookMe - Dynamically unhooking imports resolver

In the era of intrusive AVs and EDRs that introduce hot-patches to the running processes for their enhanced optics requirements, modern adversaries must have a robust tool to slide through these watchguards. The propsed implementation of dynamic imports resolver that would be capable of unhooking used functions in-the-fly is yet another step towards strengthening adversary resilience efforts.

The solution I'm proposing here is to switch from using linker-resolved WinAPI imports, staying visibile in compiled executable's PE headers (Import Address Table specifically) to favor fully-dynamic approach insisting on resolving imports only in a dynamic fashion. Such dynamical resolver can be equipped with unhooking logic happening in the background, without any sort of guidance from the operator's side.


### Simplest usage example

This is how you can ensure to call `MessageBoxW` unhooked, unmonitored:

```c++
    RESOLVE(user32, MessageBoxW);
    _MessageBoxW(0, L"Look Ma! I'm unhooked!", L"Third - Unhooked", 0);
```

All the magic happens within `RESOLVE` macrodefintion, that constructs `ImportResolver<T>` object named `_MessageBoxW`. 

### Showcase

![Unhookme showcase animation](https://raw.githubusercontent.com/mgeeky/UnhookMe/master/apimonitor.gif)


Here's how `UnhookMe` example works:

1. It presents us with the first `MessageBoxW` that is not subject for hooking
2. Then we hook `MessageBoxW` prologue ourselves to make it always return 0 without displaying it's message
3. Finally, we resolve `MessageBoxW` dynamically using the `UnhookingImportResolver` resolver, which will detect
   applied prologue patches and restore original bytes, effectively unhooking `MessageBoxW` functionality.

In the meantime of popping message boxes, these are the loglines printed to console's stdout:

```
[~] Resolved symbol kernel32.dll!CreateFileA
[~] Resolved symbol kernel32.dll!ReadProcessMemory
[~] Resolved symbol kernel32.dll!MapViewOfFile
[~] Resolved symbol kernel32.dll!VirtualProtectEx
[#] Found trampoline hook in symbol: MessageBoxW . Restored original bytes from file.
[~] Resolved symbol user32.dll!MessageBoxW
```


### How to use it?

There are in total 5 C++ source code/header files that your solution need to include. However your main program file needs to include only two required headers, as detailed below.

* `resolver.h` - header containing most of the `UnhookingImportResolver` implementation and handy macrodefinitions
* `resolver.cpp` - source code with global options defined
* `usings.h` - a one big and nasty header file containing tens of `using` type definitions for commonly used WinAPIs
* `PE.cpp` - custom PE parser source code file
* `PE.h` - custom PE parser header file


#### Required headers

Your program will require only two headers being included:

```c++
#include "usings.h"
#include "resolver.h"
```

#### Global options

There are couple of global options that can be changed affecting the way in which Resolver works or reports it's activity. These are defined in the very beginning of **`resolver.cpp`** file:

Resolver global options:

- **`globalQuietOption`**          - set to true if you don't want to have any sort of output
- **`globalVerboseOption`**        - set to true if you want to have detailed verbose output
- **`globalAntiSplicingOption`**   - unhook resolved functions if they're hooked.
- **`globalLogFilePath`**          - where to redirect output log lines. If empty, pick stdout.

```c++
bool globalQuietOption = false;
bool globalVerboseOption = true;
bool globalAntiSplicingOption = true;

wchar_t globalLogFilePath[MAX_PATH] = L"";
```

#### Custom API type specification

In order to use Resolver a function pointer type must be first declared with `using` statement of strict form:

```c++
    using fn_FunctionName = ReturnType WINAPI (
        ParamType1 paramName1,
        ...,
        ParamTypeN paramNameN,
    );
```

This repository comes with **`usings.h`** header file containing predefined using types for tens of popular Windows APIs.

The _FunctionName_ will correspond to the WinAPI that we want to have ImportResolver resolve and that function pointer must be marked as having WINAPI call convention ( `__stdcall` on x86 and `__fastcall` on x64). The _ReturnType_ must precede `WINAPI` type modifier.


#### Function resolution and usage

Having function pointer type defined like specified above, we will be able to use it in the following manner:

```c++
    RESOLVE(libraryName, FunctionName);
    ReturnType output = _FunctionName(param1, ..., paramN);
```

The macro `RESOLVE` takes care of instantiating `ImportResolver` templated object and adjust specifed library's name.

Resolver introduces several more Macrodefinitions offering easy to use in various circumstances constructor invocation:

```c++
#define RESOLVE(mod, func)                    RESOLVE_PARAMETERIZED(mod, func, ::globalVerboseOption, ::globalAntiSplicingOption)
#define RESOLVE_NO_UNHOOK(mod, func)          RESOLVE_PARAMETERIZED(mod, func, ::globalVerboseOption, false)

#define RESOLVE_VERBOSE_UNHOOK(mod, func)     RESOLVE_PARAMETERIZED(mod, func, true, true)
#define RESOLVE_VERBOSE_NOUNHOOK(mod, func)   RESOLVE_PARAMETERIZED(mod, func, true, false)
#define RESOLVE_NOVERBOSE_UNHOOK(mod, func)   RESOLVE_PARAMETERIZED(mod, func, false, true)
#define RESOLVE_NOVERBOSE_NOUNHOOK(mod, func) RESOLVE_PARAMETERIZED(mod, func, false, false)
```

Resolver's constructor:

```c++
    template<typename Ret, typename ...Args>
    ImportResolver<Ret WINAPI(Args...)>(
            std::string dllName,
            std::string funcName,
            bool _verbose = false,
            bool _unhook = false,
            bool *_wasItHooked = nullptr
        )
```

### How does it work?

The underlaying resolver leverages custom PE headers parser, that processes every referenced DLL module to map their exports and verify that module's PE headers integrity as well as integrity of referenced function's stub bytes.

The idea is following:

1) Firstly we issue `LoadLibrary` to load referenced by the user library (the one specified as first parameter for `RESOLVE` macro) if it could not be reached through `GetModuleHandle`. 

2) Then we process loaded/referenced library's PE headers, map its exports, retrieve array of exports addresses as well as compute these addresses ourselves for cross-verification.

3) If address of a routine defined in DLL's Export Address Table doesn't correspond to what we would expect, the export is considered EAT hooked. The same goes if our Executable Import Address Table (IAT) entry for that function was altered and no longer points to the correct spot in DLL's code section - then the function is considered to be IAT hooked.

4) Assuming no hooks were found so far, we fetch first N bytes of the function's prologue and compare them to what's in DLL's file stored in disk. If there is miscrepancy between bytes fetched from memory and from file - we consider function was inline patched (hot-patched).

5) If the function was considered hooked - we return original export's address (the one we computed ourselves) and/or unhook the entry. If there were patch bytes in place, we'll restore them.

6) Finally, in order to optimize resolver's performance impact - we cache all of the loaded modules imagebases and resolved functions addresses and return them from a cache (being `std::map` ) during subsequent hits.


Among the problems such dynamically-unhooking resolver faced are the issues with traversing forwarded APIs (a DLL may contain Export thunk saying that this function is not implemented in this module, but it is in another one) - which although this implementation has support for, sometimes it brokes its traversal logic.



---

### ☕ Show Support ☕

This and other projects are outcome of sleepless nights and **plenty of hard work**. If you like what I do and appreciate that I always give back to the community,
[Consider buying me a coffee](https://github.com/sponsors/mgeeky) _(or better a beer)_ just to say thank you! 💪 

---

## Author

```   
   Mariusz Banach / mgeeky, 21
   <mb [at] binary-offensive.com>
   (https://github.com/mgeeky)
```
