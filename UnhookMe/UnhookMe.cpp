/*
 * This is an example program presenting capabilities of the UnhookingImportResolver implementation.
 * The Resolver exposes an easy to use macrodefition allowing it's user to safely dynamically resolve
 * their needed imports, without worrying about any IAT/EAT/hot-patch hooks potentially introduced by 
 * AVs/EDRs.
 *
 * The program logic is following:
 *   1. It presents us with the first MessageBoxW that is not subject for hooking
 *   2. Then we hook MessageBoxW prologue ourselves to make it always return 0 without displaying it's message
 *   3. Finally, we resolve MessageBoxW dynamically using the UnhookingImportResolver resolver, which will detect
 *      applied prologue patches and restore original bytes, effectively unhooking MessageBoxW functionality.
 *
 * Compile with:
 *   /std:c++17
 *
 * Tested on both x86 and x64.
 *
 * Author:
 *    Mariusz Banach / mgeeky (@mariuszbit)
**/

#include <iostream>

//
// These are the only two required include statements your program will need.
//
#include "usings.h"
#include "resolver.h"


// optional include
#include "hexdump.hpp"


#ifndef _WIN64
#error "This resolver example was designed only for x64 architectures."
#endif


bool displayImportedFunction(const unsigned char*);

int main()
{
	// 
	// Here we Patch MessageBoxW's prologue stub to make it immediately return with 0, preventing 
	// malware from popping up those nasty messages!
	//
	unsigned char* ptr = reinterpret_cast<unsigned char*>(MessageBoxW);    

    std::wcout << L"1. Starting UnhookMe" << std::endl;

    displayImportedFunction(ptr);

    std::wcout << std::endl << L"Function's stub bytes:" << std::endl << getHexdump(ptr, 16) << std::endl;
    std::wcout << L"3. 1st MessageBox - not inspected (the one that may be monitored by EDRs/AVs)." << std::endl;

    MessageBoxW(0, L"This message box is subject for dynamic inspection.", L"First - Not inspected", 0);

    //
    // Step 1: Make MessageBoxW's stub RWX
    //
    DWORD old, old2;
    if (!VirtualProtect(ptr, 10, PAGE_EXECUTE_READWRITE, &old)) {
        return 0;
    }

    // xor rax, rax
    // ret
    std::wcout << L"4. Patching MessageBoxW's stub with (xor rax, rax; ret / 48 31 c0 c3)" << std::endl;
    unsigned char patch[] = { 0x48, 0x31, 0xC0, 0xC3 };

    //
    // Imagine instead of simple "return 0" hot patch, the Cylance EDR introduces here
    // their API inspection logic trampoline. We'll be able to easily wipe it out
    //
    memcpy(ptr, patch, _countof(patch));
    VirtualProtect(ptr, 10, old, &old2);

	std::wcout << getHexdump(ptr, 16) << std::endl;


    //
    // Step 2: Calling patched (instrumented, hooked) MessageBoxW - this will fail as we just patched
    //         function's prologue stub preventing any subsequent function calls
    //
    std::wcout << L"6. 2nd MessageBox - the one which stub was patched with a return 0 trampoline (it won't pop up)" << std::endl;

    MessageBoxW(0, L"This message box will never have chance to shine :(", L"Second - Hooked", 0);


    //
    // Step 3: As a fight back strategy we resolve MessageBoxW address dynamically here and let the resolver
    //         Do it's thing to safely unhook our lovely routine.
    //

    std::wcout << L"7. Resolving MessageBoxW's address dynamically, unhooking it along the way" << std::endl;

    RESOLVE(user32, MessageBoxW);
    unsigned char* ptr2 = reinterpret_cast<unsigned char*>(_MessageBoxW.getAddress());
    
    std::wcout << std::endl << L"8. 3rd MessageBox - the one that is unpatched, unhooked, invisible to user-mode API monitoring" << std::endl;
    std::wcout << L"9. Restored MessageBoxW stub bytes:" << std::endl << getHexdump(ptr, 16) << std::endl;

    if (ptr != ptr2)
    {
        std::wcout << L"10. MessageBoxW address: Hooked (0x" << std::hex << ptr << L"), Unhooked: (0x" << std::hex << ptr2 << L")" << std::endl;
    }
    else
    {
        std::wcout << L"10. MessageBoxW address: (0x" << std::hex << ptr << L") - was never really hooked, only trampolined." << std::endl;
    }

    _MessageBoxW(0, L"Look Ma! I'm unhooked!", L"Third - Unhooked", 0);

    //
    // From now on, MessageBoxW will remain unhooked. 
    //

    return 0;
}

bool displayImportedFunction(const unsigned char* ptr)
{
	PE pe;
    if (!pe.AnalyseProcess(0, true) || pe.GetError() != 0)
    {
        std::wcout << L"[!] Could not analyse own process memory. Error: " << pe.GetErrorString() << std::endl;;
        return false;
    }

    size_t num = 0;
	auto msgbox = std::find_if(pe.vImports.begin(), pe.vImports.end(), [&](const IMPORTED_FUNCTION& imp) {
		return !strcmp(imp.szFunction, "MessageBoxW");
		});

    if (msgbox == pe.vImports.end()) {
        std::wcout << L"[!] Could not find imported MessageBoxW thunk! Imports: " << pe.vImports.size() << std::endl;
        return false;
    }

	std::wcout << L"\t- Imported function hint: 0x" << std::dec << msgbox->dwHint << std::endl;
	std::wcout << L"\t- Imported function address: 0x" << std::hex << msgbox->dwPtrValueVA << std::endl;
    std::wcout << L"\t- Imported function RVA: 0x" << std::hex << msgbox->dwPtrValueRVA << std::endl;
	std::wcout << L"\t- Imported function thunk address: 0x" << std::hex << msgbox->dwThunkRVA << std::endl;
    std::wcout << L"\t- Hexdump of first 16 bytes from imported function's thunk:" << std::endl
        << getHexdump(reinterpret_cast<void*>(pe.RVA2VA64(msgbox->dwThunkRVA)), 16);

    return true;
}