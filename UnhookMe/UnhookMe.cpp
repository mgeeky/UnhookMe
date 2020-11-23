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

#ifndef _WIN64
#error "This resolver example was designed only for x64 architectures."
#endif

int main()
{
    MessageBoxW(0, L"This message box is subject for dynamic inspection.", L"First - Not inspected", 0);

    // 
    // Here we Patch MessageBoxW's prologue stub to make it immediately return with 0, preventing 
    // malware from popping up those nasty messages!
    //
    unsigned char *ptr = reinterpret_cast<unsigned char*>(MessageBoxW);

    //
    // Step 1: Make MessageBoxW's stub RWX
    //
    DWORD old;
    if (!VirtualProtect(ptr, 10, PAGE_EXECUTE_READWRITE, &old)) {
        return 0;
    }

    // xor rax, rax
    // ret
    unsigned char patch[] = { 0x48, 0x31, 0xC0, 0xC3 };

    //
    // Imagine instead of simple "return 0" hot patch, the Cylance EDR introduces here
    // their API inspection logic trampoline. We'll be able to easily wipe it out
    //
    memcpy(ptr, patch, _countof(patch));


    //
    // Step 2: Calling patched (instrumented, hooked) MessageBoxW - this will fail as we just patched
    //         function's prologue stub preventing any subsequent function calls
    //
    MessageBoxW(0, L"This message box will never have chance to shine :(", L"Second - Hooked", 0);


    //
    // Step 3: As a fight back strategy we resolve MessageBoxW address dynamically here and let the resolver
    //         Do it's thing to safely unhook our lovely routine.
    //
    RESOLVE(user32, MessageBoxW);
    
    _MessageBoxW(0, L"Look Ma! I'm unhooked!", L"Third - Unhooked", 0);

    //
    // From now on, MessageBoxW will remain unhooked. 
    //
}
