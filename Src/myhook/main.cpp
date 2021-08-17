#include "stdafx.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DebugLog("MyHook DLL_PROCESS_ATTACH\n");
        hook_by_code("kernel32.dll", "UnhandledExceptionFilter", (PROC)NewUnhandledExceptionFilter, UEFOrgFP);
        hook_by_code("kernel32.dll", "SetUnhandledExceptionFilter", (PROC)NewSetUnhandledExceptionFilter, SUEFOrgFP);
        hook_by_code("kernel32.dll", "IsDebuggerPresent", (PROC)NewIsDebuggerPresent, IDPOriFP);
        hook_by_code("kernel32.dll", "GetSystemInfo", (PROC)NewGetSystemInfo, GSIOriFP);
        hook_by_code("kernel32.dll", "SetErrorMode", (PROC)SetErrorMode, SEMOriFP);
        break;
    case DLL_PROCESS_DETACH:
        DebugLog("MyHook DLL_PROCESS_DETACH\n");
        unhook_by_code("kernel32.dll", "UnhandledExceptionFilter", UEFOrgFP);
        unhook_by_code("kernel32.dll", "SetUnhandledExceptionFilter", SUEFOrgFP);
        unhook_by_code("kernel32.dll", "IsDebuggerPresent", IDPOriFP);
        unhook_by_code("kernel32.dll", "GetSystemInfo", GSIOriFP);
        unhook_by_code("kernel32.dll", "SetErrorMode", SEMOriFP);
        break;
    }
    return TRUE;
}