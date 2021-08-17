#include "stdafx.h"
#include <dllheader.h>
#include "NewCreateFile.h"

//
#include "exception.h"
#include "system.h"
#include "process.h"
#include "file.h"
#include "resource.h"
#include "misc.h"
#include "synchronisation.h"

BYTE OrgFPW[5];
BYTE OrgFPA[5];

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DebugLog("MyHook DLL_PROCESS_ATTACH\n");
        hook_by_code("kernel32.dll", "CreateFileW", (PROC)NewCreateFileW, OrgFPW);
        hook_by_code("kernel32.dll", "CreateFileA", (PROC)NewCreateFileA, OrgFPA);
        hook_by_code("kernel32.dll", "NewUnhandledExceptionFilter", (PROC)NewUnhandledExceptionFilter, OrgFPA);
        break;
    case DLL_PROCESS_DETACH:
        DebugLog("MyHook DLL_PROCESS_DETACH\n");
        unhook_by_code("kernel32.dll", "CreateFileW", OrgFPW);
        unhook_by_code("kernel32.dll", "CreateFileA", OrgFPA);
        unhook_by_code("kernel32.dll", "NewUnhandledExceptionFilter", OrgFPA);

        break;
    }
    return TRUE;
}