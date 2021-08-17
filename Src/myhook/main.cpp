#include "stdafx.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DebugLog("MyHook DLL_PROCESS_ATTACH\n");
        //hook_by_code("kernel32.dll", "CreateFileW", (PROC)NewCreateFileW, OrgFPW);
        //hook_by_code("kernel32.dll", "CreateFileA", (PROC)NewCreateFileA, OrgFPA);
        hook_by_code("kernel32.dll", "OpenProcess", (PROC)NewOpenProcess, OP_OrgFP);
        hook_by_code("kernel32.dll", "TerminateProcess", (PROC)NewTerminateProcess, TP_OrgFP);
        hook_by_code("kernel32.dll", "CreateThread", (PROC)NewCreateThread, CT_OrgFP);
        hook_by_code("kernel32.dll", "ResumeThread", (PROC)NewResumeThread, RT_OrgFP);
        hook_by_code("kernel32.dll", "SuspendThread", (PROC)NewSuspendThread, ST_OrgFP);
        break;
    case DLL_PROCESS_DETACH:
        DebugLog("MyHook DLL_PROCESS_DETACH\n");
        //unhook_by_code("kernel32.dll", "CreateFileW", OrgFPW);
        //unhook_by_code("kernel32.dll", "CreateFileA", OrgFPA);
        unhook_by_code("kernel32.dll", "OpenProcess", OP_OrgFP);
        unhook_by_code("kernel32.dll", "TerminateProcess", TP_OrgFP);
        unhook_by_code("kernel32.dll", "CreateThread", CT_OrgFP);
        unhook_by_code("kernel32.dll", "ResumeThread", RT_OrgFP);
        unhook_by_code("kernel32.dll", "SuspendThread", ST_OrgFP);
        break;
    }
    return TRUE;
}