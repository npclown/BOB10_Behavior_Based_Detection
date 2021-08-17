#include "stdafx.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DebugLog("MyHook DLL_PROCESS_ATTACH\n");
        hook_by_code("kernel32.dll", "CreateFileW", (PROC)NewCreateFileW, CreateFileOrgFPW);
        hook_by_code("kernel32.dll", "CreateFileA", (PROC)NewCreateFileA, CreateFileOrgFPA);
        hook_by_code("kernel32.dll", "DeleteFileW", (PROC)NewDeleteFileW, DeleteFileOrgFPW);
        hook_by_code("kernel32.dll", "DeleteFileA", (PROC)NewDeleteFileA, DeleteFileOrgFPA);
        hook_by_code("kernel32.dll", "ReadFile", (PROC)NewReadFile, ReadFileOrgFP);
        break;
    case DLL_PROCESS_DETACH:
        DebugLog("MyHook DLL_PROCESS_DETACH\n");
        unhook_by_code("kernel32.dll", "CreateFileW", CreateFileOrgFPW);
        unhook_by_code("kernel32.dll", "CreateFileA", CreateFileOrgFPA);
        unhook_by_code("kernel32.dll", "DeleteFileW", DeleteFileOrgFPW);
        unhook_by_code("kernel32.dll", "DeleteFileA", DeleteFileOrgFPA);
        unhook_by_code("kernel32.dll", "ReadFile", ReadFileOrgFP);
        break;
    }
    return TRUE;
}