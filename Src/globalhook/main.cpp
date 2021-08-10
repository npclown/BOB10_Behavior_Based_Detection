#include "stdafx.h"
#include <dllheader.h>

BYTE OrgFPW[5];
BYTE OrgFPA[5];

BOOL WINAPI NewCreateProcessW(
    LPCTSTR lpApplicationName,
    LPTSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCTSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    DebugLog("%d %ls", GetCurrentProcessId(), L"CreateProessW");
    unhook_by_code("kernel32.dll", "CreateProcessW", OrgFPW);
    BOOL bRet;

    // original API 호출
    bRet = CreateProcessW(lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation);

    if (bRet) {
        InjectDll(lpProcessInformation->hProcess, DLLNAME);
        InjectDll(lpProcessInformation->hProcess, DLLNAME1);
    }

    hook_by_code("kernel32.dll", "CreateProcessW", (PROC)NewCreateProcessW, OrgFPW);
    return bRet;
}

BOOL WINAPI NewCreateProcessA(
    LPCTSTR lpApplicationName,
    LPTSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCTSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    DebugLog("%d %ls", GetCurrentProcessId(), L"CreateProessA");
    unhook_by_code("kernel32.dll", "CreateProcessA", OrgFPA);
    BOOL bRet;

    // original API 호출
    bRet = CreateProcessW(lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation);

    if (bRet) {
        InjectDll(lpProcessInformation->hProcess, DLLNAME);
        InjectDll(lpProcessInformation->hProcess, DLLNAME1);
    }

    hook_by_code("kernel32.dll", "CreateProcessA", (PROC)NewCreateProcessA, OrgFPA);

    return bRet;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DebugLog("GlobalHook DLL_PROCESS_ATTACH\n");
        hook_by_code("kernel32.dll", "CreateProcessW", (PROC)NewCreateProcessW, OrgFPW);
        hook_by_code("kernel32.dll", "CreateProcessA", (PROC)NewCreateProcessA, OrgFPA);
        break;
    case DLL_PROCESS_DETACH:
        DebugLog("GlobalHook DLL_PROCESS_DETACH\n");
        unhook_by_code("kernel32.dll", "CreateProcessW", OrgFPW);
        unhook_by_code("kernel32.dll", "CreateProcessA", OrgFPA);
        break;
    }
    return TRUE;
}