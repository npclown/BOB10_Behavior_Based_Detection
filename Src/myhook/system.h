#pragma once
BYTE IDPOriFP[5];
BYTE GSIOriFP[5];
BYTE SEMOriFP[5];
BYTE GetNativeSystemInfoOrgFP[5];
BYTE OutputDebugStringAOrgFPA[5];

BOOL WINAPI NewIsDebuggerPresent(VOID)
{
    DebugLog("%d %ls", GetCurrentProcessId(), L"IsDebuggerPresent");

    unhook_by_code("kernel32.dll", "IsDebuggerPresent", IDPOriFP);
    BOOL ret = IsDebuggerPresent();
    hook_by_code("kernel32.dll", "IsDebuggerPresent", (PROC)NewIsDebuggerPresent, IDPOriFP);
    return ret;
}

VOID WINAPI NewGetSystemInfo(
    LPSYSTEM_INFO lpSystemInfo
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetSystemInfo");

    unhook_by_code("kernel32.dll", "GetSystemInfo", GSIOriFP);
    GetSystemInfo(lpSystemInfo);
    hook_by_code("kernel32.dll", "GetSystemInfo", (PROC)NewGetSystemInfo, GSIOriFP);
}

UINT WINAPI NewSetErrorMode(
    UINT uMode
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"SetErrorMode");

    unhook_by_code("kernel32.dll", "SetErrorMode", SEMOriFP);
    UINT ret = SetErrorMode(uMode);
    hook_by_code("kernel32.dll", "SetErrorMode", (PROC)NewSetErrorMode, SEMOriFP);
    return ret;
}

VOID WINAPI NewGetNativeSystemInfo(
    _Out_ LPSYSTEM_INFO lpSystemInfo
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetNativeSystemInfo");

    unhook_by_code("kernel32.dll", "GetNativeSystemInfo", GetNativeSystemInfoOrgFP);
    GetNativeSystemInfo(lpSystemInfo);
    hook_by_code("kernel32.dll", "GetNativeSystemInfo", (PROC)NewGetNativeSystemInfo, GetNativeSystemInfoOrgFP);
}

VOID WINAPI NewOutputDebugStringA(
    _In_opt_ LPCSTR lpOutputString
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"OutputDebugStringA");

    unhook_by_code("kernel32.dll", "OutputDebugStringA", OutputDebugStringAOrgFPA);
    OutputDebugStringA(lpOutputString);
    hook_by_code("kernel32.dll", "OutputDebugStringA", (PROC)NewOutputDebugStringA, OutputDebugStringAOrgFPA);
}