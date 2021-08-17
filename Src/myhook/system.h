#pragma once
BYTE IDPOriFP[5];
BYTE GSIOriFP[5];
BYTE SEMOriFP[5];

BOOL WINAPI NewIsDebuggerPresent()
{
    DebugLog("%d %ls", GetCurrentProcessId(), L"SetUnhandledExceptionFilter");

    unhook_by_code("kernel32.dll", "IsDebuggerPresent", IDPOriFP);
    BOOL ret = IsDebuggerPresent();
    hook_by_code("kernel32.dll", "IsDebuggerPresent", (PROC)IsDebuggerPresent, IDPOriFP);
    return ret;
}

void WINAPI NewGetSystemInfo(
    LPSYSTEM_INFO lpSystemInfo
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetSystemInfo");

    unhook_by_code("kernel32.dll", "GetSystemInfo", GSIOriFP);
    GetSystemInfo(lpSystemInfo);
    hook_by_code("kernel32.dll", "GetSystemInfo", (PROC)GetSystemInfo, GSIOriFP);
}

UINT NewSetErrorMode(
    UINT uMode
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"SetErrorMode");

    unhook_by_code("kernel32.dll", "SetErrorMode", SEMOriFP);
    UINT ret = SetErrorMode(uMode);
    hook_by_code("kernel32.dll", "SetErrorMode", (PROC)SetErrorMode, SEMOriFP);
    return ret;
}