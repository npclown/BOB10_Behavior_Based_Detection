#pragma once
BYTE UEFOrgFP[5];
BYTE SUEFOrgFP[5];

LONG WINAPI NewUnhandledExceptionFilter(
    _EXCEPTION_POINTERS* ExceptionInfo
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"UnhandledExceptionFilter");

    unhook_by_code("kernel32.dll", "UnhandledExceptionFilter", UEFOrgFP);
    LONG ret = UnhandledExceptionFilter(ExceptionInfo);
    hook_by_code("kernel32.dll", "UnhandledExceptionFilter", (PROC)NewUnhandledExceptionFilter, UEFOrgFP);
    return ret;
}

LPTOP_LEVEL_EXCEPTION_FILTER WINAPI NewSetUnhandledExceptionFilter(
    LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"SetUnhandledExceptionFilter");

    unhook_by_code("kernel32.dll", "SetUnhandledExceptionFilter", SUEFOrgFP);
    LPTOP_LEVEL_EXCEPTION_FILTER ret = SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
    hook_by_code("kernel32.dll", "SetUnhandledExceptionFilter", (PROC)NewSetUnhandledExceptionFilter, SUEFOrgFP);
    return ret;
}