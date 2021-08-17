BYTE UEFOrgFPW[5];

LONG WINAPI NewUnhandledExceptionFilter(
    _EXCEPTION_POINTERS* ExceptionInfo
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"UnhandledExceptionFilter");

    unhook_by_code("kernel32.dll", "UnhandledExceptionFilter", UEFOrgFPW);
    LONG ret = UnhandledExceptionFilter(ExceptionInfo);
    hook_by_code("kernel32.dll", "UnhandledExceptionFilter", (PROC)UnhandledExceptionFilter, UEFOrgFPW);
    return ret;
}