#pragma once
BYTE OP_OrgFP[5];
BYTE TP_OrgFP[5];
BYTE CT_OrgFP[5];
BYTE RT_OrgFP[5];
BYTE ST_OrgFP[5];

HANDLE WINAPI NewOpenProcess(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"OpenProcess");
    unhook_by_code("kernel32.dll", "OpenProcess", OP_OrgFP);

    HANDLE ret = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    hook_by_code("kernel32.dll", "OpenProcess", (PROC)NewOpenProcess, OP_OrgFP);
    return ret;
}

BOOL WINAPI NewTerminateProcess(
    _In_ HANDLE hProcess,
    _In_ UINT uExitCode
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"TerminateProcess");
    unhook_by_code("kernel32.dll", "TerminateProcess", TP_OrgFP);

    BOOL ret = TerminateProcess(hProcess, uExitCode);
    hook_by_code("kernel32.dll", "TerminateProcess", (PROC)NewTerminateProcess, TP_OrgFP);
    return ret;
}

HANDLE WINAPI NewCreateThread(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    __drv_aliasesMem LPVOID lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"CreateThread");
    unhook_by_code("kernel32.dll", "CreateThread", CT_OrgFP);

    HANDLE ret = CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    hook_by_code("kernel32.dll", "CreateThread", (PROC)NewCreateThread, CT_OrgFP);
    return ret;
}

DWORD WINAPI NewResumeThread(
    HANDLE hThread
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"ResumeThread");
    unhook_by_code("kernel32.dll", "ResumeThread", RT_OrgFP);

    DWORD ret = ResumeThread(hThread);
    hook_by_code("kernel32.dll", "ResumeThread", (PROC)NewResumeThread, RT_OrgFP);
    return ret;
}

DWORD WINAPI NewSuspendThread(
    HANDLE hThread
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"SuspendThread");
    unhook_by_code("kernel32.dll", "SuspendThread", ST_OrgFP);

    DWORD ret = SuspendThread(hThread);
    hook_by_code("kernel32.dll", "SuspendThread", (PROC)NewSuspendThread, ST_OrgFP);
    return ret;
}
