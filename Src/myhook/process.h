#pragma once
BYTE OP_OrgFP[5];
BYTE TP_OrgFP[5];
BYTE CT_OrgFP[5];
BYTE RT_OrgFP[5];
BYTE ST_OrgFP[5];
BYTE Module32FirstWOrgFPW[5];
BYTE Module32NextWOrgFPW[5];
BYTE Process32FirstWOrgFPW[5];
BYTE Process32NextWOrgFPW[5];
BYTE Thread32FirstOrgFP[5];
BYTE Thread32NextOrgFP[5];
BYTE ReadProcessMemoryOrgFP[5];
BYTE WriteProcessMemoryOrgFP[5];
BYTE CreateRemoteThreadOrgFP[5];
BYTE CreateToolhelp32SnapshotOrgFP[5];

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

BOOL WINAPI NewModule32FirstW(
    HANDLE hSnapshot,
    LPMODULEENTRY32W lpme
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"Module32FirstW");
    unhook_by_code("kernel32.dll", "Module32FirstW", Module32FirstWOrgFPW);

    BOOL ret = Module32FirstW(hSnapshot,
                              lpme);
    hook_by_code("kernel32.dll", "Module32FirstW", (PROC)NewModule32FirstW, Module32FirstWOrgFPW);
    return ret;
}

BOOL WINAPI NewModule32NextW(
    HANDLE hSnapshot,
    LPMODULEENTRY32W lpme
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"Module32NextW");
    unhook_by_code("kernel32.dll", "Module32NextW", Module32NextWOrgFPW);

    BOOL ret = Module32NextW(hSnapshot,
                            lpme);
    hook_by_code("kernel32.dll", "Module32NextW", (PROC)NewModule32NextW, Module32NextWOrgFPW);
    return ret;
}

BOOL WINAPI NewProcess32FirstW(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"Process32FirstW");
    unhook_by_code("kernel32.dll", "Process32FirstW", Process32FirstWOrgFPW);

    BOOL ret = Process32FirstW(hSnapshot,
                                lppe);
    hook_by_code("kernel32.dll", "Process32FirstW", (PROC)NewProcess32FirstW, Process32FirstWOrgFPW);
    return ret;
}

BOOL WINAPI NewProcess32NextW(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"Process32NextW");
    unhook_by_code("kernel32.dll", "Process32NextW", Process32NextWOrgFPW);

    BOOL ret = Process32NextW(hSnapshot,
                              lppe);
    hook_by_code("kernel32.dll", "Process32NextW", (PROC)NewProcess32NextW, Process32NextWOrgFPW);
    return ret;
}

BOOL WINAPI NewThread32First(
    HANDLE hSnapshot,
    LPTHREADENTRY32 lpte
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"Thread32First");
    unhook_by_code("kernel32.dll", "Thread32First", Thread32FirstOrgFP);

    BOOL ret = Thread32First(hSnapshot,
                            lpte);
    hook_by_code("kernel32.dll", "Thread32First", (PROC)NewThread32First, Thread32FirstOrgFP);
    return ret;
}

BOOL WINAPI NewThread32Next(
    HANDLE hSnapshot,
    LPTHREADENTRY32 lpte
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"Thread32Next");
    unhook_by_code("kernel32.dll", "Thread32Next", Thread32NextOrgFP);

    BOOL ret = Thread32Next(hSnapshot,
                            lpte);
    hook_by_code("kernel32.dll", "Thread32Next", (PROC)NewThread32Next, Thread32NextOrgFP);
    return ret;
}

BOOL WINAPI NewReadProcessMemory(
    _In_ HANDLE hProcess,
    _In_ LPCVOID lpBaseAddress,
    _Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T* lpNumberOfBytesRead
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"ReadProcessMemory");
    unhook_by_code("kernel32.dll", "ReadProcessMemory", ReadProcessMemoryOrgFP);

    BOOL ret = ReadProcessMemory(hProcess,
                                lpBaseAddress,
                                lpBuffer,
                                nSize,
                                lpNumberOfBytesRead);
    hook_by_code("kernel32.dll", "ReadProcessMemory", (PROC)NewReadProcessMemory, ReadProcessMemoryOrgFP);
    return ret;
}

BOOL WINAPI NewWriteProcessMemory(
    _In_ HANDLE hProcess,
    _In_ LPVOID lpBaseAddress,
    _In_reads_bytes_(nSize) LPCVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T* lpNumberOfBytesWritten
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"WriteProcessMemory");
    unhook_by_code("kernel32.dll", "WriteProcessMemory", WriteProcessMemoryOrgFP);

    BOOL ret = WriteProcessMemory(hProcess,
                                lpBaseAddress,
                                lpBuffer,
                                nSize,
                                lpNumberOfBytesWritten);
    hook_by_code("kernel32.dll", "WriteProcessMemory", (PROC)NewWriteProcessMemory, WriteProcessMemoryOrgFP);
    return ret;
}

HANDLE WINAPI NewCreateRemoteThread(
    _In_ HANDLE hProcess,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ SIZE_T dwStackSize,
    _In_ LPTHREAD_START_ROUTINE lpStartAddress,
    _In_opt_ LPVOID lpParameter,
    _In_ DWORD dwCreationFlags,
    _Out_opt_ LPDWORD lpThreadId
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"CreateRemoteThread");
    unhook_by_code("kernel32.dll", "CreateRemoteThread", CreateRemoteThreadOrgFP);

    HANDLE ret = CreateRemoteThread(hProcess,
                                    lpThreadAttributes,
                                    dwStackSize,
                                    lpStartAddress,
                                    lpParameter,
                                    dwCreationFlags,
                                    lpThreadId);
    hook_by_code("kernel32.dll", "CreateRemoteThread", (PROC)NewCreateRemoteThread, CreateRemoteThreadOrgFP);
    return ret;
}

HANDLE WINAPI NewCreateToolhelp32Snapshot(
    DWORD dwFlags,
    DWORD th32ProcessID
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"CreateToolhelp32Snapshot");
    unhook_by_code("kernel32.dll", "CreateToolhelp32Snapshot", CreateToolhelp32SnapshotOrgFP);

    HANDLE ret = CreateToolhelp32Snapshot(dwFlags,
                                           th32ProcessID);
    hook_by_code("kernel32.dll", "CreateToolhelp32Snapshot", (PROC)NewCreateToolhelp32Snapshot, CreateToolhelp32SnapshotOrgFP);
    return ret;
}
