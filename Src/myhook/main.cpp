
// The MIT License

// Copyright (c) 2019 Sanghyeon Jeon

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#include "stdafx.h"
#include "createprocess.h"

#pragma pack(push, 1)
struct JMP_5Bytes
{
    BYTE opcode; // 0xE9 : Relative Jump
    LPVOID lpTarget;
};
#pragma pack(pop)

BOOL Hooked = FALSE;

//For checking the debugging log
void DebugLog(const char* format, ...)
{
    va_list vl;
    FILE* pf = NULL;
    char szLog[512] = { 0, };

    va_start(vl, format);
    wsprintfA(szLog, format, vl);
    va_end(vl);

    OutputDebugStringA(szLog);
}

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    HANDLE hToken;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken))
    {
        DebugLog("OpenProcessToken error: %u\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL,             // lookup privilege on local system
        lpszPrivilege,    // privilege to lookup 
        &luid))          // receives LUID of privilege
    {
        DebugLog("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.
    if (!AdjustTokenPrivileges(hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        DebugLog("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        DebugLog("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}

BOOL InjectDll(HANDLE hProcess, LPCTSTR szDllName)
{
    HANDLE hThread;
    LPVOID pRemoteBuf;
    DWORD dwBufSize = (DWORD)(_tcslen(szDllName) + 1) * sizeof(TCHAR);
    FARPROC pThreadProc;

    pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize,
        MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteBuf == NULL)
        return FALSE;

    WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllName,
        dwBufSize, NULL);

    pThreadProc = GetProcAddress(GetModuleHandleA("kernel32.dll"),
        "LoadLibraryW");
    hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pThreadProc,
        pRemoteBuf, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

    CloseHandle(hThread);

    return TRUE;
}

DWORD WINAPI hook_by_code(LPCSTR szDllName, LPCSTR apiName, LPVOID newApiName, const char* orgByte)
{
    if (Hooked)
        return 0; // Already Hooked
    
    // Get address of target function
    LPVOID lpOrgFunc = NULL;
    if ((lpOrgFunc = (LPVOID)GetProcAddress(GetModuleHandleA(szDllName), apiName)) == NULL)
        return -1;

    // Backup old protect
    DWORD dwOldProtect;
    if (VirtualProtect((LPVOID)((DWORD)lpOrgFunc-5), 7, PAGE_EXECUTE_READWRITE, &dwOldProtect) == NULL)
        return -1;

    JMP_5Bytes newFuncObj;
    newFuncObj.opcode = 0xE9; // Relative Jump
    newFuncObj.lpTarget = (LPVOID)((DWORD)(newApiName) - (DWORD)lpOrgFunc); // Set new functon to replace

    memcpy_s((LPVOID)((DWORD)lpOrgFunc-5), 5, &newFuncObj, 5);
    memcpy_s(lpOrgFunc, 2, "\xEB\xF9", 2);

    // Rollback protection
    VirtualProtect((LPVOID)((DWORD)lpOrgFunc - 5), 7, dwOldProtect, NULL);

    Hooked = TRUE;
    return 0;
}

DWORD WINAPI unhook_by_code(LPCSTR szDllName, LPCSTR apiName, LPVOID newApiName, const char* orgByte)
{
    if (!Hooked)
        return 0; // Not Hooked

    LPVOID lpOrgFunc = NULL;
    if ((lpOrgFunc = (LPVOID)GetProcAddress(GetModuleHandleA(szDllName), apiName)) == NULL)
        return -1;

    // Inline Hook
    // Backup old protect
    DWORD dwOldProtect;
    if (VirtualProtect((LPVOID)((DWORD)lpOrgFunc - 5), 7, PAGE_EXECUTE_READWRITE, &dwOldProtect) == NULL)
        return -1;

    memcpy_s((LPVOID)((DWORD)lpOrgFunc - 5), 5, "\x90\x90\x90\x90\x90", 5);
    memcpy_s(lpOrgFunc, 2, "\x8B\xFF", 2);

    // Rollback protection
    VirtualProtect((LPVOID)((DWORD)lpOrgFunc - 5), 7, dwOldProtect, NULL);

    Hooked = FALSE;
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DebugLog("DllMain() : DLL_PROCESS_ATTACH\n");
        hook_by_code("kernel32.dll", "CreateProcessW", (LPVOID)((DWORD)&NewCreateProcessW), OrgFP);
        hook_by_code("kernel32.dll", "CreateProcessA", (LPVOID)((DWORD)&NewCreateProcessA), OrgFP);
        break;
    case DLL_PROCESS_DETACH:
        unhook_by_code("kernel32.dll", "CreateProcessW", (LPVOID)((DWORD)&NewCreateProcessW), OrgFP);
        unhook_by_code("kernel32.dll", "CreateProcessA", (LPVOID)((DWORD)&NewCreateProcessA), OrgFP);
        DebugLog("DllMain() : DLL_PROCESS_DETACH\n");
        break;
    }
    return TRUE;
}