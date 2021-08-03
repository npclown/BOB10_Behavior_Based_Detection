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

#include "pch.h" // Precompiled Header

#include <stdio.h>
#include <Windows.h>

#pragma pack(push, 1)
struct JMP_5Bytes
{
    BYTE opcode; // 0xE9 : Relative Jump
    LPVOID lpTarget;
};
#pragma pack(pop)


const char* OrgFP = "\x8B\xFF\x55\x8B\xEC"; // MOV EDI, EDI; PUSH EBP; MOV EBP, ESP;
const char* FPandJmp5Bytes = "\x55\x8B\xEC\xEB\x05"; // PUSH EBP; MOV EBP, ESP; JMP $(Current)+0x5;

typedef BOOL WINAPI tWriteFile(
    _In_        HANDLE       hFile,
    _In_        LPCVOID      lpBuffer,
    _In_        DWORD        nNumberOfBytesToWrite,
    _Out_opt_   LPDWORD      lpNumberOfBytesWritten,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
);

DWORD WINAPI Hook32();
DWORD WINAPI Unhook32();

tWriteFile* newWriteFile;
tWriteFile* orgWriteFile;
BOOL Hooked = FALSE;

BOOL WINAPI NewWriteFile(
    _In_        HANDLE       hFile,
    _In_        LPCVOID      lpBuffer,
    _In_        DWORD        nNumberOfBytesToWrite,
    _Out_opt_   LPDWORD      lpNumberOfBytesWritten,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
)
{
    if (nNumberOfBytesToWrite > 0)
        MessageBoxA(NULL, (LPCSTR)lpBuffer, NULL, NULL);

    MessageBoxA(NULL, "NewWriteFile", "NewWriteFile", MB_OK);
    Unhook32();
    BOOL ret = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    Hook32();

    return ret;
}

DWORD WINAPI Hook32()
{
    if (Hooked)
        return 0; // Already Hooked

    // Get address of target function
    LPVOID lpOrgFunc = NULL;
    if ((lpOrgFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile")) == NULL)
        return -1;

    // Inline Hook
    orgWriteFile = (tWriteFile*)((DWORD)lpOrgFunc - 5);

    // Backup old protect
    DWORD dwOldProtect;
    if (VirtualProtect((LPVOID)((DWORD)lpOrgFunc - 5), 10, PAGE_EXECUTE_READWRITE, &dwOldProtect) == NULL)
        return -1;

    JMP_5Bytes newFuncObj;
    newFuncObj.opcode = 0xE9; // Relative Jump
    newFuncObj.lpTarget = (LPVOID)((DWORD)(&NewWriteFile) - (DWORD)lpOrgFunc - 5); // Set new functon to replace

    memcpy_s((LPVOID)((DWORD)lpOrgFunc - 5), 5, FPandJmp5Bytes, 5);// Replacing
    memcpy_s(lpOrgFunc, 5, &newFuncObj, 5);

    // Rollback protection
    VirtualProtect((LPVOID)((DWORD)lpOrgFunc - 5), 10, dwOldProtect, NULL);

    Hooked = TRUE;
    return 0;
}

DWORD WINAPI Unhook32()
{
    if (!Hooked)
        return 0; // Not Hooked

    LPVOID lpOrgFunc = NULL;
    if ((lpOrgFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile")) == NULL)
        return -1;

    // Inline Hook
    // Backup old protect
    DWORD dwOldProtect;
    if (VirtualProtect((LPVOID)((DWORD)lpOrgFunc - 5), 10, PAGE_EXECUTE_READWRITE, &dwOldProtect) == NULL)
        return -1;

    JMP_5Bytes newFuncObj;
    newFuncObj.opcode = 0xE9; // Relative Jump
    newFuncObj.lpTarget = (LPVOID)((DWORD)(&NewWriteFile) - (DWORD)lpOrgFunc - 5); // Set new functon to replace

    memset((tWriteFile*)((DWORD)lpOrgFunc - 5), 0x90, 5);// Set 5-byte NOP
    memcpy_s(lpOrgFunc, 5, OrgFP, 5);

    // Rollback protection
    VirtualProtect((LPVOID)((DWORD)lpOrgFunc - 5), 10, dwOldProtect, NULL);

    Hooked = FALSE;
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "Hook Ready", "Hook Ready", MB_OK);
        Hook32();
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}