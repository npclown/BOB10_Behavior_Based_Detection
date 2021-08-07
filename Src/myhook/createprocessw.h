#pragma once
#include <Windows.h>
//hard coding 10byte patch
const char* OrgFP = "\x8B\xFF\x55\x8B\xEC"; // MOV EDI, EDI; PUSH EBP; MOV EBP, ESP;
const char* FPandJmp5Bytes = "\x55\x8B\xEC\xEB\x05"; // PUSH EBP; MOV EBP, ESP; JMP $(Current)+0x5;


typedef BOOL(WINAPI* PFCREATEPROCESSW)(
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
    );

 //Use NewCreateProcessW for Global Hooking
BOOL WINAPI NewCreateProcessW(
    _In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOW lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation
) {
    //unhook_by_code("kernel32.dll", "CreateProcessW", (LPVOID)((DWORD)&NewCreateProcessW), OrgFP);
    FARPROC pFunc = (FARPROC)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessW");
    pFunc = (FARPROC)((DWORD)pFunc + 2);
    BOOL ret = ((PFCREATEPROCESSW)pFunc)(lpApplicationName,
                                         lpCommandLine,
                                         lpProcessAttributes,
                                         lpThreadAttributes,
                                         bInheritHandles,
                                         dwCreationFlags,
                                         lpEnvironment,
                                         lpCurrentDirectory,
                                         lpStartupInfo,
                                         lpProcessInformation);
    
    //hook_by_code("kernel32.dll", "CreateProcessW", (LPVOID)((DWORD)&NewCreateProcessW), OrgFP);
    if (ret)
        InjectDll(lpProcessInformation->hProcess, DLLNAME);
    DebugLog("DllMain() : NewCreateProcessW\n");
    return ret;
}
