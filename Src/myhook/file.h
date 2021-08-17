#pragma once
BYTE CreateFileOrgFPW[5];
BYTE CreateFileOrgFPA[5];

HANDLE WINAPI NewCreateFileW(
    _In_ LPCWSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"CreateFileW");
    unhook_by_code("kernel32.dll", "CreateFileW", CreateFileOrgFPW);

    if (dwDesiredAccess & (GENERIC_ALL | GENERIC_WRITE | WRITE_OWNER)) {
        if (wcsstr(wcslwr((LP)lpFileName), L"system32") != NULL && wcsstr(wcslwr((LP)lpFileName), L".exe") == NULL) {
            wchar_t result[512];
            wsprintf(result, L"시스템 폴더에 접근을 시도하였습니다. \n %ls 해당 폴더의 접근을 허용하시겠습니까?\n", (LPCWSTR)lpFileName);
            int input = MessageBox(NULL, result, L"Detected", MB_YESNO);
            if (input == IDNO) {
                MessageBox(NULL, L"해당 폴더을 접근을 차단하였습니다.", L"차단", MB_OK);
                hook_by_code("kernel32.dll", "CreateFileW", (PROC)NewCreateFileW, CreateFileOrgFPW);
                return NULL;
            }
        }

        if (wcsstr(wcslwr((LP)lpFileName), L".sys") != NULL) {
            wchar_t result[512];
            wsprintf(result, L"시스템 파일에 접근을 시도하였습니다. \n %ls 해당 파일의 접근을 허용하시겠습니까?\n", (LPCWSTR)lpFileName);
            int input = MessageBox(NULL, result, L"Detected", MB_YESNO);
            if (input == IDNO) {
                MessageBox(NULL, L"해당 파일을 차단하였습니다.", L"차단", MB_OK);
                hook_by_code("kernel32.dll", "CreateFileW", (PROC)NewCreateFileW, CreateFileOrgFPW);
                return NULL;
            }
        }
    }

    HANDLE ret = CreateFileW(lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile);

    hook_by_code("kernel32.dll", "CreateFileW", (PROC)NewCreateFileW, CreateFileOrgFPW);

    return ret;
}

HANDLE WINAPI NewCreateFileA(
    _In_ LPCSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"CreateFileA");
    unhook_by_code("kernel32.dll", "CreateFileA", CreateFileOrgFPA);

    if (dwDesiredAccess & (GENERIC_ALL | GENERIC_WRITE | WRITE_OWNER)) {
        if (strstr(strlwr((LPSTR)lpFileName), "system32") != NULL && strstr(strlwr((LPSTR)lpFileName), ".exe") == NULL) {
            wchar_t result[512];
            wsprintf(result, L"시스템 폴더에 접근을 시도하였습니다. \n %ls 해당 폴더의 접근을 허용하시겠습니까?\n", (LPCSTR)lpFileName);
            int input = MessageBox(NULL, result, L"Detected", MB_YESNO);
            if (input == IDNO) {
                MessageBox(NULL, L"해당 폴더을 접근을 차단하였습니다.", L"차단", MB_OK);
                hook_by_code("kernel32.dll", "CreateFileW", (PROC)NewCreateFileW, CreateFileOrgFPA);
                return NULL;
            }
        }

        if (strstr(strlwr((LPSTR)lpFileName), ".sys") != NULL) {
            wchar_t result[512];
            wsprintf(result, L"시스템 파일에 접근을 시도하였습니다. \n %ls 해당 파일의 접근을 허용하시겠습니까?\n", (LPCWSTR)lpFileName);
            int input = MessageBox(NULL, result, L"Detected", MB_YESNO);
            if (input == IDNO) {
                MessageBox(NULL, L"해당 파일을 차단하였습니다.", L"차단", MB_OK);
                hook_by_code("kernel32.dll", "CreateFileW", (PROC)NewCreateFileW, CreateFileOrgFPA);
                return NULL;
            }
        }
    }

    HANDLE ret = CreateFileA(lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile);

    hook_by_code("kernel32.dll", "CreateFileA", (PROC)NewCreateFileA, CreateFileOrgFPA);
    DebugLog("DllMain() : NewCreateFileA\n");
    return ret;
}
