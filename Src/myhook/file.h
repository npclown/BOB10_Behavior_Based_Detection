#pragma once
BYTE CreateFileOrgFPW[5];
BYTE CreateFileOrgFPA[5];
BYTE DeleteFileOrgFPW[5];
BYTE DeleteFileOrgFPA[5];
BYTE ReadFileOrgFP[5];
BYTE WriteFileOrgFP[5];
BYTE CreateDirectoryOrgFPW[5];
BYTE CreateDirectoryOrgFPA[5];
BYTE CopyFileOrgFPW[5];
BYTE CopyFileOrgFPA[5];
BYTE GetTempPathOrgFPW[5];
BYTE GetTempPathOrgFPA[5];
BYTE FindFirstFileOrgFPW[5];
BYTE FindFirstFileOrgFPA[5];
BYTE GetFileAttributesOrgFPW[5];
BYTE GetFileAttributesOrgFPA[5];
BYTE GetFileSizeOrgFP[5];
BYTE SetEndOfFileOrgFP[5];
BYTE SetFilePointerOrgFP[5];
BYTE GetFileInformationByHandleOrgFP[5];
BYTE GetFileInformationByHandleExOrgFP[5];
BYTE GetFileTypeOrgFP[5];
BYTE GetShortPathNameWOrgFP[5];
BYTE GetSystemDirectoryAOrgFP[5];
BYTE GetSystemDirectoryWOrgFP[5];
BYTE GetSystemWindowsDirectoryWOrgFP[5];
BYTE GetVolumeNameForVolumeMountPointWOrgFP[5];
BYTE GetVolumePathNamesForVolumeNameWOrgFP[5];
BYTE GetVolumePathNameWOrgFP[5];
BYTE MoveFileWithProgressWOrgFp[5];
BYTE RemoveDirectoryWOrgFP[5];
BYTE SearchPathWOrgFP[5];
BYTE SetFileAttributesWOrgFP[5];
BYTE SetFileInformationByHandleOrgFP[5];
BYTE FindFirstFileExWOrgFPW[5];

BOOL WINAPI NewSetFileInformationByHandle(
    HANDLE                    hFile,
    FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
    LPVOID                    lpFileInformation,
    DWORD                     dwBufferSize
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"SetFileInformationByHandle");
    unhook_by_code("kernel32.dll", "SetFileInformationByHandle", SetFileInformationByHandleOrgFP);

    BOOL ret = SetFileInformationByHandle(
        hFile,
        FileInformationClass,
        lpFileInformation,
        dwBufferSize
    );
    hook_by_code("kernel32.dll", "SetFileInformationByHandle", (PROC)NewSetFileInformationByHandle, SetFileInformationByHandleOrgFP);
    return ret;
}

BOOL WINAPI NewSetFileAttributesW(
    LPCWSTR lpFileName,
    DWORD   dwFileAttributes
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"SetFileAttributesW");
    unhook_by_code("kernel32.dll", "SetFileAttributesW", SetFileAttributesWOrgFP);

    BOOL ret = SetFileAttributesW(
        lpFileName,
        dwFileAttributes
    );
    hook_by_code("kernel32.dll", "SetFileAttributesW", (PROC)NewSetFileAttributesW, SetFileAttributesWOrgFP);
    return ret;
}

DWORD WINAPI NweSearchPathW(
    LPCWSTR lpPath,
    LPCWSTR lpFileName,
    LPCWSTR lpExtension,
    DWORD   nBufferLength,
    LPWSTR  lpBuffer,
    LPWSTR* lpFilePart
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"SearchPathW");
    unhook_by_code("kernel32.dll", "SearchPathW", SearchPathWOrgFP);

    BOOL ret = SearchPathW(
        lpPath,
        lpFileName,
        lpExtension,
        nBufferLength,
        lpBuffer,
        lpFilePart
    );
    hook_by_code("kernel32.dll", "SearchPathW", (PROC)NweSearchPathW, SearchPathWOrgFP);
    return ret;
}

BOOL WINAPI NewRemoveDirectoryW(
    LPCWSTR lpPathName
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"RemoveDirectoryW");
    unhook_by_code("kernel32.dll", "RemoveDirectoryW", RemoveDirectoryWOrgFP);

    BOOL ret = RemoveDirectoryW(
        lpPathName
    );
    hook_by_code("kernel32.dll", "RemoveDirectoryW", (PROC)NewRemoveDirectoryW, RemoveDirectoryWOrgFP);
    return ret;
}

BOOL WINAPI NewMoveFileWithProgressW(
    LPCWSTR            lpExistingFileName,
    LPCWSTR            lpNewFileName,
    LPPROGRESS_ROUTINE lpProgressRoutine,
    LPVOID             lpData,
    DWORD              dwFlags
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"MoveFileWithProgressW");
    unhook_by_code("kernel32.dll", "MoveFileWithProgressW", MoveFileWithProgressWOrgFp);

    BOOL ret = MoveFileWithProgressW(
        lpExistingFileName,
        lpNewFileName,
        lpProgressRoutine,
        lpData,
        dwFlags
    );
    hook_by_code("kernel32.dll", "MoveFileWithProgressW", (PROC)NewMoveFileWithProgressW, MoveFileWithProgressWOrgFp);
    return ret;
}

BOOL WINAPI NewGetVolumePathNameW(
    LPCWSTR lpszFileName,
    LPWSTR  lpszVolumePathName,
    DWORD   cchBufferLength
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetVolumePathNameW");
    unhook_by_code("kernel32.dll", "GetVolumePathNameW", GetVolumePathNameWOrgFP);

    BOOL ret = GetVolumePathNameW(
        lpszFileName,
        lpszVolumePathName,
        cchBufferLength
    );
    hook_by_code("kernel32.dll", "GetVolumePathNameW", (PROC)NewGetVolumePathNameW, GetVolumePathNameWOrgFP);
    return ret;
}

BOOL WINAPI NewGetVolumePathNamesForVolumeNameW(
    LPCWSTR lpszVolumeName,
    LPWCH   lpszVolumePathNames,
    DWORD   cchBufferLength,
    PDWORD  lpcchReturnLength
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetVolumePathNamesForVolumeNameW");
    unhook_by_code("kernel32.dll", "GetVolumePathNamesForVolumeNameW", GetVolumePathNamesForVolumeNameWOrgFP);

    BOOL ret = GetVolumePathNamesForVolumeNameW(
        lpszVolumeName,
        lpszVolumePathNames,
        cchBufferLength,
        lpcchReturnLength
    );
    hook_by_code("kernel32.dll", "GetVolumePathNamesForVolumeNameW", (PROC)NewGetVolumePathNamesForVolumeNameW, GetVolumePathNamesForVolumeNameWOrgFP);
    return ret;
}

BOOL WINAPI NewGetVolumeNameForVolumeMountPointW(
    LPCWSTR lpszVolumeMountPoint,
    LPWSTR  lpszVolumeName,
    DWORD   cchBufferLength
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetVolumeNameForVolumeMountPointW");
    unhook_by_code("kernel32.dll", "GetVolumeNameForVolumeMountPointW", GetVolumeNameForVolumeMountPointWOrgFP);

    BOOL ret = GetVolumeNameForVolumeMountPointW(
        lpszVolumeMountPoint,
        lpszVolumeName,
        cchBufferLength
    );
    hook_by_code("kernel32.dll", "GetVolumeNameForVolumeMountPointW", (PROC)NewGetVolumeNameForVolumeMountPointW, GetVolumeNameForVolumeMountPointWOrgFP);
    return ret;
}

UINT WINAPI NewGetSystemWindowsDirectoryW(
    LPWSTR lpBuffer,
    UINT   uSize
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetSystemWindowsDirectoryW");
    unhook_by_code("kernel32.dll", "GetSystemWindowsDirectoryW", GetSystemWindowsDirectoryWOrgFP);

    BOOL ret = GetSystemWindowsDirectoryW(
        lpBuffer,
        uSize
    );
    hook_by_code("kernel32.dll", "GetSystemWindowsDirectoryW", (PROC)NewGetSystemWindowsDirectoryW, GetSystemWindowsDirectoryWOrgFP);
    return ret;
}

UINT WINAPI NewGetSystemDirectoryW(
    LPWSTR lpBuffer,
    UINT   uSize
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetSystemDirectoryW");
    unhook_by_code("kernel32.dll", "GetSystemDirectoryW", GetSystemDirectoryWOrgFP);

    BOOL ret = GetSystemDirectoryW(
        lpBuffer,
        uSize
    );
    hook_by_code("kernel32.dll", "GetSystemDirectoryW", (PROC)NewGetSystemDirectoryW, GetSystemDirectoryWOrgFP);
    return ret;
}

UINT WINAPI NewGetSystemDirectoryA(
    LPSTR lpBuffer,
    UINT  uSize
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetSystemDirectoryA");
    unhook_by_code("kernel32.dll", "GetSystemDirectoryA", GetSystemDirectoryAOrgFP);

    BOOL ret = GetSystemDirectoryA(
        lpBuffer,
        uSize
    );
    hook_by_code("kernel32.dll", "GetSystemDirectoryA", (PROC)NewGetSystemDirectoryA, GetSystemDirectoryAOrgFP);
    return ret;
}

DWORD WINAPI NewGetShortPathNameW(
    LPCWSTR lpszLongPath,
    LPWSTR  lpszShortPath,
    DWORD   cchBuffer
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetShortPathNameW");
    unhook_by_code("kernel32.dll", "GetShortPathNameW", GetShortPathNameWOrgFP);

    BOOL ret = GetShortPathNameW(
        lpszLongPath,
        lpszShortPath,
        cchBuffer
    );
    hook_by_code("kernel32.dll", "GetShortPathNameW", (PROC)NewGetShortPathNameW, GetShortPathNameWOrgFP);
    return ret;
}

DWORD WINAPI NewGetFileType(
    HANDLE hFile
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetFileType");
    unhook_by_code("kernel32.dll", "GetFileType", GetFileTypeOrgFP);

    BOOL ret = GetFileType(
        hFile
    );

    hook_by_code("kernel32.dll", "GetFileType", (PROC)NewGetFileType, GetFileTypeOrgFP);
    return ret;
}

BOOL WINAPI NewGetFileInformationByHandle(
    _In_ HANDLE hFile,
    _Out_ LPBY_HANDLE_FILE_INFORMATION lpFileInformation
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetFileInformationByHandle");
    unhook_by_code("kernel32.dll", "GetFileInformationByHandle", GetFileInformationByHandleOrgFP);

    BOOL ret = GetFileInformationByHandle(
        hFile,
        lpFileInformation);

    hook_by_code("kernel32.dll", "GetFileInformationByHandle", (PROC)NewGetFileInformationByHandle, GetFileInformationByHandleOrgFP);
    return ret;
}

BOOL WINAPI NewGetFileInformationByHandleEx(
    HANDLE                    hFile,
    FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
    LPVOID                    lpFileInformation,
    DWORD                     dwBufferSize
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetFileInformationByHandleEx");
    unhook_by_code("kernel32.dll", "GetFileInformationByHandleEx", GetFileInformationByHandleExOrgFP);

    BOOL ret = GetFileInformationByHandleEx(
        hFile,
        FileInformationClass,
        lpFileInformation,
        dwBufferSize);

    hook_by_code("kernel32.dll", "GetFileInformationByHandleEx", (PROC)NewGetFileInformationByHandleEx, GetFileInformationByHandleExOrgFP);
    return ret;
}

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

BOOL WINAPI NewDeleteFileW(
    _In_ LPCWSTR lpFileName
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"DeleteFileW");
    unhook_by_code("kernel32.dll", "DeleteFileW", DeleteFileOrgFPW);

    BOOL ret = DeleteFileW(lpFileName);

    hook_by_code("kernel32.dll", "DeleteFileW", (PROC)NewDeleteFileW, DeleteFileOrgFPW);
    return ret;
}

BOOL WINAPI NewDeleteFileA(
    _In_ LPCSTR lpFileName
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"DeleteFileA");
    unhook_by_code("kernel32.dll", "DeleteFileA", DeleteFileOrgFPA);

    BOOL ret = DeleteFileA(lpFileName);

    hook_by_code("kernel32.dll", "DeleteFileA", (PROC)NewDeleteFileA, DeleteFileOrgFPA);
    return ret;
}

BOOL WINAPI NewReadFile(
    _In_ HANDLE hFile,
    _Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToRead,
    _Out_opt_ LPDWORD lpNumberOfBytesRead,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"ReadFile");
    unhook_by_code("kernel32.dll", "ReadFile", ReadFileOrgFP);

    BOOL ret = ReadFile(hFile,
                        lpBuffer,
                        nNumberOfBytesToRead,
                        lpNumberOfBytesRead,
                        lpOverlapped);

    hook_by_code("kernel32.dll", "ReadFile", (PROC)NewReadFile, ReadFileOrgFP);
    return ret;
}

BOOL WINAPI NewWriteFile(
    _In_ HANDLE hFile,
    _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToWrite,
    _Out_opt_ LPDWORD lpNumberOfBytesWritten,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"WriteFile");
    unhook_by_code("kernel32.dll", "WriteFile", WriteFileOrgFP);

    BOOL ret = WriteFile(hFile,
                        lpBuffer,
                        nNumberOfBytesToWrite,
                        lpNumberOfBytesWritten,
                        lpOverlapped);

    hook_by_code("kernel32.dll", "WriteFile", (PROC)NewWriteFile, WriteFileOrgFP);
    return ret;
}

BOOL WINAPI NewCreateDirectoryW(
    _In_ LPCWSTR lpPathName,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"CreateDirectoryW");
    unhook_by_code("kernel32.dll", "CreateDirectoryW", CreateDirectoryOrgFPW);

    BOOL ret = CreateDirectoryW(lpPathName,
                                lpSecurityAttributes);

    hook_by_code("kernel32.dll", "CreateDirectoryW", (PROC)NewCreateDirectoryW, CreateDirectoryOrgFPW);
    return ret;
}

BOOL WINAPI NewCreateDirectoryA(
    _In_ LPCSTR lpPathName,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"CreateDirectoryA");
    unhook_by_code("kernel32.dll", "CreateDirectoryA", CreateDirectoryOrgFPA);

    BOOL ret = CreateDirectoryA(lpPathName,
                                lpSecurityAttributes);

    hook_by_code("kernel32.dll", "CreateDirectoryA", (PROC)NewCreateDirectoryA, CreateDirectoryOrgFPA);
    return ret;
}

BOOL WINAPI NewCopyFileW(
    _In_ LPCWSTR lpExistingFileName,
    _In_ LPCWSTR lpNewFileName,
    _In_ BOOL bFailIfExists
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"CopyFileW");
    unhook_by_code("kernel32.dll", "CopyFileW", CopyFileOrgFPW);

    BOOL ret = CopyFileW(lpExistingFileName,
                        lpNewFileName,
                        bFailIfExists);

    hook_by_code("kernel32.dll", "CopyFileW", (PROC)NewCopyFileW, CopyFileOrgFPW);
    return ret;
}

BOOL WINAPI NewCopyFileA(
    _In_ LPCSTR lpExistingFileName,
    _In_ LPCSTR lpNewFileName,
    _In_ BOOL bFailIfExists
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"CopyFileA");
    unhook_by_code("kernel32.dll", "CopyFileA", CopyFileOrgFPA);

    BOOL ret = CopyFileA(lpExistingFileName,
                        lpNewFileName,
                        bFailIfExists);

    hook_by_code("kernel32.dll", "CopyFileA", (PROC)NewCopyFileA, CopyFileOrgFPA);
    return ret;
}

DWORD WINAPI NewGetTempPathW(
    _In_ DWORD nBufferLength,
    _Out_writes_to_opt_(nBufferLength, return +1) LPWSTR lpBuffer
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetTempPathW");
    unhook_by_code("kernel32.dll", "GetTempPathW", GetTempPathOrgFPW);

    DWORD ret = GetTempPathW(nBufferLength,
                            lpBuffer);

    hook_by_code("kernel32.dll", "GetTempPathW", (PROC)NewGetTempPathW, GetTempPathOrgFPW);
    return ret;
}

DWORD WINAPI NewGetTempPathA(
    _In_ DWORD nBufferLength,
    _Out_writes_to_opt_(nBufferLength, return +1) LPSTR lpBuffer
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetTempPathA");
    unhook_by_code("kernel32.dll", "GetTempPathA", GetTempPathOrgFPA);

    DWORD ret = GetTempPathA(nBufferLength,
                            lpBuffer);

    hook_by_code("kernel32.dll", "GetTempPathA", (PROC)NewGetTempPathA, GetTempPathOrgFPA);
    return ret;
}

HANDLE WINAPI NewFindFirstFileW(
    _In_ LPCWSTR lpFileName,
    _Out_ LPWIN32_FIND_DATAW lpFindFileData
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"FindFirstFileW");
    unhook_by_code("kernel32.dll", "FindFirstFileW", FindFirstFileOrgFPW);

    HANDLE ret = FindFirstFileW(lpFileName,
                               lpFindFileData);

    hook_by_code("kernel32.dll", "FindFirstFileW", (PROC)NewFindFirstFileW, FindFirstFileOrgFPW);
    return ret;
}

HANDLE WINAPI NewFindFirstFileA(
    _In_ LPCSTR lpFileName,
    _Out_ LPWIN32_FIND_DATAA lpFindFileData
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"FindFirstFileA");
    unhook_by_code("kernel32.dll", "FindFirstFileA", FindFirstFileOrgFPA);

    HANDLE ret = FindFirstFileA(lpFileName,
                                lpFindFileData);

    hook_by_code("kernel32.dll", "FindFirstFileA", (PROC)NewFindFirstFileA, FindFirstFileOrgFPA);
    return ret;
}

DWORD WINAPI NewGetFileAttributesW(
    _In_ LPCWSTR lpFileName
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetFileAttributesW");
    unhook_by_code("kernel32.dll", "GetFileAttributesW", GetFileAttributesOrgFPW);

    DWORD ret = GetFileAttributesW(lpFileName);

    hook_by_code("kernel32.dll", "GetFileAttributesW", (PROC)NewGetFileAttributesW, GetFileAttributesOrgFPW);
    return ret;
}

DWORD WINAPI NewGetFileAttributesA(
    _In_ LPCSTR lpFileName
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetFileAttributesA");
    unhook_by_code("kernel32.dll", "GetFileAttributesA", GetFileAttributesOrgFPA);

    DWORD ret = GetFileAttributesA(lpFileName);

    hook_by_code("kernel32.dll", "GetFileAttributesA", (PROC)NewGetFileAttributesA, GetFileAttributesOrgFPA);
    return ret;
}

DWORD WINAPI NewGetFileSize(
    _In_ HANDLE hFile,
    _Out_opt_ LPDWORD lpFileSizeHigh
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetFileSize");
    unhook_by_code("kernel32.dll", "GetFileSize", GetFileSizeOrgFP);

    DWORD ret = GetFileSize(hFile,
                            lpFileSizeHigh);

    hook_by_code("kernel32.dll", "GetFileSize", (PROC)NewGetFileSize, GetFileSizeOrgFP);
    return ret;
}

BOOL WINAPI NewSetEndOfFile(
    _In_ HANDLE hFile
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"SetEndOfFile");
    unhook_by_code("kernel32.dll", "SetEndOfFile", SetEndOfFileOrgFP);

    BOOL ret = SetEndOfFile(hFile);

    hook_by_code("kernel32.dll", "SetEndOfFile", (PROC)NewSetEndOfFile, SetEndOfFileOrgFP);
    return ret;
}

DWORD WINAPI NewSetFilePointer(
    _In_ HANDLE hFile,
    _In_ LONG lDistanceToMove,
    _Inout_opt_ PLONG lpDistanceToMoveHigh,
    _In_ DWORD dwMoveMethod
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"SetFilePointer");
    unhook_by_code("kernel32.dll", "SetFilePointer", SetFilePointerOrgFP);

    DWORD ret = SetFilePointer(hFile,
                                lDistanceToMove,
                                lpDistanceToMoveHigh,
                                dwMoveMethod);

    hook_by_code("kernel32.dll", "SetFilePointer", (PROC)NewSetFilePointer, SetFilePointerOrgFP);
    return ret;
}

HANDLE WINAPI NewFindFirstFileExW(
    _In_ LPCWSTR lpFileName,
    _In_ FINDEX_INFO_LEVELS fInfoLevelId,
    _Out_writes_bytes_(sizeof(WIN32_FIND_DATAW)) LPVOID lpFindFileData,
    _In_ FINDEX_SEARCH_OPS fSearchOp,
    _Reserved_ LPVOID lpSearchFilter,
    _In_ DWORD dwAdditionalFlags
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"FindFirstFileExW");
    unhook_by_code("kernel32.dll", "FindFirstFileExW", FindFirstFileExWOrgFPW);

    HANDLE ret = FindFirstFileExW(lpFileName,
                                fInfoLevelId,
                                lpFindFileData,
                                fSearchOp,
                                lpSearchFilter,
                                dwAdditionalFlags);

    hook_by_code("kernel32.dll", "FindFirstFileExW", (PROC)NewFindFirstFileExW, FindFirstFileExWOrgFPW);
    return ret;
}