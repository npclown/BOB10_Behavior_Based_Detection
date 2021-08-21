#pragma once
BYTE CryptAcquireContextWOrgFPW[5];
BYTE HeapCreateOrgFP[5];
BYTE GetSystemTimeOrgFP[5];
BYTE CryptGenRandomOrgFP[5];
BYTE DeviceIoControlOrgFP[5];
BYTE VirtualProtectExOrgFP[5];
BYTE GlobalMemoryStatusOrgFP[5];
BYTE GlobalMemoryStatusExOrgFP[5];
//BYTE UrlCanonicalizeWOrgFPW[5];
//BYTE StrCmpNICWOrgFPW[5];
BYTE SHGetFolderPathWOrgFPW[5];
//BYTE GetFileVersionInfoSizeWOrgFPW[5];
BYTE LsaOpenPolicyOrgFP[5];
//BYTE GetFileVersionInfoWOrgFPW[5];

BOOL WINAPI NewCryptAcquireContextW(
    _Out_       HCRYPTPROV* phProv,
    _In_opt_    LPCWSTR    szContainer,
    _In_opt_    LPCWSTR    szProvider,
    _In_        DWORD       dwProvType,
    _In_        DWORD       dwFlags
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"CryptAcquireContext");
    unhook_by_code("Advapi32.dll", "CryptAcquireContextW", CryptAcquireContextWOrgFPW);

    BOOL ret = CryptAcquireContextW(phProv,
                                    szContainer,
                                    szProvider,
                                    dwProvType,
                                    dwFlags);
    hook_by_code("Advapi32.dll", "CryptAcquireContextW", (PROC)NewCryptAcquireContextW, CryptAcquireContextWOrgFPW);
    return ret;
}

HANDLE WINAPI NewHeapCreate(
    _In_ DWORD flOptions,
    _In_ SIZE_T dwInitialSize,
    _In_ SIZE_T dwMaximumSize
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"HeapCreate");
    unhook_by_code("Kernel32.dll", "HeapCreate", HeapCreateOrgFP);

    HANDLE ret = HeapCreate(flOptions,
                            dwInitialSize,
                            dwMaximumSize);
    hook_by_code("Kernel32.dll", "HeapCreate", (PROC)NewHeapCreate, HeapCreateOrgFP);
    return ret;
}

VOID WINAPI NewGetSystemTime(
    _Out_ LPSYSTEMTIME lpSystemTime
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetSystemTime");
    unhook_by_code("Kernel32.dll", "GetSystemTime", GetSystemTimeOrgFP);

    GetSystemTime(lpSystemTime);
    hook_by_code("Kernel32.dll", "GetSystemTime", (PROC)NewGetSystemTime, GetSystemTimeOrgFP);
}

BOOL WINAPI NewCryptGenRandom(
    _In_                    HCRYPTPROV  hProv,
    _In_                    DWORD   dwLen,
    _Inout_updates_bytes_(dwLen)   BYTE* pbBuffer
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"CryptGenRandom");
    unhook_by_code("Advapi32.dll", "CryptGenRandom", CryptGenRandomOrgFP);

    BOOL ret = CryptGenRandom(hProv,
                            dwLen,
                            pbBuffer);
    hook_by_code("Advapi32.dll", "CryptGenRandom", (PROC)NewCryptGenRandom, CryptGenRandomOrgFP);
    return ret;
}

BOOL WINAPI NewDeviceIoControl(
    _In_ HANDLE hDevice,
    _In_ DWORD dwIoControlCode,
    _In_reads_bytes_opt_(nInBufferSize) LPVOID lpInBuffer,
    _In_ DWORD nInBufferSize,
    _Out_writes_bytes_to_opt_(nOutBufferSize, *lpBytesReturned) LPVOID lpOutBuffer,
    _In_ DWORD nOutBufferSize,
    _Out_opt_ LPDWORD lpBytesReturned,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"DeviceIoControl");
    unhook_by_code("Kernel32.dll", "DeviceIoControl", DeviceIoControlOrgFP);

    BOOL ret = DeviceIoControl(hDevice,
                    dwIoControlCode,
                    lpInBuffer,
                    nInBufferSize,
                    lpOutBuffer,
                    nOutBufferSize,
                    lpBytesReturned,
                    lpOverlapped);
    hook_by_code("Kernel32.dll", "DeviceIoControl", (PROC)NewDeviceIoControl, DeviceIoControlOrgFP);
    return ret;
}

BOOL WINAPI NewVirtualProtectEx(
    _In_ HANDLE hProcess,
    _In_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flNewProtect,
    _Out_ PDWORD lpflOldProtect
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"VirtualProtect");
    unhook_by_code("Kernel32.dll", "VirtualProtectEx", VirtualProtectExOrgFP);

    BOOL ret = VirtualProtectEx(hProcess,
                                lpAddress,
                                dwSize,
                                flNewProtect,
                                lpflOldProtect);
    hook_by_code("Kernel32.dll", "VirtualProtectEx", (PROC)NewVirtualProtectEx, VirtualProtectExOrgFP);
    return ret;
}

VOID WINAPI NewGlobalMemoryStatus(
    _Out_ LPMEMORYSTATUS lpBuffer
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GlobalMemoryStatus");
    unhook_by_code("Kernel32.dll", "GlobalMemoryStatus", GlobalMemoryStatusOrgFP);

    GlobalMemoryStatus(lpBuffer);
    hook_by_code("Kernel32.dll", "GlobalMemoryStatus", (PROC)NewGlobalMemoryStatus, GlobalMemoryStatusOrgFP);
}

VOID WINAPI NewGlobalMemoryStatusEx(
    _Out_ LPMEMORYSTATUSEX lpBuffer
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"GlobalMemoryStatus");
    unhook_by_code("Kernel32.dll", "GlobalMemoryStatusEx", GlobalMemoryStatusExOrgFP);

    GlobalMemoryStatusEx(lpBuffer);
    hook_by_code("Kernel32.dll", "GlobalMemoryStatusEx", (PROC)NewGlobalMemoryStatusEx, GlobalMemoryStatusExOrgFP);
}

//HRESULT NewUrlCanonicalizeW(
//    _In_ PCWSTR pszUrl, _Out_writes_to_(*pcchCanonicalized, *pcchCanonicalized) PWSTR pszCanonicalized, _Inout_ DWORD* pcchCanonicalized, DWORD dwFlags
//) {
//    DebugLog("%d %ls", GetCurrentProcessId(), L"UrlCanonicalizeW");
//    unhook_by_code("Shlwapi.dll", "UrlCanonicalizeW", UrlCanonicalizeWOrgFPW);
//
//    HRESULT ret = UrlCanonicalizeW(pszUrl, pszCanonicalized, pcchCanonicalized, dwFlags);
//    hook_by_code("Shlwapi.dll", "UrlCanonicalizeW", (PROC)NewUrlCanonicalizeW, UrlCanonicalizeWOrgFPW);
//    return ret;
//}

//int NewStrCmpNICW(
//    _In_ LPCWSTR pszStr1, _In_ LPCWSTR pszStr2, int nChar
//) {
//    DebugLog("%d %ls", GetCurrentProcessId(), L"StrCmpNICW");
//    unhook_by_code("Shlwapi.dll", "StrCmpNICW", StrCmpNICWOrgFPW);
//
//    int ret = StrCmpNICW(pszStr1, pszStr2, nChar);
//    hook_by_code("Shlwapi.dll", "StrCmpNICW", (PROC)NewUrlCanonicalizeW, StrCmpNICWOrgFPW);
//    return ret;
//}

HRESULT NewSHGetFolderPathW(
    _Reserved_ HWND hwnd, _In_ int csidl, _In_opt_ HANDLE hToken, _In_ DWORD dwFlags, _Out_writes_(MAX_PATH) LPWSTR pszPath
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"SHGetFolderPath");
    unhook_by_code("Shell32.dll", "SHGetFolderPathW", SHGetFolderPathWOrgFPW);

    HRESULT ret = SHGetFolderPathW(hwnd, csidl, hToken, dwFlags, pszPath);
    hook_by_code("Shell32.dll", "SHGetFolderPathW", (PROC)NewSHGetFolderPathW, SHGetFolderPathWOrgFPW);
    return ret;
}

//DWORD APIENTRY NewGetFileVersionInfoSizeW(
//    _In_        LPCWSTR lptstrFilename, /* Filename of version stamped file */
//    _Out_opt_ LPDWORD lpdwHandle       /* Information for use by GetFileVersionInfo */
//) {
//    DebugLog("%d %ls", GetCurrentProcessId(), L"GetFileVersionInfoSizeW");
//    unhook_by_code("Api-ms-win-core-version-l1-1-0.dll", "GetFileVersionInfoSizeW", GetFileVersionInfoSizeWOrgFPW);
//
//    DWORD ret = GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle);
//    hook_by_code("Api-ms-win-core-version-l1-1-0.dll", "GetFileVersionInfoSizeW", (PROC)NewGetFileVersionInfoSizeW, GetFileVersionInfoSizeWOrgFPW);
//    return ret;
//}

NTSTATUS NTAPI NewLsaOpenPolicy(
    _In_opt_ PLSA_UNICODE_STRING SystemName,
    _In_ PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PLSA_HANDLE PolicyHandle
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"LsaOpenPolicy");
    unhook_by_code("Advapi32.dll", "LsaOpenPolicy", LsaOpenPolicyOrgFP);

    DWORD ret = LsaOpenPolicy(SystemName, ObjectAttributes, DesiredAccess, PolicyHandle);
    hook_by_code("Advapi32.dll", "LsaOpenPolicy", (PROC)NewLsaOpenPolicy, LsaOpenPolicyOrgFP);
    return ret;
}

//BOOL APIENTRY NewGetFileVersionInfoW(
//    _In_                LPCWSTR lptstrFilename, /* Filename of version stamped file */
//    _Reserved_          DWORD dwHandle,          /* Information from GetFileVersionSize */
//    _In_                DWORD dwLen,             /* Length of buffer for info */
//    _Out_writes_bytes_(dwLen) LPVOID lpData            /* Buffer to place the data structure */
//) {
//    DebugLog("%d %ls", GetCurrentProcessId(), L"GetFileVersionInfoW");
//    unhook_by_code("Api-ms-win-core-version-l1-1-0.dll", "GetFileVersionInfoW", GetFileVersionInfoWOrgFPW);
//
//    DWORD ret = GetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData);
//    hook_by_code("Api-ms-win-core-version-l1-1-0.dll", "GetFileVersionInfoW", (PROC)NewGetFileVersionInfoW, GetFileVersionInfoWOrgFPW);
//    return ret;
//}