#pragma once
BYTE CryptAcquireContextWOrgFPW[5];
BYTE HeapCreateOrgFP[5];
BYTE GetSystemTimeOrgFP[5];
BYTE CryptGenRandomOrgFP[5];
BYTE DeviceIoControlOrgFP[5];
BYTE VirtualProtectExOrgFP[5];
BYTE GlobalMemoryStatusOrgFP[5];
BYTE GlobalMemoryStatusExOrgFP[5];

BOOL WINAPI NewCryptAcquireContextW(
    _Out_       HCRYPTPROV* phProv,
    _In_opt_    LPCWSTR    szContainer,
    _In_opt_    LPCWSTR    szProvider,
    _In_        DWORD       dwProvType,
    _In_        DWORD       dwFlags
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"CryptAcquireContextW");
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
    DebugLog("%d %ls", GetCurrentProcessId(), L"VirtualProtectEx");
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
    DebugLog("%d %ls", GetCurrentProcessId(), L"GlobalMemoryStatusEx");
    unhook_by_code("Kernel32.dll", "GlobalMemoryStatusEx", GlobalMemoryStatusExOrgFP);

    GlobalMemoryStatusEx(lpBuffer);
    hook_by_code("Kernel32.dll", "GlobalMemoryStatusEx", (PROC)NewGlobalMemoryStatusEx, GlobalMemoryStatusExOrgFP);
}