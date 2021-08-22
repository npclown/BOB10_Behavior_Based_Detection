#pragma once
BYTE RegOpenKeyExAOrgFPA[5];
BYTE RegOpenKeyExWOrgFPW[5];
BYTE RegQueryValueExAOrgFPA[5];
BYTE RegQueryInfoKeyWOrgFPW[5];
BYTE RegCloseKeyOrgFP[5];
BYTE RegQueryValueExWOrgFPW[5];
BYTE RegCreateKeyExWOrgFPW[5];
BYTE RegEnumKeyExWOrgFPW[5];
BYTE RegEnumValueWOrgFPW[5];

LSTATUS APIENTRY NewRegOpenKeyExA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"RegOpenKey");
    unhook_by_code("Advapi32.dll", "RegOpenKeyExA", RegOpenKeyExAOrgFPA);

    LSTATUS ret = RegOpenKeyExA(hKey,
                                lpSubKey,
                                ulOptions,
                                samDesired,
                                phkResult);
    hook_by_code("Advapi32.dll", "RegOpenKeyExA", (PROC)NewRegOpenKeyExA, RegOpenKeyExAOrgFPA);
    return ret;
}

LSTATUS APIENTRY NewRegOpenKeyExW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"RegOpenKey");
    unhook_by_code("Advapi32.dll", "RegOpenKeyExW", RegOpenKeyExWOrgFPW);

    LSTATUS ret = RegOpenKeyExW(hKey,
                                lpSubKey,
                                ulOptions,
                                samDesired,
                                phkResult);
    hook_by_code("Advapi32.dll", "RegOpenKeyExW", (PROC)NewRegOpenKeyExW, RegOpenKeyExWOrgFPW);
    return ret;
}

LSTATUS APIENTRY NewRegQueryValueExA(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"RegQueryValue");
    unhook_by_code("Advapi32.dll", "RegQueryValueExA", RegQueryValueExAOrgFPA);

    LSTATUS ret = RegQueryValueExA(hKey,
                                    lpValueName,
                                    lpReserved,
                                    lpType,
                                    lpData,
                                    lpcbData);
    hook_by_code("Advapi32.dll", "RegQueryValueExA", (PROC)NewRegQueryValueExA, RegQueryValueExAOrgFPA);
    return ret;
}

LSTATUS APIENTRY NewRegQueryInfoKeyW(
    _In_ HKEY hKey,
    _Out_writes_to_opt_(*lpcchClass, *lpcchClass + 1) LPWSTR lpClass,
    _Inout_opt_ LPDWORD lpcchClass,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpcSubKeys,
    _Out_opt_ LPDWORD lpcbMaxSubKeyLen,
    _Out_opt_ LPDWORD lpcbMaxClassLen,
    _Out_opt_ LPDWORD lpcValues,
    _Out_opt_ LPDWORD lpcbMaxValueNameLen,
    _Out_opt_ LPDWORD lpcbMaxValueLen,
    _Out_opt_ LPDWORD lpcbSecurityDescriptor,
    _Out_opt_ PFILETIME lpftLastWriteTime
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"RegQueryInfoKey");
    unhook_by_code("Advapi32.dll", "RegQueryInfoKeyW", RegQueryInfoKeyWOrgFPW);

    LSTATUS ret = RegQueryInfoKeyW(hKey,
                                    lpClass,
                                    lpcchClass,
                                    lpReserved,
                                    lpcSubKeys,
                                    lpcbMaxSubKeyLen,
                                    lpcbMaxClassLen,
                                    lpcValues,
                                    lpcbMaxValueNameLen,
                                    lpcbMaxValueLen,
                                    lpcbSecurityDescriptor,
                                    lpftLastWriteTime
                                );
    hook_by_code("Advapi32.dll", "RegQueryInfoKeyW", (PROC)NewRegQueryInfoKeyW, RegQueryInfoKeyWOrgFPW);
    return ret;
}

LSTATUS APIENTRY NewRegCloseKey(
    _In_ HKEY hKey
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"RegCloseKey");
    unhook_by_code("Advapi32.dll", "RegCloseKey", RegCloseKeyOrgFP);

    LSTATUS ret = RegCloseKey(hKey);
    hook_by_code("Advapi32.dll", "RegCloseKey", (PROC)NewRegCloseKey, RegCloseKeyOrgFP);
    return ret;
}

LSTATUS APIENTRY NewRegQueryValueExW(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"RegQueryValue");
    unhook_by_code("Advapi32.dll", "RegQueryValueExW", RegQueryValueExWOrgFPW);

    LSTATUS ret = RegQueryValueExW(hKey,
                                    lpValueName,
                                    lpReserved,
                                    lpType,
                                    lpData,
                                    lpcbData);
    hook_by_code("Advapi32.dll", "RegQueryValueExW", (PROC)NewRegQueryValueExW, RegQueryValueExWOrgFPW);
    return ret;
}

LSTATUS APIENTRY NewRegCreateKeyExW(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _Reserved_ DWORD Reserved,
    _In_opt_ LPWSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_opt_ LPDWORD lpdwDisposition
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"RegCreateKey");
    unhook_by_code("Advapi32.dll", "RegCreateKeyExW", RegCreateKeyExWOrgFPW);

    LSTATUS ret = RegCreateKeyExW(hKey,
                                lpSubKey,
                                Reserved,
                                lpClass,
                                dwOptions,
                                samDesired,
                                lpSecurityAttributes,
                                phkResult,
                                lpdwDisposition);
    hook_by_code("Advapi32.dll", "RegCreateKeyExW", (PROC)NewRegCreateKeyExW, RegCreateKeyExWOrgFPW);
    return ret;
}

LSTATUS APIENTRY NewRegEnumKeyExW(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchName, *lpcchName + 1) LPWSTR lpName,
    _Inout_ LPDWORD lpcchName,
    _Reserved_ LPDWORD lpReserved,
    _Out_writes_to_opt_(*lpcchClass, *lpcchClass + 1) LPWSTR lpClass,
    _Inout_opt_ LPDWORD lpcchClass,
    _Out_opt_ PFILETIME lpftLastWriteTime
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"RegEnumKey");
    unhook_by_code("Advapi32.dll", "RegEnumKeyExW", RegEnumKeyExWOrgFPW);

    LSTATUS ret = RegEnumKeyExW(hKey,
                                dwIndex,
                                lpName,
                                lpcchName,
                                lpReserved,
                                lpClass,
                                lpcchClass,
                                lpftLastWriteTime);
    hook_by_code("Advapi32.dll", "RegEnumKeyExW", (PROC)NewRegEnumKeyExW, RegEnumKeyExWOrgFPW);
    return ret;
}

LSTATUS APIENTRY NewRegEnumValueW(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchValueName, *lpcchValueName + 1) LPWSTR lpValueName,
    _Inout_ LPDWORD lpcchValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _Inout_opt_ LPDWORD lpcbData
) {
    DebugLog("%d %ls", GetCurrentProcessId(), L"RegEnumValue");
    unhook_by_code("Advapi32.dll", "RegEnumValueW", RegEnumValueWOrgFPW);

    LSTATUS ret = RegEnumValueW(hKey,
                                dwIndex,
                                lpValueName,
                                lpcchValueName,
                                lpReserved,
                                lpType,
                                lpData,
                                lpcbData);
    hook_by_code("Advapi32.dll", "RegEnumValueW", (PROC)NewRegEnumValueW, RegEnumValueWOrgFPW);
    return ret;
}