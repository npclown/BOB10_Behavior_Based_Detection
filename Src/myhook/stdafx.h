#pragma once
#include <stdio.h>
#include <Windows.h>
#include <string>
#include "tchar.h"

#define DLLNAME L"myhook.dll"

DWORD WINAPI hook_by_code(LPCSTR szDllName, LPCSTR apiName, LPVOID newApiName, const char* orgByte);
DWORD WINAPI unhook_by_code(LPCSTR szDllName, LPCSTR apiName, LPVOID newApiName, const char* orgByte);
BOOL InjectDll(HANDLE hProcess, LPCTSTR szDllName);
void DebugLog(const char* format, ...);