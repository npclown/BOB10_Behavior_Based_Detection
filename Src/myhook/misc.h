#pragma once
//import major Libs
#include "stdafx.h"

/*
CopyRight 2021 all served by LeeJoonSung
	writen at 08.14.2021
		[+] https://github.com/miho030

BoB Behavior-Based-Detector (real time malwarebyte dectetion solution)

# purpose of this header file is for,
	1. hook windows API which are malwares call primarily to detect malwares bihavior
	2. This code determines the behavior of all processes that invoke the API and allows the
		use of arbitrarily configured detection logic APIs.

# This APIs safety will be guaranteed(supported),

	>>> GetTimeZoneInformation
	>>> GetComputerNameA,W
	>>> GetDiskFreeSpaceA,W

# rule policy (parameter filtes, BCS(Behavioral Combination Scenario)detection)
	GetTimeZoneInformation
		>>> Handler : None
	GetComputerNameA,W
		>>> Handler : None
	GetDiskFreeSpaceA,W
		>>> Handler : None

*/

//dfinition some BYTE variable for opcode for hooking functional.
BYTE OrgGTZ[5]; //GetTimeZoneInformation
BYTE OrgGCA[5]; //NewGetComputerNameA
BYTE OrgGCW[5]; //NewGetComputerNameW
BYTE OrgGDA[5]; //GetDiskFreeSpaceA
BYTE OrgGDW[5]; //GetDiskFreeSpaceW
BYTE WriteConsoleAOrgFPA[5];
BYTE WriteConsoleWOrgFPW[5];

//Definition structure of GetTimeZoneInformation
DWORD WINAPI NewGetTimeZoneInformation(
	_Out_ LPTIME_ZONE_INFORMATION lpTimeZoneInformation
) {
	DebugLog("%d %ls", GetCurrentProcessId(), L"GetTimeZoneInformation");
	unhook_by_code("kernel32.dll", "GetTimeZoneInformation", OrgGTZ);
	DWORD GTZ_handle = GetTimeZoneInformation(lpTimeZoneInformation);

	hook_by_code("kernel32.dll", "GetTimeZoneInformation", (PROC)NewGetTimeZoneInformation, OrgGTZ);
	return GTZ_handle;
}

//Definition structure of GetComputerNameA,W
BOOL WINAPI NewGetComputerNameA(
	_Out_writes_to_opt_(*nSize, *nSize + 1) LPSTR lpBuffer,
	_Inout_ LPDWORD nSize
) {
	DebugLog("%d %ls", GetCurrentProcessId(), L"GetComputerName");
	unhook_by_code("kernel32.dll", "GetComputerNameA", OrgGCA);

	BOOL GCA_handle = GetComputerNameA(lpBuffer, nSize);

	hook_by_code("kernel32.dll", "GetComputerNameA", (PROC)NewGetComputerNameA, OrgGCA);
	return GCA_handle;
}
BOOL WINAPI NewGetComputerNameW(
	_Out_writes_to_opt_(*nSize, *nSize + 1) LPWSTR lpBuffer,
	_Inout_ LPDWORD nSize
) {
	DebugLog("%d %ls", GetCurrentProcessId(), L"GetComputerName");
	unhook_by_code("kernel32.dll", "GetComputerNameW", OrgGCW);

	BOOL GCW_handle = GetComputerNameW(lpBuffer, nSize);

	hook_by_code("kernel32.dll", "GetComputerNameW", (PROC)NewGetComputerNameW, OrgGCW);
	return GCW_handle;
}

//Definition structure of GetDiskFreeSpaceA,W
//In fact, this API belonged to a "file" OwO;; -> referenced by fileapi.h;;;;
BOOL WINAPI NewGetDiskFreeSpaceA(
	_In_opt_ LPCSTR lpRootPathName,
	_Out_opt_ LPDWORD lpSectorsPerCluster,
	_Out_opt_ LPDWORD lpBytesPerSector,
	_Out_opt_ LPDWORD lpNumberOfFreeClusters,
	_Out_opt_ LPDWORD lpTotalNumberOfClusters
) {
	DebugLog("%d %ls", GetCurrentProcessId(), L"GetDiskFreeSpace");
	unhook_by_code("kernel32.dll", "GetDiskFreeSpaceA", OrgGDA);


	BOOL GDA_handle = GetDiskFreeSpaceA(
		lpRootPathName,
		lpSectorsPerCluster,
		lpBytesPerSector,
		lpNumberOfFreeClusters,
		lpTotalNumberOfClusters
	); 

	hook_by_code("kernel32.dll", "GetDiskFreeSpaceA", (PROC)NewGetDiskFreeSpaceA, OrgGDA);

	return GDA_handle;
}
BOOL WINAPI NewGetDiskFreeSpaceW(
	_In_opt_ LPCWSTR lpRootPathName,
	_Out_opt_ LPDWORD lpSectorsPerCluster,
	_Out_opt_ LPDWORD lpBytesPerSector,
	_Out_opt_ LPDWORD lpNumberOfFreeClusters,
	_Out_opt_ LPDWORD lpTotalNumberOfClusters
) {
	DebugLog("%d %ls", GetCurrentProcessId(), L"GetDiskFreeSpace");
	unhook_by_code("kernel32.dll", "GetDiskFreeSpaceW", OrgGDW);

	BOOL GDW_handle = GetDiskFreeSpaceW(
		lpRootPathName,
		lpSectorsPerCluster,
		lpBytesPerSector,
		lpNumberOfFreeClusters,
		lpTotalNumberOfClusters
	);

	hook_by_code("kernel32.dll", "GetDiskFreeSpaceW", (PROC)NewGetDiskFreeSpaceW, OrgGDW);

	return GDW_handle;
}

BOOL WINAPI NewWriteConsoleA(
	_In_ HANDLE hConsoleOutput,
	_In_reads_(nNumberOfCharsToWrite) CONST VOID* lpBuffer,
	_In_ DWORD nNumberOfCharsToWrite,
	_Out_opt_ LPDWORD lpNumberOfCharsWritten,
	_Reserved_ LPVOID lpReserved
) {
	DebugLog("%d %ls", GetCurrentProcessId(), L"WriteConsole");
	unhook_by_code("kernel32.dll", "WriteConsoleA", WriteConsoleAOrgFPA);

	BOOL ret = WriteConsoleA(hConsoleOutput,
							lpBuffer,
							nNumberOfCharsToWrite,
							lpNumberOfCharsWritten,
							lpReserved);

	hook_by_code("kernel32.dll", "WriteConsoleA", (PROC)NewWriteConsoleA, WriteConsoleAOrgFPA);

	return ret;
}

BOOL WINAPI NewWriteConsoleW(
	_In_ HANDLE hConsoleOutput,
	_In_reads_(nNumberOfCharsToWrite) CONST VOID* lpBuffer,
	_In_ DWORD nNumberOfCharsToWrite,
	_Out_opt_ LPDWORD lpNumberOfCharsWritten,
	_Reserved_ LPVOID lpReserved
) {
	DebugLog("%d %ls", GetCurrentProcessId(), L"WriteConsole");
	unhook_by_code("kernel32.dll", "WriteConsoleW", WriteConsoleWOrgFPW);

	BOOL ret = WriteConsoleW(hConsoleOutput,
							lpBuffer,
							nNumberOfCharsToWrite,
							lpNumberOfCharsWritten,
							lpReserved);

	hook_by_code("kernel32.dll", "WriteConsoleW", (PROC)NewWriteConsoleW, WriteConsoleWOrgFPW);

	return ret;
}