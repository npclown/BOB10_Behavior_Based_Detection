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

	>>> GetTickCount
	>>> GetLocalTime
	>>> GetSystemTimeAsFileTime
	>>> Sleep

# rule policy (parameter filtes, BCS(Behavioral Combination Scenario)detection)
	GetTickCount
		>>> handler : None.
	GetLocalTime
		>>> handler : None.
	GetSystemTimeAsFileTime
		>>> handler : None.
	Sleep
		>>> handler : None.

*/

// bc
BYTE OrgGTC[5];
BYTE OrgGLT[5];
BYTE OrgGSTFT[5];
BYTE OrgSleep[5];

//Definition structure of GetTickCount
DWORD WINAPI NewGetTickCount(VOID) {
	DebugLog("%d %ls", GetCurrentProcessId(), "GetTickCount");
	unhook_by_code("kernel32.dll", "GetTickCount", OrgGTC);
	
	DWORD GTC_handle = GetTickCount();

	hook_by_code("kernel32.dll", "GetTickCount", (PROC)NewGetTickCount, OrgGTC);
	return GTC_handle;
}

//Definition structure of GetLocalTime (TYPE - VOID)
VOID WINAPI NewGetLocalTime(_Out_ LPSYSTEMTIME lpSystemTime) {
	DebugLog("%d %ls", GetCurrentProcessId(), "GetLocalTime");
	unhook_by_code("kernel32.dll", "GetLocalTime", OrgGLT);
	GetLocalTime(lpSystemTime);
	hook_by_code("kernel32.dll", "GetLocalTime", (PROC)NewGetLocalTime, OrgGLT);
}

//Definition structure of GetSystemTimeAsFileTime (TYPE - VOID)
VOID WINAPI NewGetSystemTimeAsFileTime(_Out_ LPFILETIME lpSystemTimeAsFileTime) {
	DebugLog("%d %ls", GetCurrentProcessId(), "GetSystemTimeAsFileTime");
	unhook_by_code("kernel32.dll", "GetSystemTimeAsFileTime", OrgGSTFT);

	GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);

	hook_by_code("kernel32.dll", "GetSystemTimeAsFileTime", (PROC)NewGetSystemTimeAsFileTime, OrgGSTFT);
}

//Definition structure of Sleep
VOID WINAPI NewSleep(
	_In_ DWORD dwMilliseconds
) { 
	DebugLog("%d %ls", GetCurrentProcessId(), "Sleep");
	unhook_by_code("kernel32.dll", "Sleep", OrgSleep);

	Sleep(dwMilliseconds);

	hook_by_code("kernel32.dll", "Sleep", (PROC)NewSleep, OrgSleep);
}