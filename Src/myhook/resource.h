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

	>>> FindResourceA,W
	>>> LoadResource
	>>> SizeofResource

# rule policy (parameter filtes, BCS(Behavioral Combination Scenario)detection)
	FindResourceA,W
		>>> handler(FRA_handle, FRW_handle)
	LoadResource
		>>> handler(LP_handle)
	SizeofResource
		>>> Handler : None

*/

//dfinition some BYTE variable for opcode for hooking functional.
BYTE OrgFRA[5]; //FindResourceA
BYTE OrgFRW[5]; //FindResourceW
BYTE OrgLR[5]; //LoadResource
BYTE OrgSR[5]; //SizeofResource
BYTE FindResourceExAOrgFPA[5];
BYTE FindResourceExWOrgFPW[5];

//Definition structure of FindResourceA,W
HANDLE WINAPI NewFindResourceA( //FindResourceA -> winbase.h
	_In_opt_ HMODULE hModule,
	_In_     LPCSTR lpName,
	_In_     LPCSTR lpType
) {
	DebugLog("%d %ls", GetCurrentProcessId(), L"FindResource");
	unhook_by_code("kernel32.dll", "FindResourceA", OrgFRA);

	HANDLE FRA_handle = FindResourceA(hModule, lpName, lpType);

	hook_by_code("kernel32.dll", "FindResourceA", (PROC)NewFindResourceA, OrgFRA);

	return FRA_handle;
}
HANDLE WINAPI NewFindResourceW( //FindResourceW -> libloaderapi.h
	_In_opt_ HMODULE hModule,
	_In_ LPCWSTR lpName,
	_In_ LPCWSTR lpType
) {
	DebugLog("%d %ls", GetCurrentProcessId(), L"FindResource");
	unhook_by_code("kernel32.dll", "FindResourceW", OrgFRW);

	HANDLE FRW_handle = FindResourceW(hModule, lpName, lpType);
	
	hook_by_code("kernel32.dll", "FindResourceW", (PROC)NewFindResourceW, OrgFRW);

	return FRW_handle;
}

//Definition structure of LoadResource
HANDLE WINAPI NewLoadResource(
	_In_opt_ HMODULE hModule,
	_In_ HRSRC hResInfo
) {
	DebugLog("%d %ls", GetCurrentProcessId(), L"LoadResource");
	unhook_by_code("kernel32.dll", "LoadResource", OrgLR);

	HANDLE LP_handle = LoadResource(hModule, hResInfo);
	hook_by_code("kernel32.dll", "LoadResource", (PROC)NewLoadResource, OrgLR);

	return LP_handle;
}

//Definition structure of SizeofResource
DWORD WINAPI NewSizeofResource(
	_In_opt_ HMODULE hModule,
	_In_ HRSRC hResInfo
) {
	DebugLog("%d %ls", GetCurrentProcessId(), L"SizeofResource");
	unhook_by_code("kernel32.dll", "SizeofResource", OrgSR);

	//cannot make handle cuz this api type is DWORD!!!!
	DWORD SR_handle = SizeofResource(hModule, hResInfo);

	hook_by_code("kernel32.dll", "SizeofResource", (PROC)NewSizeofResource, OrgSR);
	return SR_handle;
}

HRSRC WINAPI NewFindResourceExA(
	_In_opt_ HMODULE hModule,
	_In_     LPCSTR lpType,
	_In_     LPCSTR lpName,
	_In_     WORD    wLanguage
) {
	DebugLog("%d %ls", GetCurrentProcessId(), L"FindResource");
	unhook_by_code("kernel32.dll", "FindResourceExA", FindResourceExAOrgFPA);

	HRSRC ret = FindResourceExA(hModule, 
								lpType,
								lpName,
								wLanguage);

	hook_by_code("kernel32.dll", "FindResourceExA", (PROC)NewFindResourceExA, FindResourceExAOrgFPA);
	return ret;
}

HRSRC WINAPI NewFindResourceExW(
	_In_opt_ HMODULE hModule,
	_In_ LPCWSTR lpType,
	_In_ LPCWSTR lpName,
	_In_ WORD wLanguage
) {
	DebugLog("%d %ls", GetCurrentProcessId(), L"FindResource");
	unhook_by_code("kernel32.dll", "FindResourceExW", FindResourceExWOrgFPW);

	HRSRC ret = FindResourceExW(hModule,
								lpType,
								lpName,
								wLanguage);

	hook_by_code("kernel32.dll", "FindResourceExW", (PROC)NewFindResourceExW, FindResourceExWOrgFPW);
	return ret;
}
