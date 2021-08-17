#include "stdafx.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DebugLog("MyHook DLL_PROCESS_ATTACH\n");
        hook_by_code("kernel32.dll", "CreateFileW", (PROC)NewCreateFileW, CreateFileOrgFPW);
        hook_by_code("kernel32.dll", "CreateFileA", (PROC)NewCreateFileA, CreateFileOrgFPA);
        hook_by_code("kernel32.dll", "DeleteFileW", (PROC)NewDeleteFileW, DeleteFileOrgFPW);
        hook_by_code("kernel32.dll", "DeleteFileA", (PROC)NewDeleteFileA, DeleteFileOrgFPA);
        hook_by_code("kernel32.dll", "ReadFile", (PROC)NewReadFile, ReadFileOrgFP);
        hook_by_code("kernel32.dll", "WriteFile", (PROC)NewWriteFile, WriteFileOrgFP);
        hook_by_code("kernel32.dll", "CreateDirectoryW", (PROC)NewCreateDirectoryW, CreateDirectoryOrgFPW);
        hook_by_code("kernel32.dll", "CreateDirectoryA", (PROC)NewCreateDirectoryA, CreateDirectoryOrgFPA);
        hook_by_code("kernel32.dll", "CopyFileW", (PROC)NewCopyFileW, CopyFileOrgFPW);
        hook_by_code("kernel32.dll", "CopyFileA", (PROC)NewCopyFileA, CopyFileOrgFPA);
        hook_by_code("kernel32.dll", "GetTempPathW", (PROC)NewGetTempPathW, GetTempPathOrgFPW);
        hook_by_code("kernel32.dll", "GetTempPathA", (PROC)NewGetTempPathA, GetTempPathOrgFPA);
        hook_by_code("kernel32.dll", "FindFirstFileW", (PROC)NewFindFirstFileW, FindFirstFileOrgFPW);
        hook_by_code("kernel32.dll", "FindFirstFileA", (PROC)NewFindFirstFileA, FindFirstFileOrgFPA);
        hook_by_code("kernel32.dll", "GetFileAttributesW", (PROC)NewGetFileAttributesW, GetFileAttributesOrgFPW);
        hook_by_code("kernel32.dll", "GetFileAttributesA", (PROC)NewGetFileAttributesA, GetFileAttributesOrgFPA);
        hook_by_code("kernel32.dll", "GetFileSize", (PROC)NewGetFileSize, GetFileSizeOrgFP);
        hook_by_code("kernel32.dll", "SetEndOfFile", (PROC)NewSetEndOfFile, SetEndOfFileOrgFP);
        hook_by_code("kernel32.dll", "SetFilePointer", (PROC)NewSetFilePointer, SetFilePointerOrgFP);
        hook_by_code("kernel32.dll", "FindResourceA", (PROC)NewFindResourceA, OrgFRA);
        hook_by_code("kernel32.dll", "FindResourceA", (PROC)NewFindResourceW, OrgFRW);
        hook_by_code("kernel32.dll", "LoadResource", (PROC)NewLoadResource, OrgLR);
        hook_by_code("kernel32.dll", "SizeofResource", (PROC)NewSizeofResource, OrgSR);
        hook_by_code("kernel32.dll", "GetTimeZoneInformation", (PROC)NewGetTimeZoneInformation, OrgGTZ);
        hook_by_code("kernel32.dll", "GetComputerNameW", (PROC)NewGetComputerNameA, OrgGCW);
        hook_by_code("kernel32.dll", "GetDiskFreeSpaceA", (PROC)NewGetDiskFreeSpaceA, OrgGDA);
        hook_by_code("kernel32.dll", "GetDiskFreeSpaceW", (PROC)NewGetDiskFreeSpaceA, OrgGDW);
        hook_by_code("kernel32.dll", "GetTickCount", (PROC)NewGetTickCount, OrgGTC);
        hook_by_code("kernel32.dll", "GetLocalTime", (PROC)NewGetLocalTime, OrgGLT);
        hook_by_code("kernel32.dll", "GetSystemTimeAsFileTime", (PROC)NewGetSystemTimeAsFileTime, OrgGSTFT);
        hook_by_code("kernel32.dll", "Sleep", (PROC)NewSleep, OrgSleep);
        hook_by_code("kernel32.dll", "UnhandledExceptionFilter", (PROC)NewUnhandledExceptionFilter, UEFOrgFP);
        hook_by_code("kernel32.dll", "SetUnhandledExceptionFilter", (PROC)NewSetUnhandledExceptionFilter, SUEFOrgFP);
        hook_by_code("kernel32.dll", "IsDebuggerPresent", (PROC)NewIsDebuggerPresent, IDPOriFP);
        hook_by_code("kernel32.dll", "GetSystemInfo", (PROC)NewGetSystemInfo, GSIOriFP);
        hook_by_code("kernel32.dll", "SetErrorMode", (PROC)SetErrorMode, SEMOriFP);
        break;
    case DLL_PROCESS_DETACH:
        DebugLog("MyHook DLL_PROCESS_DETACH\n");
        unhook_by_code("kernel32.dll", "CreateFileW", CreateFileOrgFPW);
        unhook_by_code("kernel32.dll", "CreateFileA", CreateFileOrgFPA);
        unhook_by_code("kernel32.dll", "DeleteFileW", DeleteFileOrgFPW);
        unhook_by_code("kernel32.dll", "DeleteFileA", DeleteFileOrgFPA);
        unhook_by_code("kernel32.dll", "ReadFile", ReadFileOrgFP);
        unhook_by_code("kernel32.dll", "WriteFile", WriteFileOrgFP);
        unhook_by_code("kernel32.dll", "CreateDirectoryW", CreateDirectoryOrgFPW);
        unhook_by_code("kernel32.dll", "CreateDirectoryA", CreateDirectoryOrgFPA);
        unhook_by_code("kernel32.dll", "CopyFileW", CopyFileOrgFPW);
        unhook_by_code("kernel32.dll", "CopyFileA", CopyFileOrgFPA);
        unhook_by_code("kernel32.dll", "GetTempPathW", GetTempPathOrgFPW);
        unhook_by_code("kernel32.dll", "GetTempPathA", GetTempPathOrgFPA);
        unhook_by_code("kernel32.dll", "FindFirstFileW", FindFirstFileOrgFPW);
        unhook_by_code("kernel32.dll", "FindFirstFileA", FindFirstFileOrgFPA);
        unhook_by_code("kernel32.dll", "GetFileAttributesW", GetFileAttributesOrgFPW);
        unhook_by_code("kernel32.dll", "GetFileAttributesA", GetFileAttributesOrgFPA);
        unhook_by_code("kernel32.dll", "GetFileSize", GetFileSizeOrgFP);
        unhook_by_code("kernel32.dll", "SetEndOfFile", SetEndOfFileOrgFP);
        unhook_by_code("kernel32.dll", "SetFilePointer", SetFilePointerOrgFP);
        unhook_by_code("kernel32.dll", "FindResourceA", OrgFRA);
        unhook_by_code("kernel32.dll", "FindResourceW", OrgFRW);
        unhook_by_code("kernel32.dll", "LoadResource", OrgLR);
        unhook_by_code("kernel32.dll", "SizeofResource", OrgSR);
        unhook_by_code("kernel32.dll", "GetDiskFreeSpaceW", OrgGDW);
        unhook_by_code("kernel32.dll", "GetDiskFreeSpaceA", OrgGDA);
        unhook_by_code("kernel32.dll", "GetComputerNameW", OrgGCW);
        unhook_by_code("kernel32.dll", "GetComputerNameA", OrgGCA);
        unhook_by_code("kernel32.dll", "GetTickCount", OrgGTC);
        unhook_by_code("kernel32.dll", "GetLocalTime", OrgGLT);
        unhook_by_code("kernel32.dll", "GetSystemTimeAsFileTime", OrgGSTFT);
        unhook_by_code("kernel32.dll", "Sleep", OrgSleep);
        unhook_by_code("kernel32.dll", "UnhandledExceptionFilter", UEFOrgFP);
        unhook_by_code("kernel32.dll", "SetUnhandledExceptionFilter", SUEFOrgFP);
        unhook_by_code("kernel32.dll", "IsDebuggerPresent", IDPOriFP);
        unhook_by_code("kernel32.dll", "GetSystemInfo", GSIOriFP);
        unhook_by_code("kernel32.dll", "SetErrorMode", SEMOriFP);
        break;
    }
    return TRUE;
}