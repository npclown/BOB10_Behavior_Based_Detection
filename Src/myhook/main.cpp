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
        break;
    }
    return TRUE;
}