#include "stdafx.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DebugLog("MyHook DLL_PROCESS_ATTACH\n");
        //file.h
        hook_by_code("kernel32.dll", "SetFileInformationByHandle", (PROC)NewSetFileInformationByHandle, SetFileInformationByHandleOrgFP);
        hook_by_code("kernel32.dll", "SetFileAttributesW", (PROC)NewSetFileAttributesW, SetFileAttributesWOrgFP);
        hook_by_code("kernel32.dll", "SearchPathW", (PROC)NweSearchPathW, SearchPathWOrgFP);
        hook_by_code("kernel32.dll", "RemoveDirectoryW", (PROC)NewRemoveDirectoryW, RemoveDirectoryWOrgFP);
        hook_by_code("kernel32.dll", "MoveFileWithProgressW", (PROC)NewMoveFileWithProgressW, MoveFileWithProgressWOrgFp);
        hook_by_code("kernel32.dll", "GetVolumePathNameW", (PROC)NewGetVolumePathNameW, GetVolumePathNameWOrgFP);
        hook_by_code("kernel32.dll", "GetVolumePathNamesForVolumeNameW", (PROC)NewGetVolumePathNamesForVolumeNameW, GetVolumePathNamesForVolumeNameWOrgFP);
        hook_by_code("kernel32.dll", "GetVolumeNameForVolumeMountPointW", (PROC)NewGetVolumeNameForVolumeMountPointW, GetVolumeNameForVolumeMountPointWOrgFP);
        hook_by_code("kernel32.dll", "GetSystemWindowsDirectoryW", (PROC)NewGetSystemWindowsDirectoryW, GetSystemWindowsDirectoryWOrgFP);
        hook_by_code("kernel32.dll", "GetSystemDirectoryW", (PROC)NewGetSystemDirectoryW, GetSystemDirectoryWOrgFP);
        hook_by_code("kernel32.dll", "GetShortPathNameW", (PROC)NewGetShortPathNameW, GetShortPathNameWOrgFP);
        hook_by_code("kernel32.dll", "GetFileType", (PROC)NewGetFileType, GetFileTypeOrgFP);
        hook_by_code("kernel32.dll", "GetFileInformationByHandle", (PROC)NewGetFileInformationByHandle, GetFileInformationByHandleOrgFP);
        hook_by_code("kernel32.dll", "GetFileInformationByHandleEx", (PROC)NewGetFileInformationByHandleEx, GetFileInformationByHandleExOrgFP);

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
        //resource.h
        hook_by_code("kernel32.dll", "FindResourceA", (PROC)NewFindResourceA, OrgFRA);
        hook_by_code("kernel32.dll", "FindResourceA", (PROC)NewFindResourceW, OrgFRW);
        hook_by_code("kernel32.dll", "LoadResource", (PROC)NewLoadResource, OrgLR);
        hook_by_code("kernel32.dll", "SizeofResource", (PROC)NewSizeofResource, OrgSR);
        //misc.h
        hook_by_code("kernel32.dll", "GetTimeZoneInformation", (PROC)NewGetTimeZoneInformation, OrgGTZ);
        hook_by_code("kernel32.dll", "GetComputerNameA", (PROC)NewGetComputerNameA, OrgGCA);
        hook_by_code("kernel32.dll", "GetComputerNameW", (PROC)NewGetComputerNameW, OrgGCW);
        hook_by_code("kernel32.dll", "GetDiskFreeSpaceA", (PROC)NewGetDiskFreeSpaceA, OrgGDA);
        hook_by_code("kernel32.dll", "GetDiskFreeSpaceW", (PROC)NewGetDiskFreeSpaceW, OrgGDW);
        //synchronisation.h
        //hook_by_code("kernel32.dll", "GetTickCount", (PROC)NewGetTickCount, OrgGTC);
        hook_by_code("kernel32.dll", "GetLocalTime", (PROC)NewGetLocalTime, OrgGLT);
        hook_by_code("kernel32.dll", "GetSystemTimeAsFileTime", (PROC)NewGetSystemTimeAsFileTime, OrgGSTFT);
        hook_by_code("kernel32.dll", "Sleep", (PROC)NewSleep, OrgSleep);
        //exception.h
        hook_by_code("kernel32.dll", "UnhandledExceptionFilter", (PROC)NewUnhandledExceptionFilter, UEFOrgFP);
        hook_by_code("kernel32.dll", "SetUnhandledExceptionFilter", (PROC)NewSetUnhandledExceptionFilter, SUEFOrgFP);
        //system.h
        //hook_by_code("kernel32.dll", "IsDebuggerPresent", (PROC)NewIsDebuggerPresent, IDPOriFP);
        hook_by_code("kernel32.dll", "GetSystemInfo", (PROC)NewGetSystemInfo, GSIOriFP);
        hook_by_code("kernel32.dll", "SetErrorMode", (PROC)NewSetErrorMode, SEMOriFP);
        //process.h
        hook_by_code("kernel32.dll", "OpenProcess", (PROC)NewOpenProcess, OP_OrgFP);
        hook_by_code("kernel32.dll", "TerminateProcess", (PROC)NewTerminateProcess, TP_OrgFP);
        hook_by_code("kernel32.dll", "CreateThread", (PROC)NewCreateThread, CT_OrgFP);
        hook_by_code("kernel32.dll", "ResumeThread", (PROC)NewResumeThread, RT_OrgFP);
        hook_by_code("kernel32.dll", "SuspendThread", (PROC)NewSuspendThread, ST_OrgFP);
        break;
    case DLL_PROCESS_DETACH:
        DebugLog("MyHook DLL_PROCESS_DETACH\n");
        //file.h
        unhook_by_code("kernel32.dll", "SetFileInformationByHandle", SetFileInformationByHandleOrgFP);
        unhook_by_code("kernel32.dll", "SetFileAttributesW", SetFileAttributesWOrgFP);
        unhook_by_code("kernel32.dll", "SearchPathW", SearchPathWOrgFP);
        unhook_by_code("kernel32.dll", "RemoveDirectoryW", RemoveDirectoryWOrgFP);
        unhook_by_code("kernel32.dll", "MoveFileWithProgressW", MoveFileWithProgressWOrgFp);
        unhook_by_code("kernel32.dll", "GetVolumePathNameW", GetVolumePathNameWOrgFP);
        unhook_by_code("kernel32.dll", "GetVolumePathNamesForVolumeNameW", GetVolumePathNamesForVolumeNameWOrgFP);
        unhook_by_code("kernel32.dll", "GetVolumeNameForVolumeMountPointW", GetVolumeNameForVolumeMountPointWOrgFP);
        unhook_by_code("kernel32.dll", "GetSystemWindowsDirectoryW", GetSystemWindowsDirectoryWOrgFP);
        unhook_by_code("kernel32.dll", "GetSystemDirectoryW", GetSystemDirectoryWOrgFP);
        unhook_by_code("kernel32.dll", "GetShortPathNameW", GetShortPathNameWOrgFP);
        unhook_by_code("kernel32.dll", "GetFileType", GetFileTypeOrgFP);
        unhook_by_code("kernel32.dll", "GetFileInformationByHandle", GetFileInformationByHandleOrgFP);
        unhook_by_code("kernel32.dll", "GetFileInformationByHandleEx", GetFileInformationByHandleExOrgFP);


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
        //resource.h
        unhook_by_code("kernel32.dll", "FindResourceA", OrgFRA);
        unhook_by_code("kernel32.dll", "FindResourceW", OrgFRW);
        unhook_by_code("kernel32.dll", "LoadResource", OrgLR);
        unhook_by_code("kernel32.dll", "SizeofResource", OrgSR);
        //misc.h
        unhook_by_code("kernel32.dll", "GetTimeZoneInformation", OrgGTZ);
        unhook_by_code("kernel32.dll", "GetDiskFreeSpaceW", OrgGDW);
        unhook_by_code("kernel32.dll", "GetDiskFreeSpaceA", OrgGDA);
        unhook_by_code("kernel32.dll", "GetComputerNameW", OrgGCW);
        unhook_by_code("kernel32.dll", "GetComputerNameA", OrgGCA);
        //synchronisation.h
        //unhook_by_code("kernel32.dll", "GetTickCount", OrgGTC);
        unhook_by_code("kernel32.dll", "GetLocalTime", OrgGLT);
        unhook_by_code("kernel32.dll", "GetSystemTimeAsFileTime", OrgGSTFT);
        unhook_by_code("kernel32.dll", "Sleep", OrgSleep);
        //exception.h
        unhook_by_code("kernel32.dll", "UnhandledExceptionFilter", UEFOrgFP);
        unhook_by_code("kernel32.dll", "SetUnhandledExceptionFilter", SUEFOrgFP);
        //system.h
        //unhook_by_code("kernel32.dll", "IsDebuggerPresent", IDPOriFP);
        unhook_by_code("kernel32.dll", "GetSystemInfo", GSIOriFP);
        unhook_by_code("kernel32.dll", "SetErrorMode", SEMOriFP);
        //process.h
        unhook_by_code("kernel32.dll", "OpenProcess", OP_OrgFP);
        unhook_by_code("kernel32.dll", "TerminateProcess", TP_OrgFP);
        unhook_by_code("kernel32.dll", "CreateThread", CT_OrgFP);
        unhook_by_code("kernel32.dll", "ResumeThread", RT_OrgFP);
        unhook_by_code("kernel32.dll", "SuspendThread", ST_OrgFP);
        break;
    }
    return TRUE;
}