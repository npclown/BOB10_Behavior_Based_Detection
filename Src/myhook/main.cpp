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
        hook_by_code("kernel32.dll", "FindFirstFileExW", (PROC)NewFindFirstFileExW, FindFirstFileExWOrgFPW);


        //resource.h
        hook_by_code("kernel32.dll", "FindResourceA", (PROC)NewFindResourceA, OrgFRA);
        hook_by_code("kernel32.dll", "FindResourceA", (PROC)NewFindResourceW, OrgFRW);
        hook_by_code("kernel32.dll", "LoadResource", (PROC)NewLoadResource, OrgLR);
        hook_by_code("kernel32.dll", "SizeofResource", (PROC)NewSizeofResource, OrgSR);
        hook_by_code("kernel32.dll", "FindResourceW", (PROC)NewFindResourceW, OrgFRW);
        hook_by_code("kernel32.dll", "LoadResource", (PROC)NewLoadResource, OrgLR);
        hook_by_code("kernel32.dll", "SizeofResource", (PROC)NewSizeofResource, OrgSR);
        hook_by_code("kernel32.dll", "FindResourceExA", (PROC)NewFindResourceExA, FindResourceExAOrgFPA);
        hook_by_code("kernel32.dll", "FindResourceExW", (PROC)NewFindResourceExW, FindResourceExWOrgFPW);

        //misc.h
        hook_by_code("kernel32.dll", "GetTimeZoneInformation", (PROC)NewGetTimeZoneInformation, OrgGTZ);
        hook_by_code("kernel32.dll", "GetComputerNameA", (PROC)NewGetComputerNameA, OrgGCA);
        hook_by_code("kernel32.dll", "GetComputerNameW", (PROC)NewGetComputerNameW, OrgGCW);
        hook_by_code("kernel32.dll", "GetDiskFreeSpaceA", (PROC)NewGetDiskFreeSpaceA, OrgGDA);
        hook_by_code("kernel32.dll", "GetDiskFreeSpaceW", (PROC)NewGetDiskFreeSpaceW, OrgGDW);
        hook_by_code("kernel32.dll", "WriteConsoleA", (PROC)NewWriteConsoleA, WriteConsoleAOrgFPA);
        hook_by_code("kernel32.dll", "WriteConsoleW", (PROC)NewWriteConsoleW, WriteConsoleWOrgFPW);

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
        hook_by_code("kernel32.dll", "GetNativeSystemInfo", (PROC)NewGetNativeSystemInfo, GetNativeSystemInfoOrgFP);
        //hook_by_code("kernel32.dll", "OutputDebugStringA", (PROC)NewOutputDebugStringA, OutputDebugStringAOrgFPA);

        //process.h
        hook_by_code("kernel32.dll", "OpenProcess", (PROC)NewOpenProcess, OP_OrgFP);
        hook_by_code("kernel32.dll", "TerminateProcess", (PROC)NewTerminateProcess, TP_OrgFP);
        hook_by_code("kernel32.dll", "CreateThread", (PROC)NewCreateThread, CT_OrgFP);
        hook_by_code("kernel32.dll", "ResumeThread", (PROC)NewResumeThread, RT_OrgFP);
        hook_by_code("kernel32.dll", "SuspendThread", (PROC)NewSuspendThread, ST_OrgFP);
        hook_by_code("kernel32.dll", "Module32FirstW", (PROC)NewModule32FirstW, Module32FirstWOrgFPW);
        hook_by_code("kernel32.dll", "Module32NextW", (PROC)NewModule32NextW, Module32NextWOrgFPW);
        hook_by_code("kernel32.dll", "Process32FirstW", (PROC)NewProcess32FirstW, Process32FirstWOrgFPW);
        hook_by_code("kernel32.dll", "Process32NextW", (PROC)NewProcess32NextW, Process32NextWOrgFPW);
        hook_by_code("kernel32.dll", "Thread32First", (PROC)NewThread32First, Thread32FirstOrgFP);
        hook_by_code("kernel32.dll", "Thread32Next", (PROC)NewThread32Next, Thread32NextOrgFP);
        hook_by_code("kernel32.dll", "ReadProcessMemory", (PROC)NewReadProcessMemory, ReadProcessMemoryOrgFP);
        hook_by_code("kernel32.dll", "WriteProcessMemory", (PROC)NewWriteProcessMemory, WriteProcessMemoryOrgFP);
        hook_by_code("kernel32.dll", "CreateRemoteThread", (PROC)NewCreateRemoteThread, CreateRemoteThreadOrgFP);
        hook_by_code("kernel32.dll", "CreateToolhelp32Snapshot", (PROC)NewCreateToolhelp32Snapshot, CreateToolhelp32SnapshotOrgFP);

        //register.h
        hook_by_code("Advapi32.dll", "RegOpenKeyExA", (PROC)NewRegOpenKeyExA, RegOpenKeyExAOrgFPA);
        hook_by_code("Advapi32.dll", "RegOpenKeyExW", (PROC)NewRegOpenKeyExW, RegOpenKeyExWOrgFPW);
        hook_by_code("Advapi32.dll", "RegQueryValueExA", (PROC)NewRegQueryValueExA, RegQueryValueExAOrgFPA);
        hook_by_code("Advapi32.dll", "RegQueryInfoKeyW", (PROC)NewRegQueryInfoKeyW, RegQueryInfoKeyWOrgFPW);
        hook_by_code("Advapi32.dll", "RegCloseKey", (PROC)NewRegCloseKey, RegCloseKeyOrgFP);
        hook_by_code("Advapi32.dll", "RegQueryValueExW", (PROC)NewRegQueryValueExW, RegQueryValueExWOrgFPW);
        hook_by_code("Advapi32.dll", "RegCreateKeyExW", (PROC)NewRegCreateKeyExW, RegCreateKeyExWOrgFPW);
        hook_by_code("Advapi32.dll", "RegEnumKeyExW", (PROC)NewRegEnumKeyExW, RegEnumKeyExWOrgFPW);
        hook_by_code("Advapi32.dll", "RegEnumValueW", (PROC)NewRegEnumValueW, RegEnumValueWOrgFPW);

        //etc.h
        hook_by_code("Advapi32.dll", "CryptAcquireContextW", (PROC)NewCryptAcquireContextW, CryptAcquireContextWOrgFPW);
        hook_by_code("Kernel32.dll", "HeapCreate", (PROC)NewHeapCreate, HeapCreateOrgFP);
        hook_by_code("Kernel32.dll", "GetSystemTime", (PROC)NewGetSystemTime, GetSystemTimeOrgFP);
        hook_by_code("Advapi32.dll", "CryptGenRandom", (PROC)NewCryptGenRandom, CryptGenRandomOrgFP);
        hook_by_code("Kernel32.dll", "DeviceIoControl", (PROC)NewDeviceIoControl, DeviceIoControlOrgFP);
        hook_by_code("Kernel32.dll", "VirtualProtectEx", (PROC)NewVirtualProtectEx, VirtualProtectExOrgFP);
        hook_by_code("Kernel32.dll", "GlobalMemoryStatus", (PROC)NewGlobalMemoryStatus, GlobalMemoryStatusOrgFP);
        hook_by_code("Kernel32.dll", "GlobalMemoryStatusEx", (PROC)NewGlobalMemoryStatusEx, GlobalMemoryStatusExOrgFP);

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
        unhook_by_code("kernel32.dll", "FindFirstFileExW", FindFirstFileExWOrgFPW);


        //resource.h
        unhook_by_code("kernel32.dll", "FindResourceA", OrgFRA);
        unhook_by_code("kernel32.dll", "FindResourceW", OrgFRW);
        unhook_by_code("kernel32.dll", "LoadResource", OrgLR);
        unhook_by_code("kernel32.dll", "SizeofResource", OrgSR);
        unhook_by_code("kernel32.dll", "FindResourceExA", FindResourceExAOrgFPA);
        unhook_by_code("kernel32.dll", "FindResourceExW", FindResourceExWOrgFPW);

        //misc.h
        unhook_by_code("kernel32.dll", "GetTimeZoneInformation", OrgGTZ);
        unhook_by_code("kernel32.dll", "GetDiskFreeSpaceW", OrgGDW);
        unhook_by_code("kernel32.dll", "GetDiskFreeSpaceA", OrgGDA);
        unhook_by_code("kernel32.dll", "GetComputerNameW", OrgGCW);
        unhook_by_code("kernel32.dll", "GetComputerNameA", OrgGCA);
        unhook_by_code("kernel32.dll", "WriteConsoleA",  WriteConsoleAOrgFPA);
        unhook_by_code("kernel32.dll", "WriteConsoleW", WriteConsoleWOrgFPW);

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
        unhook_by_code("kernel32.dll", "GetNativeSystemInfo", GetNativeSystemInfoOrgFP);
        //unhook_by_code("kernel32.dll", "OutputDebugStringA", OutputDebugStringAOrgFPA);

        //process.h
        unhook_by_code("kernel32.dll", "OpenProcess", OP_OrgFP);
        unhook_by_code("kernel32.dll", "TerminateProcess", TP_OrgFP);
        unhook_by_code("kernel32.dll", "CreateThread", CT_OrgFP);
        unhook_by_code("kernel32.dll", "ResumeThread", RT_OrgFP);
        unhook_by_code("kernel32.dll", "SuspendThread", ST_OrgFP);
        unhook_by_code("kernel32.dll", "Module32FirstW", Module32FirstWOrgFPW);
        unhook_by_code("kernel32.dll", "Module32NextW", Module32NextWOrgFPW);
        unhook_by_code("kernel32.dll", "Process32FirstW", Process32FirstWOrgFPW);
        unhook_by_code("kernel32.dll", "Process32NextW", Process32NextWOrgFPW);
        unhook_by_code("kernel32.dll", "Thread32First", Thread32FirstOrgFP);
        unhook_by_code("kernel32.dll", "Thread32Next", Thread32NextOrgFP);
        unhook_by_code("kernel32.dll", "ReadProcessMemory", ReadProcessMemoryOrgFP);
        unhook_by_code("kernel32.dll", "WriteProcessMemory", WriteProcessMemoryOrgFP);
        unhook_by_code("kernel32.dll", "CreateRemoteThread",  CreateRemoteThreadOrgFP);
        unhook_by_code("kernel32.dll", "CreateToolhelp32Snapshot", CreateToolhelp32SnapshotOrgFP);

        //register.h
        unhook_by_code("Advapi32.dll", "RegOpenKeyExA", RegOpenKeyExAOrgFPA);
        unhook_by_code("Advapi32.dll", "RegOpenKeyExW", RegOpenKeyExWOrgFPW);
        unhook_by_code("Advapi32.dll", "RegQueryValueExA", RegQueryValueExAOrgFPA);
        unhook_by_code("Advapi32.dll", "RegQueryInfoKeyW", RegQueryInfoKeyWOrgFPW);
        unhook_by_code("Advapi32.dll", "RegCloseKey", RegCloseKeyOrgFP);
        unhook_by_code("Advapi32.dll", "RegQueryValueExW", RegQueryValueExWOrgFPW);
        unhook_by_code("Advapi32.dll", "RegCreateKeyExW", RegCreateKeyExWOrgFPW);
        unhook_by_code("Advapi32.dll", "RegEnumKeyExW", RegEnumKeyExWOrgFPW);
        unhook_by_code("Advapi32.dll", "RegEnumValueW", RegEnumValueWOrgFPW);
        
        //etc.h
        unhook_by_code("Advapi32.dll", "CryptAcquireContextW", CryptAcquireContextWOrgFPW);
        unhook_by_code("Kernel32.dll", "HeapCreate", HeapCreateOrgFP);
        unhook_by_code("Kernel32.dll", "GetSystemTime", GetSystemTimeOrgFP);
        unhook_by_code("Advapi32.dll", "CryptGenRandom", CryptGenRandomOrgFP);
        unhook_by_code("Kernel32.dll", "DeviceIoControl", DeviceIoControlOrgFP);
        unhook_by_code("Kernel32.dll", "VirtualProtectEx", VirtualProtectExOrgFP);
        unhook_by_code("Kernel32.dll", "GlobalMemoryStatus", GlobalMemoryStatusOrgFP);
        unhook_by_code("Kernel32.dll", "GlobalMemoryStatusEx", GlobalMemoryStatusExOrgFP);
        break;
    }
    return TRUE;
}