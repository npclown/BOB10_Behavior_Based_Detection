#pragma once

std::vector<std::string> Scenario1()
{
	std::vector<std::string> scenario;
	//scenario.push_back("LdrGetDllHandle");
	scenario.push_back("LdrGetProcedureAddress");
	scenario.push_back("RegOpenKeyExW");
	scenario.push_back("RegQueryInfoKeyW");
	scenario.push_back("RegEnumKeyExW");
	scenario.push_back("RegEnumValueW");
	scenario.push_back("RegCloseKey");
	scenario.push_back("RegQueryValueExW");
	scenario.push_back("FindFirstFileExW");
	//scenario.push_back("memcpy");
	//scenario.push_back("VirtualProtectEx");
	scenario.push_back("GetSystemInfo");
	scenario.push_back("GlobalMemoryStatus");
	//scenario.push_back("GetFileVersionInfoSizeW");
	//scenario.push_back("GetFileVersionInfoW");

	//scenario.push_back("HeapCreate");
	//scenario.push_back("IsDebuggerPresent");
	scenario.push_back("CreateThread");
	scenario.push_back("RtlAddVectoredExceptionHandler");
	scenario.push_back("SetUnhandledExceptionFilter");
	scenario.push_back("GlobalMemoryStatusEx");
	//scenario.push_back("LsaOpenPolicy");
	//scenario.push_back("UrlCanonicalizeW");
	//scenario.push_back("StrCmpNICW");

	scenario.push_back("DeviceIoControl");
	scenario.push_back("RegOpenKeyExA");
	//scenario.push_back("SHGetFolderPathW");
	scenario.push_back("RegQueryValueExA");
	scenario.push_back("CryptAcquireContextW");
	scenario.push_back("CryptGenRandom");
	scenario.push_back("RegCreateKeyExW");

	return scenario;
}

std::vector<std::string> Scenario2()
{
	std::vector<std::string> scenario;
	
	scenario.push_back("GetSystemTimeAsFileTime");
	//scenario.push_back("HeapCreate");
	//scenario.push_back("IsDebuggerPresent");
	scenario.push_back("CreateThread");
	//scenario.push_back("RtlAddVectoredExceptionHandler");
	scenario.push_back("SetUnhandledExceptionFilter");
	scenario.push_back("GlobalMemoryStatusEx");
	//scenario.push_back("LsaOpenPolicy");

	//scenario.push_back("UrlCanonicalizeW");
	//scenario.push_back("StrCmpNICW");
	scenario.push_back("DeviceIoControl");
	scenario.push_back("RegOpenKeyExA");
	//scenario.push_back("SHGetFolderPathW");
	scenario.push_back("RegQueryValueExA");
	scenario.push_back("CryptAcquireContextW");
	scenario.push_back("CryptGenRandom");
	scenario.push_back("RegCreateKeyExW");

	return scenario;
}

std::vector<std::string> Scenario3()
{
	std::vector<std::string> scenario;

	scenario.push_back("LdrGetProcedureAddress");
	scenario.push_back("RegOpenKeyExW");
	scenario.push_back("RegQueryInfoKeyW");
	scenario.push_back("RegEnumKeyExW");
	scenario.push_back("RegEnumValueW");
	scenario.push_back("RegCloseKey");
	scenario.push_back("RegQueryValueExW");
	scenario.push_back("FindFirstFileExW");
	//scenario.push_back("memcpy");
	//scenario.push_back("VirtualProtectEx");
	scenario.push_back("GetSystemInfo");
	scenario.push_back("GlobalMemoryStatus");
	//scenario.push_back("GetFileVersionInfoSizeW");
	//scenario.push_back("GetFileVersionInfoW");

	return scenario;
}