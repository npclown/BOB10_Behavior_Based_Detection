#pragma once

std::set<std::string> Exception()
{
	std::set<std::string> exception;
	exception.insert("UnhandledExceptionFilter");
	exception.insert("SetUnhandledExceptionFilter");

	return exception;
}

std::set<std::string> System()
{
	std::set<std::string> system_;
	system_.insert("IsDebuggerPresent");
	system_.insert("GetSystemInfo");
	system_.insert("SetErrorMode");

	return system_;
}

std::set<std::string> Process()
{
	std::set<std::string> process;
	process.insert("TerminateProcess");
	process.insert("CreateThread");
	process.insert("ResumeThread");
	process.insert("SuspendThread");
	process.insert("OpenProcess");

	return process;
}

std::set<std::string> File()
{
	std::set<std::string> file;
	file.insert("CreateFile");
	file.insert("DeleteFile");
	file.insert("ReadFile");
	file.insert("SetEndOfFile");
	file.insert("WriteFile");
	file.insert("CreateDirectory");
	file.insert("GetTempPath");
	file.insert("CopyFile");
	file.insert("FindFirstFile");
	file.insert("GetFileAttributes");
	file.insert("GetFileSize");
	file.insert("SetFilePointer");

	return file;
}

std::set<std::string> Resource()
{
	std::set<std::string> resource;
	resource.insert("FindResource");
	resource.insert("LoadResource");
	resource.insert("SizeofResource");

	return resource;
}

std::set<std::string> Misc()
{
	std::set<std::string> misc;
	misc.insert("GetTimeZoneInformation");
	misc.insert("GetComputerName");
	misc.insert("GetDiskFreeSpace");

	return misc;
}

std::set<std::string> Synchronisation()
{
	std::set<std::string> synchronisation;
	synchronisation.insert("GetTickCount");
	synchronisation.insert("GetLocalTime");
	synchronisation.insert("GetSystemTimeAsFileTime");
	synchronisation.insert("Sleep");

	return synchronisation;
}