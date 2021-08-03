#include "stdafx.h"

typedef unsigned long		DWORD;

bool process_name_to_pid(__out DWORD& pid, __in const std::wstring& process_name);
bool dll_injection(__in DWORD& pid, __in const std::wstring& dll_name);

int main() {
	DWORD pid = 7796;
	std::wstring process_name = L"notepad.exe";
	std::wstring dll_name = L"C:\\Users\\bob\\Desktop\\WinAPI_Hooking_Project\\Build\\Win32Debug\\myhook.dll";

	if (process_name_to_pid(pid, process_name)) {
		dll_injection(pid, dll_name);
	}
}

bool process_name_to_pid(__out DWORD& pid, __in const std::wstring& process_name) {
	bool result = false;
	HANDLE snapshot = nullptr;
	PROCESSENTRY32 entry = {};

	entry.dwSize = sizeof(PROCESSENTRY32);
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);  //tlhelp32.h,  kernel32.dll
	printf("%d\n", entry.dwSize);

	if (snapshot != INVALID_HANDLE_VALUE) {
		Process32First(snapshot, &entry);	//tlhelp32.h,  kernel32.dll
		do {
			std::cout << process_name.c_str() << std::endl;
			if (!_tcsicmp(process_name.c_str(), entry.szExeFile)) {	//<string.h> 또는 <wchar.h>
				pid = entry.th32ProcessID;
				result = true;
				break;
			}
		} while (Process32Next(snapshot, &entry));	//tlhelp32.h,  kernel32.dll

		CloseHandle(snapshot);
	}

	return result;
}

bool dll_injection(__in DWORD& pid, __in const std::wstring& dll_name) {
	bool result = false;

	HANDLE process_handle = nullptr;
	HANDLE thread_handle = nullptr;
	LPVOID remote_buffer = nullptr;
	HMODULE module = NULL;

	LPTHREAD_START_ROUTINE thread_start_routine = nullptr;

	process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);	// processthreadsapi.h, Kernel32.dll
	if (process_handle == nullptr) {
		return false;
	}

	remote_buffer = VirtualAllocEx(process_handle, nullptr, dll_name.size(), MEM_COMMIT, PAGE_READWRITE);	//memoryapi.h Kernel32.dll

	if (!remote_buffer) {
		return false;
	}

	if (!WriteProcessMemory(process_handle, remote_buffer, dll_name.c_str(), dll_name.size() * sizeof(wchar_t), nullptr)) { // memoryapi.h(Windows.h 포함) Kernel32.lib
		return false;
	}

	module = GetModuleHandle(L"kernel32.dll");	// libloaderapi.h(Windows.h 포함) kernel32.dll

	thread_start_routine = (LPTHREAD_START_ROUTINE)GetProcAddress(module, "LoadLibraryW"); // libloaderapi.h(Windows.h 포함) kernel32.dll

	thread_handle = CreateRemoteThread(process_handle, nullptr, 0, thread_start_routine, remote_buffer, 0, nullptr); //processthreadsapi.h kernel32.dll

	WaitForSingleObject(thread_handle, INFINITE);	//syschapi.h kernel32.dll

	result = true;

	CloseHandle(thread_handle);
	CloseHandle(process_handle);

	return result;
}