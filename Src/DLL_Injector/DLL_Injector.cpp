#include <Windows.h>
#include <TlHelp32.h>

#include <string>

bool process_name_to_pid(
	__out DWORD& pid,
	__in const std::wstring& process_name
);

bool dll_injection(
	__in DWORD pid,
	__in const std::wstring& dll_name
);

int main() {
	DWORD pid = 0;
	std::wstring process_name = L"notepad.exe";
	std::wstring dll_name = L"../zwCreateFolder_Hooker/";

	if (process_name_to_pid(pid, process_name)) {
		dll_injection(pid, dll_name);
	}
	return 0;
}

bool process_name_to_pid(
	__out DWORD& pid,
	__in const std::wstring& process_name
) {
	bool result = false;
	HANDLE snapshot = nullptr;
	PROCESSENTRY32 entry = {};
	
	entry.dwSize = sizeof(PROCESSENTRY32);
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);

	}
