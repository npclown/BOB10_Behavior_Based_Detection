// debug_monitor.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include <map>
#include <set>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include "APIset.h"

struct db_buffer
{
	DWORD   dwProcessId;
	char    data[4096 - sizeof(DWORD)];
};

static HANDLE	hMutex = NULL;

HANDLE hEventDataReady;
HANDLE hDBWINBuffer;
HANDLE hEventBufferReady;

struct db_buffer* pDBBuffer;

// pid를 키로 가지고 해당 pid의 호출 api 목록을 set으로 저장하는 map : logs
//std::map<DWORD, std::set<std::string>> logs;
std::map<DWORD, std::vector<std::string>> logs;
std::string detach = "DETACH\n";
std::string attach = "ATTACH\n";

bool pid_check[32769]; // pid : 0 ~ 32768, true - 한 번 체크됨 (메시지 박스 중복 방지용)
bool malware_check[32769]; // pid : 0 ~ 32768, true - 차단된 pid

void Init_check()
{
	memset(pid_check, sizeof(pid_check), false);
	memset(malware_check, sizeof(malware_check), false);
}

void Get_API(DWORD pid, char* data)
{
	if (data == NULL)
		return;
	
	std::string* str_data = new std::string("");
	std::string* str_pid = new std::string("");

	*str_data = (std::string)data;
	*str_pid = std::to_string((int)pid);

	if (*str_pid == (*str_data).substr(0, (*str_pid).size())) {
		//logs[pid].insert((*str_data).substr((*str_pid).size() + 1));

		// 중복체크하면서 push back
		std::string api_name = (*str_data).substr((*str_pid).size() + 1);
		if(std::find(logs[pid].begin(), logs[pid].end(), api_name) == logs[pid].end())
			logs[pid].push_back(api_name);
	}
	else {
		if ((*str_data).substr((*str_data).size() - 7) == detach) {
			pid_check[(int)pid] = false;
			malware_check[(int)pid] = false;
			printf("========\n");
			logs[pid].clear();
		}
	}

	delete str_data;
	delete str_pid;

	return;
}
// 여기까지

// 딜레마이군.....
// 호출하는 api 목록이랑 체크할 api 목록(아래 애들) 둘 다를 set으로 하면
// 결국 detach 하기 직전에 둘이 비교하는 법 밖에 없을 듯
// 하지만 detach 하지 않는다면???
// 호출하는 api 목록을 vector로 처리하면 중복처리를 while 돌 때마다 계속 호출해야됨 => 너무 비효율 => 그런데 이게 최선일 듯
// 체크할 api 목록을 vector로 처리하면 중복처리를 못하고 계속 체킹됨
// 무엇이 최선일까......

std::set<std::string> exception = Exception();
std::set<std::string> system_ = System();
std::set<std::string> process = Process();
std::set<std::string> file = File();
std::set<std::string> resource = Resource();
std::set<std::string> misc = Misc();
std::set<std::string> synchronisation = Synchronisation();

std::vector<std::set<std::string>> ListOfAPIsets; // 위에 애들 모아놓은 것
std::vector<int> SizeOfAPIsets;

void MakeVectorAboutAPIsets()
{
	ListOfAPIsets.push_back(exception); // 0 (index of vec_check)
	ListOfAPIsets.push_back(system_); // 1
	ListOfAPIsets.push_back(process); // 2
	ListOfAPIsets.push_back(file); // 3
	ListOfAPIsets.push_back(resource); // 4
	ListOfAPIsets.push_back(misc); // 5
	ListOfAPIsets.push_back(synchronisation); // 6

	SizeOfAPIsets.push_back(exception.size());
	SizeOfAPIsets.push_back(system_.size());
	SizeOfAPIsets.push_back(process.size());
	SizeOfAPIsets.push_back(file.size());
	SizeOfAPIsets.push_back(resource.size());
	SizeOfAPIsets.push_back(misc.size());
	SizeOfAPIsets.push_back(synchronisation.size());
}

std::map<DWORD, int> IdxOfVecOfPid; // 해당 pid의 중복 없는 vector의 체크 대상 idx 저장, key = pid value = idx
std::map<DWORD, std::vector<int>> CountingOfAPIsOfPid; // 해당 pid에 대해 check_list의 set 목록에 몇 개가 체크되고 있는지 확인

void Init_IdxOfVecPid(DWORD pid)
{
	IdxOfVecOfPid[pid] = 0;
}

void Init_CountingOfAPIsOfPid(DWORD pid)
{
	CountingOfAPIsOfPid[pid].clear();
	CountingOfAPIsOfPid[pid].resize(ListOfAPIsets.size(), 0);
}

void CountAPI(std::string s, DWORD pid)
{
	std::set<std::string>::iterator iter;

	// i : 위의 0 ~ 6에 해당
	for (int i = 0; i < ListOfAPIsets.size(); i++) {

		iter = ListOfAPIsets[i].find(s);
		if (iter != ListOfAPIsets[i].end()) {

			if (CountingOfAPIsOfPid[pid].empty()) {
				Init_CountingOfAPIsOfPid(pid);
			}

			CountingOfAPIsOfPid[pid][i]++;

			break;
		}
	}
}

// 얘가 악성인지 판단
bool check_condition(DWORD pid)
{
	int cnt_set = 0; // 몇 개의 목록이 만족하는지 체크

	for (int i = 0; i < CountingOfAPIsOfPid[pid].size(); i++) {

		// i번째 목록에 대해 조건 만족하는지 체크
		// 조건 = i번째 목록의 전체 api 개수 중 절반 이상인지
		if (CountingOfAPIsOfPid[pid][i] >= (SizeOfAPIsets[i] / 2)) {
			cnt_set++;
		}
	}

	if (cnt_set >= (SizeOfAPIsets.size() / 2)) {
		return true;
	}
	else
		return false;
}

bool isKeyLogger(DWORD pid)
{
	// logs[pid] 는 중복 없는 vector of strings
	int idx = IdxOfVecOfPid[pid];

	for (int i = idx; i < logs[pid].size(); i++) {
		
		std::string str = logs[pid][i];

		if (str.back() == 'W' || str.back() == 'A') {
			logs[pid][i] = str.substr(0, str.size() - 1);
		}

		CountAPI(str, pid);

		bool check = check_condition(pid);

		if (check) {
			Init_IdxOfVecPid(pid);
			Init_CountingOfAPIsOfPid(pid);
			return true;
		}
	}

	IdxOfVecOfPid[pid] += ((int)(logs[pid].size()) - idx);
	return false;
}

int _tmain(int argc, _TCHAR* argv[])
{

	DWORD errorCode = 0;


	//OpenMutex(MUTEX_ALL_ACCESS, FALSE, L"DBWinMutex");

	/*
	SECURITY_DESCRIPTOR     sdopen;

	InitializeSecurityDescriptor(&sdopen,SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sdopen, TRUE, NULL, FALSE);

	SECURITY_ATTRIBUTES     sa;
	ZeroMemory(&sa, sizeof sa);

	sa.nLength = sizeof sa;
	sa.lpSecurityDescriptor = &sdopen;
	sa.bInheritHandle = FALSE;

	if ((hMutex = CreateMutex(&sa, FALSE, L"DBWinMutex")) == 0)
	{

	errorCode = GetLastError();
	printf("createmutex error %d", errorCode);
	return errorCode;
	}
	*/


	hEventBufferReady = OpenEvent(EVENT_ALL_ACCESS, FALSE, L"DBWIN_BUFFER_READY");
	if (hEventBufferReady == NULL) {
		hEventBufferReady = CreateEvent(NULL, FALSE, TRUE, L"DBWIN_BUFFER_READY");

		if (hEventBufferReady == NULL) {
			errorCode = GetLastError();
			printf("buffer ready error %d", errorCode);
			return errorCode;
		}
	}


	hEventDataReady = OpenEvent(SYNCHRONIZE, FALSE, L"DBWIN_DATA_READY");
	if (hEventDataReady == NULL) {
		hEventDataReady = CreateEvent(NULL, FALSE, FALSE, L"DBWIN_DATA_READY");

		if (hEventDataReady == NULL) {
			errorCode = GetLastError();
			printf("ready data error %d", errorCode);
			return errorCode;
		}
	}


	hDBWINBuffer = OpenFileMapping(FILE_MAP_READ, FALSE, L"DBWIN_BUFFER");


	if (hDBWINBuffer == NULL) {
		hDBWINBuffer = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(struct db_buffer), L"DBWIN_BUFFER");

		if (hDBWINBuffer == NULL) {
			errorCode = GetLastError();
			printf("create file mapping error %d", errorCode);
			return errorCode;
		}
	}

	pDBBuffer = (struct db_buffer*)MapViewOfFile(hDBWINBuffer, SECTION_MAP_READ, 0, 0, 0);

	if (pDBBuffer == NULL) {
		errorCode = GetLastError();
		printf("map view of file error %d", errorCode);
		return errorCode;
	}

	bool isRunning = true;

	// csv 파일 만들기 
	// 행 별로 0번째에 해당 process 경로 (이름 포함), 1번째에 해당 pid 2번째부터 api 이름
	std::ofstream writeFile;
	writeFile.open("logs.csv");
	//writeFile.open("logs.txt");
	MakeVectorAboutAPIsets();
	Init_check();

	while (isRunning)
	{
		DWORD mb = WaitForSingleObject(hEventDataReady, INFINITE);

		if (mb == WAIT_OBJECT_0) {

			HANDLE terminate_handle = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, TRUE, pDBBuffer->dwProcessId);

			int ProcessId = (int)(pDBBuffer->dwProcessId);

			if ((malware_check[ProcessId] == false) && (pid_check[ProcessId] == true)) {
				try {
					// 악성코드 아닌 것이라 판정된 pid
					CloseHandle(terminate_handle);
					SetEvent(hEventBufferReady);
				}
				catch (int exception) {
					printf("terminate handle error!!!\n");
				}
				continue;
			}

			if ((malware_check[ProcessId] == true) && (pid_check[ProcessId] == true)) {
				try {
					// 악성코드인지 한 번 체크된 pid
					TerminateProcess(terminate_handle, 0);
					CloseHandle(terminate_handle);
					SetEvent(hEventBufferReady);
				}
				catch (int exception) {
					printf("kill error!!!!\n");
				}
				continue;
			}
			
			try {
				HANDLE process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pDBBuffer->dwProcessId);

				Get_API(pDBBuffer->dwProcessId, pDBBuffer->data);
				printf("[%d] %s\n", pDBBuffer->dwProcessId, pDBBuffer->data);

				wchar_t buffer[MAX_PATH] = {};
				DWORD buffer_size = MAX_PATH;
				std::wstring ws;
				std::string str;
				
				if (process_handle) {
					
					if (QueryFullProcessImageNameW(process_handle, 0, buffer, &buffer_size)) {
						ws = std::wstring(buffer);
						str = std::string(ws.begin(), ws.end());
						writeFile << str << ',' << pDBBuffer->dwProcessId << ',';
						
						for (auto api_name : logs[pDBBuffer->dwProcessId]) {
							writeFile << api_name << ',';
						}
						writeFile << '\n';
					}
				}

				bool keylogger_check = isKeyLogger(pDBBuffer->dwProcessId);
				
				if ((keylogger_check == true) && (malware_check[ProcessId] == false)) {
					printf("[%d] is key logger\n", pDBBuffer->dwProcessId);

					wchar_t result[512];
					wsprintf(result, L" 악성 파일로 예상됩니다.\n 파일 이름 : %ls\n 해당 파일을 허용하시겠습니까?\n", ws.c_str());
					int input = MessageBox(NULL, result, L"Detected", MB_YESNO);
					if (input == IDNO) {
						MessageBox(NULL, L"해당 파일을 차단하였습니다.", L"차단", MB_OK);
						malware_check[ProcessId] = true;
						pid_check[ProcessId] = true;
						TerminateProcess(terminate_handle, 0);
						CloseHandle(process_handle);
						SetEvent(hEventBufferReady);
						printf("kill [%d]\n", pDBBuffer->dwProcessId);
					}
					if (input == IDYES) {
						MessageBox(NULL, L"해당 파일을 허용하였습니다.", L"허용", MB_OK);
						malware_check[ProcessId] = false;
						pid_check[ProcessId] = true;
						CloseHandle(process_handle);
						SetEvent(hEventBufferReady);
					}
				}

				CloseHandle(process_handle);
			}
			catch (int exception) {
				writeFile << "error" << '\n';
			}

			CloseHandle(terminate_handle);
			SetEvent(hEventBufferReady);
		}
	}

	writeFile.close();

	UnmapViewOfFile(pDBBuffer);
	CloseHandle(hDBWINBuffer);
	CloseHandle(hEventBufferReady);
	CloseHandle(hEventDataReady);
	//CloseHandle(hMutex);
	//hMutex = 0;

	return 0;
}