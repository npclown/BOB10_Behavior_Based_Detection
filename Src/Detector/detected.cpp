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
#include "Scenarios.h"

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

typedef struct index_of_scenario {
	int idx1 = 0; int idx2 = 0; int idx3 = 0;
}index_of_scenario;

typedef struct bool_of_malware_check {
	bool check1 = false; bool check2 = false; bool check3 = false;
}bool_of_malware_check;

index_of_scenario check_index_of_scenario[32769]; // index of checking on scenarios
bool check_by_user[32769]; // if it is true, then it must be malware why user checking
bool_of_malware_check malware_check[32769]; // if it has one or more true, then it will be malware by scenario
int check_count[32769]; 
// if user click NO on message box, then other or same scenario will be call later, 
// so if user click NO 3 times, then it must be not malware because of user clicking

std::string logs[32769]; // 0 ~ 32768 = pid, string = called api
std::string detach = "DETACH\n";
std::string attach = "ATTACH\n";

std::vector<std::string> scenario1 = Scenario1();
std::vector<std::string> scenario2 = Scenario2();
std::vector<std::string> scenario3 = Scenario3();

int scenario1_size = scenario1.size();
int scenario2_size = scenario2.size();
int scenario3_size = scenario3.size();

void Get_API(DWORD pid, char* data)
{
	if (data == NULL)
		return;
	
	std::string* str_data = new std::string("");
	std::string* str_pid = new std::string("");

	*str_data = (std::string)data;
	*str_pid = std::to_string((int)pid);

	if (*str_pid == (*str_data).substr(0, (*str_pid).size())) {
		std::string api_name = (*str_data).substr((*str_pid).size() + 1);
		logs[(int)pid] = api_name;
	}
	else {
		if ((*str_data).substr((*str_data).size() - 7) == detach) {
			logs[(int)pid].clear();
			check_index_of_scenario[(int)pid] = { 0,0,0 };
			check_by_user[(int)pid] = false;
			malware_check[(int)pid] = { false, false, false };
		}
	}

	delete str_data;
	delete str_pid;

	return;
}

int KeyLogger_check(DWORD pid)
{
	// 0 : no keylogger, 1 : scenario1, 2 : scenario2, 3 : scenario3
	// probability : scenario1 > scenario2 > scenario3

	bool check1 = malware_check[(int)pid].check1;
	bool check2 = malware_check[(int)pid].check2;
	bool check3 = malware_check[(int)pid].check3;

	if (check1 == false && check2 == false && check3 == false)
		return 0;
	else if (check1 == true)
		return 1;
	else if (check1 == false && check2 == true)
		return 2;
	else if (check1 == false && check2 == false && check3 == true)
		return 3;
}

void MessageBox_and_KeyLogger_check(DWORD pid, int isKeyLogger, std::wstring ws) {

	wchar_t result[512];
	std::wstring probability;

	if (isKeyLogger == 1) {
		probability = std::wstring(L"90%");
	}
	else if (isKeyLogger == 2) {
		probability = std::wstring(L"70%");
	}
	else if (isKeyLogger == 3) {
		probability = std::wstring(L"50%");
	}
	else
		return;

	printf("[%d] is key logger\n", pid);

	wsprintf(result, L" 악성 파일로 예상됩니다. (확률 : %ls)\n 파일 이름 : %ls \n 해당 파일을 허용하시겠습니까?\n ", probability.c_str(), ws.c_str());

	int input = MessageBox(NULL, result, L"Detected", MB_YESNO);
	int pid_ = (int)pid;

	if (input == IDNO) {
		MessageBox(NULL, L"해당 파일을 차단하였습니다.\n", L"차단", MB_OK);
		check_index_of_scenario[pid_] = { 0, 0, 0 };
		check_by_user[pid_] = true;
		malware_check[pid_] = { false, false, false };
		check_count[pid_] = 0;
		logs[pid_] = "";
	}
	if (input == IDYES) {
		MessageBox(NULL, L"해당 파일을 허용하였습니다.\n", L"허용", MB_OK);
		if (malware_check[pid_].check1 == true) {
			malware_check[pid_].check1 = false;
			check_index_of_scenario[pid_].idx1 = 0;
		}
		if (malware_check[pid_].check2 == true) {
			malware_check[pid_].check2 = false;
			check_index_of_scenario[pid_].idx2 = 0;
		}
		if (malware_check[pid_].check3 == true) {
			malware_check[pid_].check3 = false;
			check_index_of_scenario[pid_].idx3 = 0;
		}
		check_by_user[pid_] = false;
		check_count[pid_]++;
	}
	return;
}

int _tmain(int argc, _TCHAR* argv[])
{

	DWORD errorCode = 0;

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

	while (isRunning)
	{
		DWORD mb = WaitForSingleObject(hEventDataReady, INFINITE);

		if (mb == WAIT_OBJECT_0) {

			int pid = pDBBuffer->dwProcessId;
			
			if (check_count[pid] >= 3) // no malware by user 3 times check
				continue;

			if (check_by_user[pid] == true) { // malware
				HANDLE terminate_handle = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, TRUE, pDBBuffer->dwProcessId);
				try {
					TerminateProcess(terminate_handle, 0);
					printf("[%d] terminate\n", pid);
					CloseHandle(terminate_handle);
					SetEvent(hEventBufferReady);
				}
				catch(int exception){
					printf("kill error!!!\n");
					CloseHandle(terminate_handle);
					SetEvent(hEventBufferReady);
				}
				continue;
			}
			
			try {
				HANDLE process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pDBBuffer->dwProcessId);

				Get_API(pDBBuffer->dwProcessId, pDBBuffer->data);
				//printf("[%d] %s\n", pDBBuffer->dwProcessId, pDBBuffer->data);
				printf("[%d] %s\n", pid, logs[pid].c_str());

				wchar_t buffer[MAX_PATH] = {};
				DWORD buffer_size = MAX_PATH;
				std::wstring ws;
				std::string str;
				
				if (process_handle) {
					
					if (QueryFullProcessImageNameW(process_handle, 0, buffer, &buffer_size)) {
						ws = std::wstring(buffer);
						str = std::string(ws.begin(), ws.end());

						writeFile << str << ',' << pDBBuffer->dwProcessId << ',';
						writeFile << logs[pid] << '\n';
					}
				}

				int idx_scenario1 = check_index_of_scenario[pid].idx1;
				int idx_scenario2 = check_index_of_scenario[pid].idx2;
				int idx_scenario3 = check_index_of_scenario[pid].idx3;

				std::string called_api = logs[pid];

				// index check
				if (scenario1[idx_scenario1] == called_api) {
					idx_scenario1++;
				}
				if (scenario2[idx_scenario2] == called_api) {
					idx_scenario2++;
				}
				if (scenario3[idx_scenario3] == called_api) {
					idx_scenario3++;
				}

				// malware check
				if (idx_scenario1 == scenario1_size) {
					malware_check[pid].check1 = true;
				}
				if (idx_scenario2 == scenario2_size) {
					malware_check[pid].check2 = true;
				}
				if (idx_scenario3 == scenario3_size) {
					malware_check[pid].check3 = true;
				}

				check_index_of_scenario[pid] = { idx_scenario1, idx_scenario2, idx_scenario3 };

				int isKeyLogger = KeyLogger_check(pDBBuffer->dwProcessId);

				if (isKeyLogger == 0) {
					// no key logger
					CloseHandle(process_handle);
				}
				else {
					MessageBox_and_KeyLogger_check(pDBBuffer->dwProcessId, isKeyLogger, ws);
					CloseHandle(process_handle);
				}
			}
			catch (int exception) {
				writeFile << "error" << '\n';
			}

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