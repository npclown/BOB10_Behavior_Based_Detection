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
std::map<DWORD, std::set<std::string>> logs;
std::string detach = "DETACH";
std::string attach = "ATTACH";

void Get_API(DWORD pid, char* data)
{
	if (data == NULL)
		return;
	
	std::string* str_data = new std::string("");
	std::string* str_pid = new std::string("");

	*str_data = (std::string)data;
	*str_pid = std::to_string((int)pid);

	if (*str_pid == (*str_data).substr(0, (*str_pid).size())) {
		logs[pid].insert((*str_data).substr((*str_pid).size() + 1));
	}
	else {
		if ((*str_data).substr((*str_data).size() - 6) == detach) {
			logs[pid].clear();
		}
	}

	delete str_data;
	delete str_pid;

	return;
}
// 여기까지

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

	while (isRunning)
	{

		DWORD mb = WaitForSingleObject(hEventDataReady, INFINITE);

		if (mb == WAIT_OBJECT_0) {

			printf("[%d] %s\n", pDBBuffer->dwProcessId, pDBBuffer->data);
			Get_API(pDBBuffer->dwProcessId, pDBBuffer->data);

			try {
				HANDLE process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pDBBuffer->dwProcessId);
				if (process_handle) {
					wchar_t buffer[MAX_PATH] = {};
					DWORD buffer_size = MAX_PATH;

					if (QueryFullProcessImageNameW(process_handle, 0, buffer, &buffer_size)) {
						std::wstring ws(buffer);
						std::string str(ws.begin(), ws.end());

						writeFile << str << ',' << pDBBuffer->dwProcessId << ',';
						
						for (auto api_name : logs[pDBBuffer->dwProcessId]) {
							writeFile << api_name << ',';
						}
						writeFile << '\n';
					}
				}
				CloseHandle(process_handle);
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