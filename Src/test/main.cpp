#include <Windows.h>
#include <stdio.h>

void DebugLog(const char* format, ...)
{
    va_list vl;
    char szLog[512] = { 0, };

    va_start(vl, format);
    wvsprintfA(szLog, format, vl);
    va_end(vl);

    OutputDebugStringA(szLog);
}

int main() {
    printf("SN1\n");
    DebugLog("%d %ls", GetCurrentProcessId(), L"OpenProcess");
    DebugLog("%d %ls", GetCurrentProcessId(), L"CreateThread");
    DebugLog("%d %ls", GetCurrentProcessId(), L"SuspendThread");
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetTickCount");
    DebugLog("%d %ls", GetCurrentProcessId(), L"GetLocalTime");
    DebugLog("%d %ls", GetCurrentProcessId(), L"Sleep");
    DebugLog("%d %ls", GetCurrentProcessId(), L"ResumeThread");
    DebugLog("%d %ls", GetCurrentProcessId(), L"CreateFileW");
    DebugLog("%d %ls", GetCurrentProcessId(), L"FindResourceW");
    DebugLog("%d %ls", GetCurrentProcessId(), L"WriteFile");
    DebugLog("%d %ls", GetCurrentProcessId(), L"SetEndOfFile");
    DebugLog("%d %ls", GetCurrentProcessId(), L"SetFilePointer");
    //sn1 sn2 sn3
    //keylogger 
}