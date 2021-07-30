// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBox(nullptr, L"DLL_PROCESS_ATTACH 공격 성공", L"ATTCK", MB_OK);
        break;
    case DLL_THREAD_ATTACH:
        MessageBox(nullptr, L"DLL_THREAD_ATTACH 공격 성공", L"ATTCK", MB_OK);
        break;
    case DLL_THREAD_DETACH:
        MessageBox(nullptr, L"DLL_THREAD_DETACH 공격 성공", L"ATTCK", MB_OK);
        break;
    case DLL_PROCESS_DETACH:
        MessageBox(nullptr, L"DLL_PROCESS_DETACH 공격 성공", L"ATTCK", MB_OK);
        break;
    }
    return TRUE;
}

