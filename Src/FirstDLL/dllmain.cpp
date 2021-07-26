// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        if (hook_mouse_callback::instance()->attach(hModule)) {
            MessageBox(nullptr, L"hook success", L"analog_note", MB_OK);
        }
        else {
            MessageBox(nullptr, L"hook success", L"analog_note", MB_OK);
        }
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        if (hook_mouse_callback::instance()->attached()) {
            hook_mouse_callback::instance()->detach();
        }
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}