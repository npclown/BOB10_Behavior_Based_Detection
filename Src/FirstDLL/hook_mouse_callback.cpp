#include "pch.h"

hook_mouse_callback* volatile hook_mouse_callback::_instance = nullptr;
std::mutex hook_mouse_callback::_mutex;
hook_mouse_callback::hook_mouse_callback() :
	_hook(nullptr) {
}
LRESULT hook_mouse_callback::new_function(
	__in int code,
	__in WPARAM wparam,
	__in LPARAM lparam
) {
	do {
		if (code < HC_ACTION) {
			break;
		}
		MOUSEHOOKSTRUCT* mouse_param = (MOUSEHOOKSTRUCT*)lparam;
		if (wparam == WM_LBUTTONDOWN) {
			OutputDebugString(L"mouse left button down");
		}
		else if (wparam == WM_LBUTTONUP) {
			OutputDebugString(L"mouse left button up");
		}
		if (wparam == WM_RBUTTONDOWN) {
			OutputDebugString(L"mouse right button down");
		}
		else if (wparam == WM_RBUTTONUP) {
			OutputDebugString(L"mouse right button up");
		}
		else if (wparam == WM_MOUSEMOVE) {
			//OutputDebugString(L"mouse move");
		}
		else {
			break;
		}
	} while (false);
	return ::CallNextHookEx(_hook, code, wparam, lparam);
}