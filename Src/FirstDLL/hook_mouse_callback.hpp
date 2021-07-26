#pragma once
#include "pch.h"
#define WIN32_LEAN_AND_MEAN             // 거의 사용되지 않는 내용을 Windows 헤더에서 제외합니다.
// Windows 헤더 파일
#include <windows.h>

class hook_mouse_callback {
private:
	static hook_mouse_callback* volatile _instance;
	static std::mutex _mutex;
	hook_mouse_callback();
	hook_mouse_callback(const hook_mouse_callback& other) {};
	~hook_mouse_callback() {};
public:
	static hook_mouse_callback* volatile instance() {
		if (_instance == nullptr) {
			std::lock_guard<std::mutex> lock(_mutex);
			if (_instance == nullptr) {
				_instance = new hook_mouse_callback();
			}
			atexit(_finalize);
		}
		return _instance;
	}
	static void _finalize() {
		hook_mouse_callback::instance()->finalize();
		if (_instance) {
			delete _instance;
		}
	}
public:
	void finalize() {
	}
	bool attached() const {
		return _hook != nullptr;
	}
	bool attach(
		__in HINSTANCE module
	) {
		_hook = SetWindowsHookExW(WH_MOUSE_LL, proxy_function, module, 0);
		return _hook != nullptr;
	}
	void detach() {
		if (attached()) {
			UnhookWindowsHookEx(_hook);
		}
	}
	static LRESULT __stdcall proxy_function(
		__in int code,
		__in WPARAM wparam,
		__in LPARAM lparam
	) {
		return hook_mouse_callback::instance()->new_function(
			code,
			wparam,
			lparam);
	}
	LRESULT new_function(
		__in int code,
		__in WPARAM wparam,
		__in LPARAM lparam
	);
private:
	HHOOK _hook;
};