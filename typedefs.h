#pragma once

#include <Windows.h>

typedef HMODULE(WINAPI* fnLoadLibraryW)(
	LPCWSTR lpLibFileName
);

typedef RPC_STATUS(WINAPI* fnUuidFromStringA)(
	RPC_CSTR	StringUuid,
	UUID*		Uuid
);

typedef BOOL(WINAPI* fnVirtualProtect)(
	LPVOID			lpAddress,
	SIZE_T			dwSize,
	DWORD			flNewProtect,
	PDWORD			lpflOldProtect
);

typedef NTSTATUS(NTAPI* fnNtOpenSection)(
	PHANDLE					SectionHandle,
	ACCESS_MASK				DesiredAccess,
	POBJECT_ATTRIBUTES		ObjectAttributes
);

typedef LPVOID(WINAPI* fnMapViewOfFile)(
	HANDLE		hFileMappingObject,
	DWORD		dwDesiredAccess,
	DWORD		dwFileOffsetHigh,
	DWORD		dwFileOffsetLow,
	SIZE_T		dwNumberOfBytesToMap
);

typedef BOOL(WINAPI* fnInitializeProcThreadAttributeList)(
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, 
	DWORD dwAttributeCount,
	DWORD dwFlags,
	PSIZE_T lpSize
);

typedef BOOL(WINAPI* fnUpdateProcThreadAttribute)(
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	DWORD dwFlags,
	DWORD_PTR Attribute,
	PVOID lpValue,
	SIZE_T cbSize,
	PVOID lpPreviousValue,
	PSIZE_T lpReturnSize
);

typedef BOOL(WINAPI* fnCreateProcessW)(LPCWSTR lpApplicationName, 
LPWSTR					lpCommandLine, 
LPSECURITY_ATTRIBUTES	lpProcessAttributes,
LPSECURITY_ATTRIBUTES	lpThreadAttributes,
BOOL					bInheritHandles,
DWORD					dwCreationFlags,
LPVOID					lpEnvironment,
LPCWSTR					lpCurrentDirectory,
LPSTARTUPINFOW			lpStartupInfo,
LPPROCESS_INFORMATION	lpProcessInformation
);

typedef ULONGLONG(WINAPI* fnGetTickCount64)();

typedef HANDLE(WINAPI* fnOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

typedef LRESULT(WINAPI* fnCallNextHookEx)(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam);

typedef HHOOK(WINAPI* fnSetWindowsHookExW)(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId);

typedef BOOL(WINAPI* fnGetMessageW)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);

typedef LRESULT(WINAPI* fnDefWindowProcW)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);

typedef BOOL(WINAPI* fnUnhookWindowsHookEx)(HHOOK hhk);

typedef DWORD(WINAPI* fnGetModuleFileNameW)(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);

typedef HANDLE(WINAPI* fnCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

typedef BOOL(WINAPI* fnSetFileInformationByHandle)(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize);

typedef BOOL(WINAPI* fnCloseHandle)(HANDLE hObject);
