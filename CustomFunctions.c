#include <Windows.h>
#include "Debug.h"
#include "Structs.h"
#include "Common.h"

#pragma function(memcpy)

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

#ifdef DEBUG
	PRINTA("[*] GetProcAddressH called with Hash: 0x%0.8X\n", dwApiNameHash);
#endif

	if (hModule == NULL || dwApiNameHash == NULL)
		return NULL;

	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD pdwAddressOfFunctions = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PWORD  pwAddressOfOrdinals = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

		PCHAR pFunctionName = (PCHAR)(pBase + pdwAddressOfNames[i]);
		PVOID pFunctionAddress = (PVOID)(pBase + pdwAddressOfFunctions[pwAddressOfOrdinals[i]]);

		if (dwApiNameHash == HASHA(pFunctionName)) {
#ifdef DEBUG
			PRINTA("[+] Function found: %s at 0x%p\n", pFunctionName, pFunctionAddress);
#endif
			return (FARPROC)pFunctionAddress;
		}
	}

#ifdef DEBUG
	PRINTA("[!] Function not found for hash: 0x%0.8X\n", dwApiNameHash);
#endif
	return NULL;
}


HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {
	if (dwModuleNameHash == NULL)
		return NULL;

	PPEB pPeb = NULL;
#ifdef _WIN64
	pPeb = (PEB*)(__readgsqword(0x60));
#else
	pPeb = (PEB*)(__readfsdword(0x30));
#endif

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->LoaderData);
	PLIST_ENTRY pListHead = &pLdr->InLoadOrderModuleList;
	PLIST_ENTRY pListEntry = pListHead->Flink;

	while (pListEntry != pListHead) {
		PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)pListEntry;

		if (pDte->BaseDllName.Buffer != NULL) {
			CHAR UpperCaseDllName[MAX_PATH];
			DWORD i = 0;

			while (i < pDte->BaseDllName.Length / sizeof(WCHAR) && i < MAX_PATH - 1) {
				WCHAR wChar = pDte->BaseDllName.Buffer[i];
				UpperCaseDllName[i] = (CHAR)_toUpper((CHAR)wChar);
				i++;
			}
			UpperCaseDllName[i] = '\0';

#ifdef DEBUG
			PRINTA("[*] Module: %s | Hash: 0x%0.8X\n", UpperCaseDllName, HASHA(UpperCaseDllName));
#endif

			if (HASHA(UpperCaseDllName) == dwModuleNameHash) {
				return (HMODULE)pDte->DllBase;
			}
		}
		pListEntry = pListEntry->Flink;
	}

#ifdef DEBUG
	PRINTA("[!] Failed to find module with hash: 0x%0.8X\n", dwModuleNameHash);
#endif
	return NULL;
}

PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size)
{
	for (volatile int i = 0; i < Size; i++) {
		((BYTE*)Destination)[i] = ((BYTE*)Source)[i];
	}
	return Destination;
}

extern void* __cdecl memset(void*, int, size_t);
#pragma intrinsic(memset)
#pragma function(memset)

void* __cdecl memset(void* Destination, int Value, size_t Size) {
	unsigned char* p = (unsigned char*)Destination;
	while (Size > 0) {
		*p = (unsigned char)Value;
		p++;
		Size--;
	}
	return Destination;
}


CHAR _toUpper(CHAR C)
{
	if (C >= 'a' && C <= 'z')
		return C - 'a' + 'A';

	return C;
}


void* memcpy(void* dst, const void* src, size_t size)
{
	BYTE* d = (BYTE*)dst;
	const BYTE* s = (const BYTE*)src;

	while (size--)
		*d++ = *s++;

	return dst;
}