#include <Windows.h>
#include "Structs.h"
#include "Common.h"

PTEB RtlGetThreadEnvironmentBlock() {
#ifdef _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

BOOL GetImageExportDirectory(IN PVOID pBase, OUT PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {

	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pBase + pImgNtHdrs->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL GetVxTableEntry(IN PVOID pBase, IN PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, IN PVX_TABLE_ENTRY pVxTableEntry) {

	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames	 = (PDWORD)((PBYTE)pBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfOrdinals	 = (PWORD)((PBYTE)pBase + pImageExportDirectory->AddressOfNameOrdinals);
	
	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {

		PCHAR pFunctionName = (PCHAR)((PBYTE)pBase + pdwAddressOfNames[cx]);

		PVOID pFunctionAddress = (PBYTE)pBase + pdwAddressOfFunctions[pwAddressOfOrdinals[cx]];

		if (HASHA(pFunctionName) == pVxTableEntry->uHash) {
			pVxTableEntry->pAddress = pFunctionAddress;

			WORD cw = 0;
			
			while (TRUE) {

				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;

				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE High = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE Low  = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (High << 8) | Low;
					break;
				}

				cw++;
			};
		}
	}

	if (pVxTableEntry->wSystemCall != NULL)
		return TRUE;
	else
		return FALSE;
}