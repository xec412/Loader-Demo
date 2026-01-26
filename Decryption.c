#include "ChaCha.h"
#include "Common.h"
#include <Windows.h>

BOOL ChaCha20_Decrypt(IN PBYTE Data, IN SIZE_T Size, IN PBYTE Key, IN PBYTE Iv) {

	if (!Data || !Key || !Iv || Size == 0)
		return FALSE;

	return chacha_memory(
		Key, CHACHA_KEYLEN,
		20,
		Iv,  CHACHA_IVLEN,
		1,
		Data,
		(unsigned long)Size,
		Data
	) == CRYPT_OK;
}