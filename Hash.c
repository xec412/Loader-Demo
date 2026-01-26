#include <Windows.h>
#include "Common.h"

UINT32 HashStringJoaa32BitA(_In_ PCHAR Str) {

	SIZE_T Index  = 0;
	UINT32 Hash   = 0;
	SIZE_T Length = lstrlenA(Str);

	while (Index != Length) {

		Hash += Str[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

UINT32 HashStringJoaa32BitW(_In_ PWCHAR Str) {

	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenW(Str);

	while (Index != Length) {

		Hash += Str[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}