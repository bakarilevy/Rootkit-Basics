// Injector for Process Hider, defines entry point of application

#include <string>
#include <vector>
#include <Psapi.h>
#include <Windows.h>
#include <Tlhelp32.h>

# pragma comment (lib, "psapi.lib")

using namespace std;

vector<int> pids;
vector<string> pnames;

void CleanStatic(HWND h, int id)
{
	SetDlgItemText(h, id, "");
}

void AddStaticText(HWND h, int id, string text)
{
	int len = GetWindowTextLength(GetDlgItem(h, id));
	if (len != 0)
	{
		char* mem = (char*)malloc(len);
		memset(mem, 0, len);
		GetDlgItemText(h, id, mem, len);
		string str = mem;
		free(mem);
		str += text;
		SetDlgItemText(h, id, str.c_str());
	}
	else
	{
		SetDlgItemText(h, id, text.c_str());
	}
}

void ProcessList(HWND hwnd, int id)
{
	PROCESSENTRY32 lppe32;
	HANDLE hSnapshot;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	lppe32.dwSize = sizeof(PROCESSENTRY32);
	pids.clear();
	pnames.clear();

	Process32First(hSnapshot, &lppe32);
	do
	{
		pids.push_back(lppe32.th32ProcessID);
		pnames.push_back(lppe32.szExeFile);
	}
	while (Process32Next(hSnapshot, &lppe32));
	CloseHandle(hSnapshot);

	int size = SendDlgItemMessage(hwnd, id, CB_GETCOUNT, 0, (LPARAM)0);
	int i = 0;
	while (i < size)
	{
		SendDlgItemMessage(hwnd, id, CB_DELETESTRING, 0, (LPARAM)0);
		i++;
	}

	i = 0;
	size = pids.size();
	char tmp[260];
	while (i < size)
	{
		memset(tmp, 0, 260);
		sprintf(tmp, "%s(%d)", pnames[i].c_str(), pids[i]);
		SendDlgItemMessage(hwnd, id, CB_INSERTSTRING, i, (LPARAM)tmp);
		i++;
	}
	SendDlgItemMessage(hwnd, id, CB_SETCURSEL, 0, (LPARAM)0);
}

BOOL CALLBACK DlgProc(HWND hwnd, UINT Msg, WPARAM wParam, LPARAM lparam)
{
	switch (Msg)
	{
	case WM_INITDIALOG:
	{
		ProcessList(hwnd, 1003);
	}
	break;
	case WM_COMMAND:
	{
		if (LOWORD(wParam) == 1008) // Open
		{
			OPENFILENAME ofn;
			char sNazwaPliku[MAX_PATH] = "";

			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(ofn);
			ofn.lpstrFilter = "Biblioteki dll\0*.dll\0\0";
			ofn.nMaxFile = MAX_PATH;
			ofn.lpstrFile = sNazwaPliku;
			ofn.lpstrDefExt = "dll";
			ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

			if (GetOpenFileName(&ofn))
			{
				SetDlgItemText(hwnd, 1006, sNazwaPliku);
			}
		}
		else if (LOWORD(wParam) == 1005) //refresh
		{
			ProcessList(hwnd, 1003);
		}
		else if (LOWORD(wParam) == 1011) //inject
		{
			char dll[260];
			GetDlgItemText(hwnd, 1006, dll, 260);
			int sel = SendDlgItemMessage(hwnd, 1003, CB_GETCURSEL, 0, 0);
			CleanStatic(hwnd, 1010);
			char tmp[260];
			memset(tmp, 0, 260);
			sprintf(tmp, "Opening process: %s(%d)\r\n", pnames[sel].c_str(), pids[sel]);
			AddStaticText(hwnd, 1010, tmp);
			HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pids[sel]);
			if (hProc)
			{
				AddStaticText(hwnd, 1010, "OpenProcess success\r\n");
			}
			else
			{
				AddStaticText(hwnd, 1010, "OpenProcess failed\r\n");
				return 0;
			}
			LPVOID Vmem = VirtualAllocEx(hProc, 0, strlen(dll) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			DWORD wrt;
			WriteProcessMemory(hProc, Vmem, dll, strlen(dll), (SIZE_T*)&wrt);
			sprintf(tmp, "Wrote %d bytes\r\n", wrt);
			AddStaticText(hwnd, 1010, tmp);
			FARPROC LoadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
			HANDLE h = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLib, Vmem, 0, 0);
			if (h)
			{
				AddStaticText(hwnd, 1010, "CreateRemoteThread succedded\r\n");
			}
			WaitForSingleObject(h, INFINITE);
			DWORD exit;
			GetExitCodeThread(h, &exit);
			sprintf(tmp, "DLL loaded to 0x%.8x\r\n", exit);
			AddStaticText(hwnd, 1010, tmp);
		}
	}
	}
}