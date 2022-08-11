Set up the project in Visual Studio:

Set the compiler mode from debug to release
Go to settings, advanced, change the Character Set to Use Multi Byte Character Set
Under C/C++ select code generation and select Multi-Threaded MT option
Select Precompiled Headers and select not using precompiled headers

In the case of an executable compiled in Visual Studio, in a debugger the program prologue will always
look the same.

Shellcode to exit process

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

"\x6A\x00\x6A\xFF\xE8\x01\x00\x00\x00\xC3\xB8\x01\x01\x00\x00\xE8\x00\x00\x00\x00\x8B\xD4\x0F\x34\xC3"

0x20 is 32 bytes in Hex notation