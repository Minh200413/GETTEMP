section .text
	global main
mov rcx, 0             ; process handle = NULL (current process)
mov edx, 0             ; exit status 0
mov eax, 0x2C          ; syscall number của NtTerminateProcess trên Win10 x64 (cần check lại)
syscall