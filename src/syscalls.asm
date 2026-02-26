; syscalls.asm — x64 Direct Syscall Stubs for bigbro
;
; These stubs bypass ntdll.dll entirely. The syscall numbers
; are patched at runtime by SyscallInit() in Syscalls.cpp.
;
; NTSTATUS __fastcall SyscallStub(DWORD number, ...args)
; Each exported stub does:
;   mov r10, rcx   ; Windows syscall convention
;   mov eax, <num> ; syscall number (patched at runtime)
;   syscall
;   ret

.data
; Runtime-patchable syscall numbers (initialized by SyscallInit)
PUBLIC g_sysNtQueryInformationProcess
PUBLIC g_sysNtQueryInformationThread
PUBLIC g_sysNtGetContextThread
PUBLIC g_sysNtSetContextThread
PUBLIC g_sysNtQueryVirtualMemory
PUBLIC g_sysNtOpenThread
PUBLIC g_sysNtSuspendThread
PUBLIC g_sysNtResumeThread
PUBLIC g_sysNtClose

g_sysNtQueryInformationProcess  DWORD 0
g_sysNtQueryInformationThread   DWORD 0
g_sysNtGetContextThread         DWORD 0
g_sysNtSetContextThread         DWORD 0
g_sysNtQueryVirtualMemory       DWORD 0
g_sysNtOpenThread               DWORD 0
g_sysNtSuspendThread            DWORD 0
g_sysNtResumeThread             DWORD 0
g_sysNtClose                    DWORD 0

.code

; ============================================================
; Direct syscall stubs — each uses pre-resolved syscall numbers
; ============================================================

DirectNtQueryInformationProcess PROC
    mov     r10, rcx
    mov     eax, g_sysNtQueryInformationProcess
    syscall
    ret
DirectNtQueryInformationProcess ENDP

DirectNtQueryInformationThread PROC
    mov     r10, rcx
    mov     eax, g_sysNtQueryInformationThread
    syscall
    ret
DirectNtQueryInformationThread ENDP

DirectNtGetContextThread PROC
    mov     r10, rcx
    mov     eax, g_sysNtGetContextThread
    syscall
    ret
DirectNtGetContextThread ENDP

DirectNtSetContextThread PROC
    mov     r10, rcx
    mov     eax, g_sysNtSetContextThread
    syscall
    ret
DirectNtSetContextThread ENDP

DirectNtQueryVirtualMemory PROC
    mov     r10, rcx
    mov     eax, g_sysNtQueryVirtualMemory
    syscall
    ret
DirectNtQueryVirtualMemory ENDP

DirectNtOpenThread PROC
    mov     r10, rcx
    mov     eax, g_sysNtOpenThread
    syscall
    ret
DirectNtOpenThread ENDP

DirectNtSuspendThread PROC
    mov     r10, rcx
    mov     eax, g_sysNtSuspendThread
    syscall
    ret
DirectNtSuspendThread ENDP

DirectNtResumeThread PROC
    mov     r10, rcx
    mov     eax, g_sysNtResumeThread
    syscall
    ret
DirectNtResumeThread ENDP

DirectNtClose PROC
    mov     r10, rcx
    mov     eax, g_sysNtClose
    syscall
    ret
DirectNtClose ENDP

; ============================================================
; GENERIC SYSCALL — call ANY syscall by number
;
; C: NTSTATUS GenericSyscall(DWORD num, a1, a2, a3, a4, a5, a6)
;
; Entry (x64 fastcall):
;   RCX = syscall number
;   RDX = NT arg1     R8 = NT arg2     R9 = NT arg3
;   [RSP+28h] = arg4  [RSP+30h] = arg5 [RSP+38h] = arg6
;
; Syscall needs:
;   EAX = number      R10 = arg1       RDX = arg2
;   R8  = arg3        R9  = arg4
;   [RSP+28h] = arg5  [RSP+30h] = arg6
; ============================================================

GenericSyscall PROC
    ; Capture syscall number FIRST
    mov     eax, ecx

    ; Save arg4 before stack overwrite
    mov     r11, [rsp+28h]

    ; Shift stack args down (arg5 -> slot4, arg6 -> slot5)
    mov     r10, [rsp+30h]
    mov     [rsp+28h], r10
    mov     r10, [rsp+38h]
    mov     [rsp+30h], r10

    ; Shift register args (1 position left because 'num' was first)
    mov     r10, rdx            ; R10 = arg1
    mov     rdx, r8             ; RDX = arg2
    mov     r8, r9              ; R8  = arg3
    mov     r9, r11             ; R9  = arg4

    syscall
    ret
GenericSyscall ENDP

END
