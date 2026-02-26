; retpoline.asm — x64 MASM Retpoline Thunks for adheslime
; Mitigates Spectre v2 (Branch Target Injection) on indirect calls.
;
; Usage from C++:
;   extern "C" void retpoline_call_rax();
;   // Load target into RAX, then call retpoline_call_rax
;
; How it works:
;   1. CALL pushes the address of .inner (the speculation trap) onto the stack
;   2. .setup overwrites that return address with RAX (the real target)
;   3. RET pops the real target and jumps to it (architecturally correct)
;   4. Speculative execution follows the original prediction into .inner,
;      which is an infinite PAUSE+LFENCE loop — no useful gadgets leak.

.code

; ============================================================
; retpoline_call_rax — indirect CALL through RAX via retpoline
; ============================================================
retpoline_call_rax PROC
    call    retpoline_setup_rax
retpoline_inner_rax:
    pause
    lfence
    jmp     retpoline_inner_rax
retpoline_setup_rax:
    mov     [rsp], rax
    ret
retpoline_call_rax ENDP

; ============================================================
; retpoline_jmp_rax — indirect JMP through RAX via retpoline
; (for tail-call scenarios)
; ============================================================
retpoline_jmp_rax PROC
    call    retpoline_setup_jmp_rax
retpoline_inner_jmp_rax:
    pause
    lfence
    jmp     retpoline_inner_jmp_rax
retpoline_setup_jmp_rax:
    mov     [rsp], rax
    ret
retpoline_jmp_rax ENDP

END
