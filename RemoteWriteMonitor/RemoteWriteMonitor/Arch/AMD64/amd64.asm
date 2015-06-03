; Copyright (c) 2015, tandasat. All rights reserved.
; Use of this source code is governed by a MIT-style license that can be
; found in the LICENSE file.

;
; This module implements stub functions implementing overwritten part of the
; hooked function and providing accesses to the those original functionalities.
;
; Those functions are taken from ntoskrnl.exe and used only on x64 build.
;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
.CONST


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
.DATA


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
.CODE


; Implements jump to an arbitrary location without modifying registers.
; 0ffffffffffffffffh is used as a mark to be replaced with a correct address.
JMP_TEMPLATE MACRO 
    nop     ; This is space for implanting int 3 for debugging
    jmp     qword ptr [jmp_address]
jmp_address:
    dq      0ffffffffffffffffh
ENDM


; NtMapViewOfSection for Windows 8.1 and 7 (both are identical)
AsmNtMapViewOfSection_Win81_7 PROC
    mov     qword ptr [rsp+10h], rbx
    mov     qword ptr [rsp+18h], rsi
    mov     qword ptr [rsp+8h], rcx
    push    rdi
    JMP_TEMPLATE 
AsmNtMapViewOfSection_Win81_7 ENDP
AsmNtMapViewOfSection_Win81_7End PROC
    nop
AsmNtMapViewOfSection_Win81_7End ENDP


; NtWriteVirtualMemory for Win 8.1
AsmNtWriteVirtualMemory_Win81 PROC
    sub     rsp, 38h
    mov     rax, [rsp+60h]
    mov     dword ptr [rsp+28h], 20h 
    mov     [rsp+20h], rax 
    JMP_TEMPLATE 
AsmNtWriteVirtualMemory_Win81 ENDP
AsmNtWriteVirtualMemory_Win81End PROC
    nop
AsmNtWriteVirtualMemory_Win81End ENDP


; NtWriteVirtualMemory for Win 7
AsmNtWriteVirtualMemory_Win7 PROC
    mov     rax, rsp
    mov     qword ptr [rax+8h], rbx
    mov     qword ptr [rax+10h], rsi
    mov     qword ptr [rax+18h], rdi
    mov     qword ptr [rax+20h], r12
    JMP_TEMPLATE 
AsmNtWriteVirtualMemory_Win7 ENDP
AsmNtWriteVirtualMemory_Win7End PROC
    nop
AsmNtWriteVirtualMemory_Win7End ENDP


END
