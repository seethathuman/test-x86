; opcode_test.asm
; Test specific x86 instructions for emulator validation

org 0x100 ; COM file entry point

start:
    call test_all

    ; Wait for keypress before exit
    mov ah, 0x00
    int 0x16

    ret ; opcode C3

; -----------------------
test_all:
    call test_xor
    call test_push_pop
    call test_cmp
    call test_mov
    call test_jumps
    call test_segment
    call test_operand_prefix
    call test_lodsb
    call test_les
    call test_call_ret
    call test_nop_cli_hlt
    ret

; -----------------------
test_xor:
    mov al, 0xAA
    xor al, al         ; opcode 33/83 (xor reg, reg/immed)
    cmp al, 0
    jne .fail
    ret
.fail:
    mov si, msg_xor
    call print_str
    ret

; -----------------------
test_push_pop:
    xor ax, ax
    mov ax, 0x1234
    push ax            ; 50
    xor ax, ax
    pop ax             ; 58
    cmp ax, 0x1234
    jne .fail
    ret
.fail:
    mov si, msg_push_pop
    call print_str
    ret

; -----------------------
test_cmp:
    mov al, 5
    cmp al, 5          ; 3C
    jne .fail
    mov ax, 5
    cmp ax, 5          ; 3D
    jne .fail
    ret
.fail:
    mov si, msg_cmp
    call print_str
    ret

; -----------------------
test_mov:
    mov al, 0x42       ; B0
    mov bl, al         ; 88 / 89
    cmp bl, 0x42
    jne .fail

    mov ax, cs
    mov ds, ax         ; 8E
    ret
.fail:
    mov si, msg_mov
    call print_str
    ret

; -----------------------
test_jumps:
    mov al, 1
    cmp al, 1
    jnz .fail_jnz      ; 75
    jnc .ok_jnc        ; 73
.fail_jnz:
    mov si, msg_jnz
    call print_str
    ret
.ok_jnc:
    ret

; -----------------------
test_segment:
    mov ax, 0
    mov es, ax
    mov bx, 0
    mov al, 0xAA
    mov [es:bx], al    ; 36 prefix would allow segment override
    mov al, 0
    mov al, [es:bx]
    cmp al, 0xAA
    jne .fail
    ret
.fail:
    mov si, msg_seg
    call print_str
    ret

; -----------------------
test_operand_prefix:
    ; test 66h prefix for 16-bit ADD
    mov ax, 1
    add ax, 1          ; 66 83 C0 01
    cmp ax, 2
    jne .fail
    ret
.fail:
    mov si, msg_op_pre
    call print_str
    ret

; -----------------------
test_lodsb:
    mov si, data_byte
    lodsb              ; AC
    cmp al, 0x55
    jne .fail
    ret
.fail:
    mov si, msg_lodsb
    call print_str
    ret

; -----------------------
test_les:
    mov word [ptr], 0x0010
    mov word [ptr+2], 0x9000
    les bx, [ptr]      ; C4
    cmp bx, 0x0010
    jne .fail
    mov bx, es
    cmp bx, 0x9000
    jne .fail
    ret
.fail:
    mov si, msg_les
    call print_str
    ret

; -----------------------
test_call_ret:
    call .test_call    ; E8
    cmp ax, 0xBEEF
    jne .fail
    ret
.test_call:
    mov ax, 0xBEEF
    ret
.fail:
    mov si, msg_call
    call print_str
    ret

; -----------------------
test_nop_cli_hlt:
    nop                ; 90
    cli                ; FA
    ; Don't actually halt emulator
    ; hlt               ; F4 -- HLT is dangerous to test here
    ret

; -----------------------
print_str:
    ; DS:SI -> null-terminated string
.print_loop:
    lodsb
    or al, al
    jz .done

    mov ah, 0x0E
    int 0x10
    jmp .print_loop
.done:
    ret

; -----------------------
data_byte db 0x55

ptr dw 0, 0

; -----------------------
msg_xor       db 'XOR FAIL', 0
msg_push_pop  db 'PUSH/POP FAIL', 0
msg_cmp       db 'CMP FAIL', 0
msg_mov       db 'MOV FAIL', 0
msg_jnz       db 'JNZ/JNC FAIL', 0
msg_seg       db 'SEGMENT PREFIX FAIL', 0
msg_op_pre    db 'OPERAND PREFIX FAIL', 0
msg_lodsb     db 'LODSB FAIL', 0
msg_les       db 'LES FAIL', 0
msg_call      db 'CALL/RET FAIL', 0

msg_valid_xor       db 'XOR SUCCESS', 0
msg_valid_push_pop  db 'PUSH/POP SUCCESS', 0
msg_valid_cmp       db 'CMP SUCCESS', 0
msg_valid_mov       db 'MOV SUCCESS', 0
msg_valid_jnz       db 'JNZ/JNC SUCCESS', 0
msg_valid_seg       db 'SEGMENT PREFIX SUCCESS', 0
msg_valid_op_pre    db 'OPERAND PREFIX SUCCESS', 0
msg_valid_lodsb     db 'LODSB SUCCESS', 0
msg_valid_les       db 'LES SUCCESS', 0
msg_valid_call      db 'CALL/RET SUCCESS', 0
