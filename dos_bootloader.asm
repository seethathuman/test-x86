; Bootloader decompiled from binary
; Comments: [address] and instruction explanation

org 0x7C00

start:
    jmp short main         ; [0x7C00] Jump to main code
    nop                    ; [0x7C02] No operation

; --- OEM/Filesystem/Boot sector info ---
    db 0x29,0x39,0x45,0x2D,0x3F,0x49,0x48,0x43 ; [0x7C03] Disk ID / OEM name
    db 0x00,0x02,0x01,0x01,0x00,0x02,0xE0,0x00 ; [0x7C0B] BPB: bytes/sector, sectors/cluster, reserved, etc.
    db 0x40,0x0B,0xF0,0x09,0x00,0x12,0x00,0x02
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00

main:
    cli                    ; [0x7C3A] Disable interrupts
    xor bp, bp             ; [0x7C3B] BP = 0
    mov ax, 0x07C0         ; [0x7C3D] AX = 0x07C0
    mov ds, ax             ; [0x7C40] DS = 0x07C0
    les bx, [0x001C]       ; [0x7C42] Load ES:BX from [0x1C]
    mov [0x01FD], dl       ; [0x7C46] Store boot drive
    or dl, dl              ; [0x7C4A] Set flags for boot drive
    jnz skip_reset         ; [0x7C4C] If not zero, skip
    mov [0x0024], bx       ; [0x7C4E] Store BX
    mov [0x0026], es       ; [0x7C52] Store ES
skip_reset:
    mov es, bp             ; [0x7C56] ES = 0
    mov ss, bp             ; [0x7C58] SS = 0
    mov sp, 0x7C00         ; [0x7C5A] SP = 0x7C00
    cld                    ; [0x7C5D] Clear direction flag
    push ds                ; [0x7C5E] Save DS
    push si                ; [0x7C5F] Save SI
    push ds                ; [0x7C61] Save DS
    push ax                ; [0x7C62] Save AX
    mov di, 0x7C2A         ; [0x7C64] DI = 0x7C2A
    mov cx, 0x000B         ; [0x7C67] CX = 11
    rep movsb              ; [0x7C6A] Copy 11 bytes
    pop ds                 ; [0x7C6C] Restore DS
    mov byte [0x002E], 0x0F ; [0x7C6D] Set flag/marker
    mov di, 0x0078         ; [0x7C72] DI = 0x78
    mov ax, 0x7C2A         ; [0x7C75] AX = 0x7C2A
    stosw                  ; [0x7C78] Store word at ES:DI, DI+=2
    xchg ax, cx            ; [0x7C79] Swap AX, CX
    stosw                  ; [0x7C7A] Store word at ES:DI, DI+=2
    sti                    ; [0x7C7B] Enable interrupts
    mov dl, [0x01FD]       ; [0x7C7C] Restore boot drive
    int 0x13               ; [0x7C80] BIOS disk service
    mov al, [0x0010]       ; [0x7C82] Load value
    cbw                    ; [0x7C85] Sign-extend AL to AX
    mul word [0x0016]      ; [0x7C86] Multiply AX by [0x16]
    add ax, [0x000E]       ; [0x7C8A] Add [0xE] to AX
    call near next1        ; [0x7C8D] Call next1
    call near next2        ; [0x7C90] Call next2
    mov bx, 0x0500         ; [0x7C93] BX = 0x500
    push bx                ; [0x7C96] Push BX
    call near next3        ; [0x7C97] Call next3
    pop di                 ; [0x7C9A] Pop to DI
    mov si, 0x0171         ; [0x7C9B] SI = 0x171
    mov cx, 0x000B         ; [0x7C9E] CX = 11
    nop                    ; [0x7CA1] No operation
    repe cmpsb             ; [0x7CA2] Compare strings
    jne not_equal          ; [0x7CA4] Jump if not equal
    add di, 0x15           ; [0x7CA6] DI += 0x15
    mov cl, 0x0B           ; [0x7CA9] CL = 11
    nop                    ; [0x7CAB] No operation
    nop                    ; [0x7CAC] No operation
    repe cmpsb             ; [0x7CAD] Compare strings
    jne not_equal2         ; [0x7CAF] Jump if not equal
    mov ax, [es:bx+0x1C]   ; [0x7CB1] Load word from ES:BX+0x1C
    cwd                    ; [0x7CB5] Sign-extend AX to DX:AX
    mov cx, [0x000B]       ; [0x7CB6] CX = [0xB]
    add ax, cx             ; [0x7CB9] AX += CX
    dec ax                 ; [0x7CBB] AX--
    div cx                 ; [0x7CBC] AX = AX/CX
    cmp ax, 0x0014         ; [0x7CBE] Compare AX, 0x14
    jg skip1               ; [0x7CC1] Jump if greater
    mov al, 0x14           ; [0x7CC3] AL = 0x14
skip1:
    xchg ax, si            ; [0x7CC5] Swap AX, SI
    mov ax, [0x0011]       ; [0x7CC6] AX = [0x11]
    mov cl, 0x04           ; [0x7CC9] CL = 4
    shr ax, cl             ; [0x7CCB] AX >>= 4
    call near next4        ; [0x7CCD] Call next4
    push word [0x0024]     ; [0x7CD0] Push [0x24]
    les bx, [0x016D]       ; [0x7CD4] Load ES:BX from [0x16D]
    call near next5        ; [0x7CD8] Call next5
    call near next6        ; [0x7CDB] Call next6
    sub si, ax             ; [0x7CDE] SI -= AX
    jbe skip2              ; [0x7CE0] Jump if below/equal
    call near next7        ; [0x7CE2] Call next7
    push dx                ; [0x7CE5] Push DX
    mul word [0x000B]      ; [0x7CE6] DX:AX = AX * [0xB]
    add bx, ax             ; [0x7CEA] BX += AX
    pop dx                 ; [0x7CEC] Pop DX
    jmp short loop1        ; [0x7CED] Jump to loop1
not_equal:
    pop bx                 ; [0x7CEF] Pop BX
    mov ch, [0x0015]       ; [0x7CF0] CH = [0x15]
    mov dl, [0x01FD]       ; [0x7CF3] DL = [0x1FD]
    jmp far [0x016D]       ; [0x7CF6] Far jump to [0x16D]
not_equal2:
    mov si, 0x018B         ; [0x7CFA] SI = 0x18B
    jmp short error        ; [0x7CFD] Jump to error
next1:
    nop                    ; [0x7CFF] No operation
    add [0x0024], ax       ; [0x7D00] [0x24] += AX
    adc [0x0026], bp       ; [0x7D03] [0x26] += BP + CF
    retf                   ; [0x7D06] Far return
next2:
    mov ax, [0x0018]       ; [0x7D07] AX = [0x18]
    mul byte [0x001A]      ; [0x7D0A] AX *= [0x1A]
    xchg ax, cx            ; [0x7D0D] Swap AX, CX
    mov ax, [0x0024]       ; [0x7D0E] AX = [0x24]
    mov dx, [0x0026]       ; [0x7D11] DX = [0x26]
    mul cx                 ; [0x7D14] DX:AX = AX * CX
    xchg dx, cx            ; [0x7D16] Swap DX, CX
    mov ax, [0x0018]       ; [0x7D17] AX = [0x18]
    mul cx                 ; [0x7D1A] AX *= CX
    sub dl, ah             ; [0x7D1C] DL -= AH
    xchg si, bp            ; [0x7D1E] Swap SI, BP
    dec bp                 ; [0x7D1F] BP--
    ror si, 1              ; [0x7D21] Rotate SI right
    ror si, 1              ; [0x7D23] Rotate SI right
    or dl, cl              ; [0x7D25] DL |= CL
    xchg dx, si            ; [0x7D27] Swap DX, SI
    xchg dx, cx            ; [0x7D28] Swap DX, CX
    mov dl, [0x01FD]       ; [0x7D29] DL = [0x1FD]
    ret                    ; [0x7D2C] Return
next3:
    mov di, 0x0005         ; [0x7D2D] DI = 5
    mov ax, 0x0201         ; [0x7D30] AX = 0x0201
    int 0x13               ; [0x7D33] BIOS disk read
    jc disk_error          ; [0x7D35] Jump if carry (error)
    mov al, 0x01           ; [0x7D37] AL = 1
    ret                    ; [0x7D39] Return
disk_error:
    cmp ah, 0x11           ; [0x7D3A] Compare AH, 0x11
    je disk_error_loop     ; [0x7D3C] If equal, loop
    xor ax, ax             ; [0x7D3E] AX = 0
    int 0x13               ; [0x7D40] Reset disk
    dec si                 ; [0x7D42] SI--
    jne disk_error         ; [0x7D43] Loop if not zero
    mov si, 0x01D5         ; [0x7D45] SI = 0x1D5
    call print_string      ; [0x7D48] Print error string
    mov si, 0x01AB         ; [0x7D4B] SI = 0x1AB
    call print_string      ; [0x7D4E] Print error string
    xor ax, ax             ; [0x7D51] AX = 0
    int 0x16               ; [0x7D53] Wait for key
    mov word [0x0472], 0x1234 ; [0x7D55] Magic reboot value
    jmp far 0xFFFF:0x0000  ; [0x7D5B] Reboot
print_string:
    mov ah, 0x0E           ; [0x7D60] Teletype output
    mov bx, 0x0007         ; [0x7D62] Page/attribute
.print_char:
    int 0x10               ; [0x7D65] Print char
    lodsb                  ; [0x7D67] AL = [SI++]
    cmp al, 0x24           ; [0x7D68] '$' end marker
    jne .print_char        ; [0x7D6A] Loop
    ret                    ; [0x7D6C] Return

; --- Data section ---
times 0x7D6E-($-$$) db 0   ; [0x7D6E] Padding to data

; --- Strings and data ---
disk_label: db "IO      SYSMSDOS   SYS",0 ; [0x7D70] Disk label
db 0x00,0x00,0x00,0x00     ; [0x7D86] Padding
error_msg: db 0x0A,0x0D,"Non-System disk or disk error$",0x0A,0x0D ; [0x7D8A]
replace_msg: db "Replace and strike any key when ready",0x0A,0x0D,"$",0x0A,0x0D ; [0x7DAA]
diskfail_msg: db "Disk boot failure$",0x7DCE
times 0x7DFE-($-$$) db 0x20 ; [0x7DFE] Padding to boot signature
dw 0xAA55                  ; [0x7DFF] Boot sector signature

; --- FAT12 Table (partial, for boot sector) ---
db 0xF0,0xFF,0xFF,0x03,0x40,0x00,0x05,0x60,0x00,0x07,0x80,0x00,0x09,0xA0,0x00,0x0B ; [0x7E00+]

