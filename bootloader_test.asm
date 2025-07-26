; Bootloader decompiled from binary
; Comments: [address] and instruction explanation

org 0x7C00

start:
    jmp short main         ; [0x7C00] Jump to main code
    nop                    ; [0x7C02] No operation

main:
    mov ds, ax             ; [0x7C40] DS = 0x07C0
    jmp disk_error

disk_error:
    xor ax, ax             ; [0x7D3E] AX = 0
    mov si, error_msg      ; [0x7D45] SI = 0x1D5
    call print_string      ; [0x7D48] Print error string
    mov si, replace_msg    ; [0x7D4B] SI = 0x1AB
    call print_string      ; [0x7D4E] Print error string
    xor ax, ax             ; [0x7D51] AX = 0
    int 0x16               ; [0x7D53] Wait for key
    jmp 0xFFFF:0x0000  ; [0x7D5B] Reboot

print_string:
    mov ah, 0x0E           ; [0x7D60] Teletype output
    mov bx, 0x0007         ; [0x7D62] Page/attribute
.print_char:
    int 0x10               ; [0x7D65] Print char
    lodsb                  ; [0x7D67] AL = [SI++]
    cmp al, 0x24           ; [0x7D68] '$' end marker
    jne .print_char        ; [0x7D6A] Loop
    ret                    ; [0x7D6C] Return

; --- Strings and data ---
disk_label: db "IO      SYSMSDOS   SYS",0 ; [0x7D70] Disk label
error_msg: db 0x0A,0x0D,"Non-System disk or disk error$",0x0A,0x0D ; [0x7D8A]
replace_msg: db "Replace and strike any key when ready",0x0A,0x0D,"$",0x0A,0x0D ; [0x7DAA]
diskfail_msg: db "Disk boot failure$",0x0A,0x0D ; [0x7DCE]
times 0x7DFE-($-$$) db 0x20 ; [0x7DFE] Padding to boot signature
dw 0xAA55                  ; [0x7DFF] Boot sector signature