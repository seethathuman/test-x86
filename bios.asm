section .text
global main
org 0xF0000

main:
    mov ax, 0xF000
    mov ds, ax              ; set data to bios address
    mov ax, 0x07C0
    mov ss, ax              ; set stack to bootsector address

    call clear_screen
    call print
    call fill_ansi
    mov ah, 0x00
    int 0x16                ; wait for keyboard

    mov ax, 0x07C0
    mov ds, ax              ; set data to bootsector address
    jmp 0x07C0:0x0144       ; jump to bootsector

print:
    mov ah, 0x0E            ; teletype output
    mov si, msg             ; load message address
    lodsb                   ; load first character
.print_char:
    int 0x10                ; screen interrupt to write character
    lodsb                   ; load current character
    cmp al, 0x0             ; check if character is $
    jne .print_char         ; if not equal to $, print another character
    ret

clear_screen:
    mov ah, 0x02            ; set cursor position
    mov dl, 0x00            ; cursor x
    mov dh, 0x00            ; cursor y
    int 0x10                ; screen interrupt

    mov bx, 0x07D0          ; 2000 = 80x25

.clear_character:
    mov ax, 0x0EFF          ; teletype output (0E) in high byte, character to print in low byte
    int 0x10                ; save character

    mov ax, bx              ; get ax from bx
    sub ax, 0x0001          ; decrement ax
    mov bx, ax              ; save ax to bx

    jae .clear_character    ; jump if not negative

    mov ah, 0x02            ; set cursor position
    mov dl, 0x00            ; cursor x
    mov dh, 0x00            ; cursor y
    int 0x10                ; screen interrupt
    ret

fill_ansi:
    mov ah, 0x02            ; set cursor position
    mov dl, 0x00            ; cursor x
    mov dh, 0x01            ; cursor y
    int 0x10                ; screen interrupt

    mov ax, 0x0EFF          ; teletype output (0E) in high byte

.clear_character:
    int 0x10                ; print character

    sub ax, 0x0001          ; decrement al
    cmp ax, 0x0DFF          ; check if al is FF
    jne .clear_character    ; jump if al didn't rolled over

    mov ah, 0x02            ; set cursor position
    mov dl, 0x00            ; cursor x
    mov dh, 0x00            ; cursor y
    int 0x10                ; screen interrupt
    ret
msg db "Hello world! Press any key to continue.", 0