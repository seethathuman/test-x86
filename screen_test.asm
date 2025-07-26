[BITS 16]
[ORG 0x7C00]

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    sti

; --- Print "Hello World!" ---
    mov si, msg_hello
.print:
    lodsb
    or al, al
    jz .done
    mov ah, 0x0E
    int 0x10
    jmp .print
.done:
    mov ah, 0x00            ; wait for key mode
    int 0x16
; --- Switch to VGA Mode 13h (320x200x8bpp) ---
    mov ax, 0x0013
    int 0x10

; --- Setup segment for video memory (0xA000) ---
    mov ax, 0xA000
    mov es, ax
    xor di, di        ; es:di = start of video memory

; --- Draw Red Rectangle (top third) ---
    mov cx, 320 * 66
    mov al, 4         ; Red color (palette index)
.draw_red:
    stosb
    loop .draw_red

; --- Draw Green Rectangle (middle third) ---
    mov cx, 320 * 67
    mov al, 2         ; Green
.draw_green:
    stosb
    loop .draw_green

; --- Draw Blue Rectangle (bottom third) ---
    mov cx, 320 * 67
    mov al, 1         ; Blue
.draw_blue:
    stosb
    loop .draw_blue

hang:
    jmp hang

; --- Data ---
msg_hello db 'Hello World!', 0

; --- Boot Signature ---
times 510 - ($ - $$) db 0
dw 0xAA55
