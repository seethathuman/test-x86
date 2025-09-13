00000000  C45C08            les bx,[si+0x8]
00000003  33ED              xor bp,bp
00000005  B8C007            mov ax,0x7c0
00000008  8ED8              mov ds,ax
0000000A  0AD2              or dl,dl
0000000C  7912              jns 0x20
0000000E  891E2900          mov [0x29],bx
00000012  8C062B00          mov [0x2b],es
00000016  88162D00          mov [0x2d],dl
0000001A  C7062F000200      mov word [0x2f],0x2
00000020  8EC5              mov es,bp
00000022  8ED5              mov ss,bp
00000024  BC007C            mov sp,0x7c00
00000027  FC                cld
00000028  BF7800            mov di,0x78
0000002B  B81E00            mov ax,0x1e
0000002E  AB                stosw
0000002F  8CD8              mov ax,ds
00000031  AB                stosw
00000032  A11600            mov ax,[0x16]
00000035  D1E0              shl ax,1
00000037  40                inc ax
00000038  01062900          add [0x29],ax
0000003C  112E2B00          adc [0x2b],bp
00000040  E86700            call 0xaa
00000043  BB0005            mov bx,0x500
00000046  53                push bx
00000047  B001              mov al,0x1
00000049  E89400            call 0xe0
0000004C  5F                pop di
0000004D  BE7601            mov si,0x176
00000050  B90B00            mov cx,0xb
00000053  F3A6              repe cmpsb
00000055  75A3              jnz 0xfffa
00000057  83C715            add di,byte +0x15
0000005A  B10B              mov cl,0xb
0000005C  F3A6              repe cmpsb
0000005E  759A              jnz 0xfffa
00000060  A11100            mov ax,[0x11]
00000063  B104              mov cl,0x4
00000065  D3E8              shr ax,cl
00000067  01062900          add [0x29],ax
0000006B  112E2B00          adc [0x2b],bp
0000006F  FF362900          push word [0x29]
00000073  C41E7201          les bx,[0x172]
00000077  E83000            call 0xaa
0000007A  00062E00          add [0x2e],al
0000007E  E85F00            call 0xe0
00000081  01062900          add [0x29],ax
00000085  112E2B00          adc [0x2b],bp
00000089  803E2E0011        cmp byte [0x2e],0x11
0000008E  72E7              jc 0x77
00000090  CD11              int 0x11
00000092  D1E0              shl ax,1
00000094  D1E0              shl ax,1
00000096  80E403            and ah,0x3
00000099  B90200            mov cx,0x2
0000009C  7404              jz 0xa2
0000009E  FEC4              inc ah
000000A0  8ACC              mov cl,ah
000000A2  A12F00            mov ax,[0x2f]
000000A5  5B                pop bx
000000A6  FF2E7201          jmp far [0x172]
000000AA  A11800            mov ax,[0x18]
000000AD  F6261A00          mul byte [0x1a]
000000B1  91                xchg ax,cx
000000B2  A12900            mov ax,[0x29]
000000B5  8B162B00          mov dx,[0x2b]
000000B9  F7F1              div cx
000000BB  92                xchg ax,dx
000000BC  8B0E1800          mov cx,[0x18]
000000C0  F6F1              div cl
000000C2  FEC4              inc ah
000000C4  86CC              xchg cl,ah
000000C6  D0CE              ror dh,1
000000C8  D0CE              ror dh,1
000000CA  0ACE              or cl,dh
000000CC  8AEA              mov ch,dl
000000CE  8AF0              mov dh,al
000000D0  8A162D00          mov dl,[0x2d]
000000D4  51                push cx
000000D5  80E13F            and cl,0x3f
000000D8  2AE1              sub ah,cl
000000DA  FEC4              inc ah
000000DC  8AC4              mov al,ah
000000DE  59                pop cx
000000DF  C3                ret
000000E0  98                cbw
000000E1  96                xchg ax,si
000000E2  56                push si
000000E3  BF0500            mov di,0x5
000000E6  B80102            mov ax,0x201
000000E9  CD13              int 0x13
000000EB  720A              jc 0xf7
000000ED  80C702            add bh,0x2
000000F0  FEC1              inc cl
000000F2  4E                dec si
000000F3  75F1              jnz 0xe6
000000F5  58                pop ax
000000F6  C3                ret
000000F7  80FC11            cmp ah,0x11
000000FA  750F              jnz 0x10b
000000FC  1E                push ds
000000FD  B800C8            mov ax,0xc800
00000100  8ED8              mov ds,ax
00000102  813EEA1F434F      cmp word [0x1fea],0x4f43
00000108  1F                pop ds
00000109  74E2              jz 0xed
0000010B  33C0              xor ax,ax
0000010D  CD13              int 0x13
0000010F  4F                dec di
00000110  75D4              jnz 0xe6
00000112  BED601            mov si,0x1d6
00000115  E81D00            call 0x135
00000118  BEAC01            mov si,0x1ac
0000011B  E81700            call 0x135
0000011E  33C0              xor ax,ax
00000120  CD16              int 0x16
00000122  26C70672043412    mov word [es:0x472],0x1234
00000129  EA0000FFFF        jmp 0xffff:0x0
0000012E  B40E              mov ah,0xe
00000130  BB0700            mov bx,0x7
00000133  CD10              int 0x10
00000135  AC                lodsb
00000136  3C24              cmp al,0x24
00000138  75F4              jnz 0x12e
0000013A  C3                ret