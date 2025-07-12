def log(msg, src="Main"):
    if debug:
        if src:
            src = f"[{src}]"
        print(f"{src} {msg}")

def screen_thread():
    global buff
    global screen
    log("Starting screen thread...", "Screen")
    screen = Screen((720, 400))
    cpu.screen = screen
    while True:
        try:
            # log(f"Buffer length: {len(buff)}", "Screen")
            screen.write(to_screen(buff))
            screen.update()
        except Exception as e:
            log(f"Screen thread crashed: {e}", "Screen")
            screen.exit()
            break

from time import sleep
from CPU import CPU
from DISK import Disk
from SCREEN import Screen
from MEM import AddressSpace
from Renderer import render_text_buffer_to_rgb as to_screen
from threading import Thread

debug = True
cpu = CPU(debug_mode=debug)
address = AddressSpace()
floppy = Disk("dos.img")
bios = Disk("bios.bin")
bootsector = floppy[0:512]

address.map([0x00] * 0xFFFFF, 0x0) # 16-bit addressable space
address.map(bootsector, 0x7c00) # bootloader placed at 7c00
address.map(bios, 0xF0000)
address.write(0xFFFF0, b'\xEA\x00\x00\x00\xF0') # jump to F0000 placed at reset vector

cpu.memory = address

log("------------------------", "")

# noinspection PyTypeChecker
screen: Screen = None
buff: bytearray = address[0xB8000:0xB8FA0]
screen_thread_ = Thread(target=screen_thread)
screen_thread_.daemon = True
screen_thread_.start()
while not screen:
    sleep(0.1)

while True:
    log(f"IP: {hex(cpu.resolve_address(cpu.cs, cpu.ip))}", "CPU")
    log(f"Instruction: {hex(cpu.fetch(0)[0])}", "CPU")
    cpu.execute()
    log("------------------------", "")

    # fill screen data buffer
    if screen.exiting: # display has crashed/exited
        log("Display thread has exited, exiting.", "Main")
        exit()
    buff = address[0xB8000:0xB8FA0]