from time import sleep
from CPU import CPU
from DISK import Disk
from SCREEN import Screen
from MEM import AddressSpace
from Renderer import render_text_buffer_to_rgb as to_screen
from threading import Thread

debug = not not not not not not not not True
cpu = CPU(debug_mode=debug)
address = AddressSpace()

floppy = Disk()
boot = floppy[0:512]

# address.map(floppy, 0x0)
address.map([0] * 0xc0000, 0x0)
address.map(boot, 0x7c00)

cpu.memory = address
cpu.ip = 0x0
cpu.ip = 0x144 # test print function

def log(msg, src="Main"):
    if debug:
        if src:
            src = f"[{src}]"
        print(f"{src} {msg}")

log("------------------------", "")

def screen_thread():
    log("Starting screen thread...", "Screen")
    screen = Screen((720, 400))
    cpu.screen = screen
    while True:
        try:
            #log(f"Buffer length: {len(buff)}", "Screen")
            screen.write(to_screen(buff))
            screen.update()
        except Exception as e:
            log(f"Screen thread crashed: {e}", "Screen")
            break


screen_thread_ = Thread(target=screen_thread)
screen_thread_.daemon = True
screen_thread_.start()

while True:
    # fill screen data buffer
    buff = address[0xB8000:0xB8FA0]

    log(f"IP: {hex(cpu.ip)}", "CPU")
    log(f"Instruction: {hex(cpu.fetch(0)[0])}", "CPU")
    cpu.execute()
    log("------------------------", "")

