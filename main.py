def log(msg, src="Main"):
    if debug:
        if src:
            src = f"[{src}]"
        print(f"{src} {msg}")

def screen_thread():
    global address
    global screen
    global error
    global mode
    log("Starting screen thread...", "Screen")
    screen = Screen((720, 400))
    cpu.screen = screen
    while True:
        try:
            screen.write(address, mode)
            screen.update()
        except Exception as e:
            log(f"Screen thread crashed: {e}", "Screen")
            error = e
            screen.exit()
            break

from time import sleep
from CPU import CPU
from DISK import Disk
from SCREEN import Screen
from MEM import AddressSpace
from threading import Thread

debug = not True
cpu = CPU(debug_mode=debug)
address = AddressSpace()

# floppy = Disk("dos.img")
floppy = Disk("screen_test.img")
bios = Disk("bios.bin").content

com = Disk("tests.com")

bootsector = floppy[0:512]

address.write(0x0000, bytearray([0x00] * 0xFFFFF)) # 16-bit addressable space
address.write(0x7c00, bootsector) # bootloader placed at 7c00
address.write(0xF0000, bios)
address.write(0xFFFF0, bytes(b'\xEA\x00\x00\x00\xF0')) # jump to F0000 placed at reset vector

cpu.memory = address

log("------------------------", "")

# noinspection PyTypeChecker
screen: Screen = None
error = None
mode = 0x0E
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

    mode = cpu.video_mode
    if screen.exiting: # display has crashed/exited
        log("Display thread has exited, exiting.", "Main")
        if error:
            raise error
        exit()