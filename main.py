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


from time import perf_counter
from time import sleep
from CPU import CPU
from DISK import Disk
from SCREEN import Screen
from MEM import AddressSpace
from threading import Thread

debug = not False
cpu = CPU(debug_mode=debug)
address = AddressSpace()

# 18-20k, pypy

floppy = Disk("images/dos_2.img")

bios = Disk("images/bios.bin").content
ram_real = [0x00] * 0x9FFFF
video_ram = [0x00] * (0xBFFFF - 0xA0000)
bootsector = floppy[0:512]

address.map(0, ram_real)  # 0x0-0x9FFFF
address.map(0xA0000, video_ram)  # 0xA0000-0xBFFFF

address.write(0x7c00, bootsector)  # bootloader placed at 0x7c00
address.map(0xF0000, bios)
address.map(0xFFFF0, bytes(b'\xEA\x00\x00\x00\xF0'))  # jump to F0000 placed at reset vector

cpu.disks.append(floppy)

ips_goal = 330_000  # 0.33 MIPS, 8086 at ~0.330 MIPS
ips_count = 0
start_time = perf_counter()
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
    cpu.execute()
    log("------------------------", "")

    ips_count += 1
    time = perf_counter()
    if time - start_time > 3 and not debug:
        speed = round(ips_count / (time - start_time))
        print(
            f"executed:{ips_count}, ips:{speed}, {round((speed / ips_goal) * 100)}% of goal {ips_goal}, ecx={cpu.ecx}")
        start_time = time
        ips_count = 0

    mode = cpu.video_mode
    if screen.exiting:  # display has crashed/exited
        log("Display thread has exited, exiting.")
        if error:
            raise error
        exit()
