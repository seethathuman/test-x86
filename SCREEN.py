import pygame as pg
from Keyboard import Key
from Renderer import *


class Screen:
    def __init__(self, resolution: tuple):
        self.resolution = resolution
        self.screen = pg.display.set_mode(resolution)
        pg.display.set_caption('x86-test')
        self.keystrokes: list[Key] = []
        self.exiting = False

    def write(self, buffer, mode):
        match mode:
            case 0x0E:  # 80x25x16 = 4000 = 0xFA0 text mode
                data = buffer.read(0xB8000, 0xFA0)
                data = text_renderer(data)
                self.resolution = pg.Vector2(len(data), len(data[0]))

            case 0x13:  # 320x200x8 = 64000 = 0xFA00 graphics mode
                data = buffer.read(0xA0000, 0xFA00)
                data = h13_renderer(data)
                self.resolution = pg.Vector2(320, 200)
            case _:
                raise ValueError(f"Unsupported mode: {mode}")

        if self.resolution != self.screen.get_size():
            self.screen = pg.display.set_mode(self.resolution)
        surface = pg.Surface(self.resolution)
        pg.surfarray.blit_array(surface, data)
        self.screen.blit(surface, (0, 0))

    def update(self):
        pg.display.flip()
        for event in pg.event.get():
            if event.type == pg.QUIT:
                pg.quit()
            if event.type == pg.KEYDOWN:
                if event.key == pg.K_ESCAPE:
                    pg.quit()
                    exit()
                self.keystrokes.append(Key(event.scancode, event.key))

    def exit(self):
        self.exiting = True
        pg.quit()
