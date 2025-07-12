import pygame as pg
from Keyboard import Key

class Screen:
    def __init__(self, resolution: tuple):
        self.resolution = pg.Vector2(resolution)
        self.screen = pg.display.set_mode(resolution)
        pg.display.set_caption('x86-test')
        self.keystrokes: list[Key] = []
        self.exiting = False


    def write(self, data):
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
