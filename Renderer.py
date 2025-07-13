# This file was created by AI
# kinda funny how I can make an entire x86 emulator,
# but be too lazy to make a program to render some text
# I know this is probably not how the display buffer
# works, but it works well enough for now
import numpy as np
from PIL import Image, ImageDraw, ImageFont
from numpy import ndarray

cols, rows = 80, 25
cell_width, cell_height = 9, 16
width, height = cols * cell_width, rows * cell_height

font = ImageFont.truetype("cga.ttf", 14)

image = Image.new("RGB", (width, height))
draw = ImageDraw.Draw(image)

last_buffer: bytearray = None
last_rendered: ndarray = None

# VGA 16-color palette (RGB)
VGA_PALETTE = [
    (0, 0, 0),          # 0: Black
    (0, 0, 170),        # 1: Blue
    (0, 170, 0),        # 2: Green
    (0, 170, 170),      # 3: Cyan
    (170, 0, 0),        # 4: Red
    (170, 0, 170),      # 5: Magenta
    (170, 85, 0),       # 6: Brown / Yellow
    (170, 170, 170),    # 7: Light Gray
    (85, 85, 85),       # 8: Dark Gray
    (85, 85, 255),      # 9: Bright Blue
    (85, 255, 85),      # 10: Bright Green
    (85, 255, 255),     # 11: Bright Cyan
    (255, 85, 85),      # 12: Bright Red
    (255, 85, 255),     # 13: Bright Magenta
    (255, 255, 85),     # 14: Yellow
    (255, 255, 255),    # 15: White
]

def render_text_buffer_to_rgb(buffer: bytearray) -> np.ndarray:
    global last_buffer
    global last_rendered
    if last_buffer == buffer:
        return last_rendered
    last_buffer = buffer
    # Create the image
    for row in range(rows):
        for col in range(cols):
            i = (row * cols + col) * 2
            char_code = buffer[i][0]
            attr = buffer[i + 1][0]
            fg_color = VGA_PALETTE[attr & 0x0F]
            bg_color = VGA_PALETTE[(attr >> 4) & 0x0F]
            try:
                char = bytes([char_code]).decode('windows-1252')
            except:
                char = " "

            x = col * cell_width
            y = row * cell_height

            # Draw background
            draw.rectangle((x, y, x + cell_width, y + cell_height), fill=bg_color)

            # Draw character
            draw.text((x, y), char, font=font, fill=fg_color)

    # Convert to NumPy array
    last_rendered = np.transpose(image, (1, 0, 2))
    return last_rendered
