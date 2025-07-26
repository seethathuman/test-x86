# This file was created by AI
# kinda funny how I can make an entire x86 emulator,
# but be too lazy to make a program to render some text
# I know this is probably not how the display buffer
# works, but it works well enough for now

import numpy as np
from PIL import Image, ImageDraw, ImageFont

# Screen and character dimensions
cols, rows = 80, 25
cell_width, cell_height = 9, 16
width, height = cols * cell_width, rows * cell_height

# Load a bitmap font
# You can also use `.ttf` if it’s pixel aligned (like CGA)
font = ImageFont.truetype("cga.ttf", 14)

# VGA 16-color palette (RGB)
VGA_PALETTE = [
    (0, 0, 0), (0, 0, 170), (0, 170, 0), (0, 170, 170),
    (170, 0, 0), (170, 0, 170), (170, 85, 0), (170, 170, 170),
    (85, 85, 85), (85, 85, 255), (85, 255, 85), (85, 255, 255),
    (255, 85, 85), (255, 85, 255), (255, 255, 85), (255, 255, 255),
]

VGA_PALETTE_np = np.array(VGA_PALETTE, dtype=np.uint8)

# Cache rendered characters for reuse: (char, fg, bg) => Image
glyph_cache = {}

last_buffer = None
last_rendered = None

def h13_renderer(buffer):
    # Convert buffer to palette indices
    indices = np.frombuffer(b''.join(buffer), dtype=np.uint8)

    if indices.size != 320 * 200:
        raise ValueError(f"Expected 64000 bytes, got {indices.size}")

    # Map palette indices to RGB
    rgb_flat = VGA_PALETTE_np[indices]  # shape: (64000, 3)

    # Reshape to (height=200, width=320)
    rgb_image = rgb_flat.reshape((200, 320, 3))
    rgb_image = np.transpose(rgb_image, (1, 0, 2))  # Transpose to (width, height, channels)
    return rgb_image


def text_renderer(buffer):
    global last_buffer, last_rendered

    if last_buffer == buffer and last_rendered is not None:
        return last_rendered
    last_buffer = buffer

    image = Image.new("RGB", (width, height))

    for row in range(rows):
        for col in range(cols):
            i = (row * cols + col) * 2
            char_code = buffer[i][0]
            attr = buffer[i + 1][0]

            fg_color = VGA_PALETTE[attr & 0x0F]
            bg_color = VGA_PALETTE[(attr >> 4) & 0x0F]

            char = bytes([char_code]).decode('cp437')

            cache_key = (char, fg_color, bg_color)
            if cache_key not in glyph_cache:
                # Render character with background to an image
                glyph = Image.new("RGB", (cell_width, cell_height), color=bg_color)
                d = ImageDraw.Draw(glyph)
                d.text((0, 0), char, font=font, fill=fg_color)
                glyph_cache[cache_key] = glyph
            else:
                glyph = glyph_cache[cache_key]

            image.paste(glyph, (col * cell_width, row * cell_height))

    last_rendered = np.array(image)
    last_rendered = np.transpose(image, (1, 0, 2))
    return last_rendered
