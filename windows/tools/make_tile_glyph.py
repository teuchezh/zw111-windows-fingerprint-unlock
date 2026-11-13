#!/usr/bin/env python3
"""Draws the white fingerprint glyph used for the sign-in tile (assets/tile-glyph-256.png).

Same visual language as the built-in sign-in option glyphs: white, uniform stroke, rounded caps,
transparent background. Run:  python3 windows/tools/make_tile_glyph.py
"""
import math, os
from PIL import Image, ImageDraw

S = 1024                      # draw big, downscale for smooth edges
W = 50                        # stroke width at 1024 px
C = (512, 560)                # common centre of the ridges

img = Image.new('L', (S, S), 0)
d = ImageDraw.Draw(img)

def dot(p):
    d.ellipse((p[0] - W / 2, p[1] - W / 2, p[0] + W / 2, p[1] + W / 2), fill=255)

def arc(r, a0, a1):
    """Arc of radius r from angle a0 to a1 (degrees, 0 = east, clockwise), rounded ends."""
    box = (C[0] - r, C[1] - r, C[0] + r, C[1] + r)
    d.arc(box, a0, a1, fill=255, width=W)
    for a in (a0, a1):
        t = math.radians(a)
        dot((C[0] + (r - W / 2) * math.cos(t), C[1] + (r - W / 2) * math.sin(t)))

def leg(r, side, length):
    """Straight continuation going down from the end of a half-circle of radius r."""
    x = C[0] + side * (r - W / 2)
    d.line((x, C[1], x, C[1] + length), fill=255, width=W)
    dot((x, C[1] + length))

# outer ridge: a shallow cap
arc(400, 205, 335)
# second ridge: half circle, short left leg
arc(310, 180, 360); leg(310, -1, 90)
# third ridge: half circle, longer legs (right one shorter)
arc(215, 180, 360); leg(215, -1, 230); leg(215, +1, 120)
# core loop
arc(115, 180, 360); leg(115, -1, 300); leg(115, +1, 200)
# centre line
d.line((C[0], C[1] - 10, C[0], C[1] + 330), fill=255, width=W); dot((C[0], C[1] - 10)); dot((C[0], C[1] + 330))

bbox = img.getbbox()
img = img.crop(bbox)
side = int(max(img.size) * 1.12)
sq = Image.new('L', (side, side), 0)
sq.paste(img, ((side - img.width) // 2, (side - img.height) // 2))
glyph = Image.new('RGBA', (side, side), (255, 255, 255, 0))
glyph.putalpha(sq)
here = os.path.dirname(os.path.abspath(__file__))
out = os.path.join(here, '..', 'assets', 'tile-glyph-256.png')
glyph.resize((256, 256), Image.LANCZOS).save(out, optimize=True)
print('wrote', out)
