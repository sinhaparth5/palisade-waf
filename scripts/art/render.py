#!/usr/bin/env python3
"""Isometric source scenes for the dashboard art, drawn from boxes on white.

    uv run --with numpy --with pillow scripts/art/render.py <out-dir>

Writes <out-dir>/palisade.png, rack.png and vault.png, the inputs for
dissolve.py. Drawn here rather than downloaded so the art is ours to ship and
every shape is a plain grey the gradient map can recolour.
"""
import math
import sys
from pathlib import Path

from PIL import Image, ImageDraw

S = 2  # supersample, halved at the end
COS, SIN = math.cos(math.radians(30)), math.sin(math.radians(30))
TOP, LEFT, RIGHT, LINE = 214, 150, 96, 58  # face greys: lit top, mid left, shaded right


class Scene:
    def __init__(self, w, h, unit, origin):
        self.img = Image.new('RGB', (w * S, h * S), 'white')
        self.d = ImageDraw.Draw(self.img)
        self.u = unit * S
        self.ox, self.oy = origin[0] * S, origin[1] * S
        self.items = []

    def p(self, x, y, z):
        return (self.ox + (x - y) * COS * self.u, self.oy + (x + y) * SIN * self.u - z * self.u)

    def poly(self, pts, fill):
        self.d.polygon([self.p(*q) for q in pts], fill=(fill,) * 3, outline=(LINE,) * 3, width=S)

    def line(self, a, b, shade=LINE, width=1):
        self.d.line([self.p(*a), self.p(*b)], fill=(shade,) * 3, width=width * S)

    # Painter's order: centre depth (x + y), then height, so tall parts
    # behind a wall are drawn before the wall in front of them.
    # layer: -1 for ground slabs (always first), 1 for parts that sit on top of
    # a neighbour, like a lintel on its posts.
    def box(self, x, y, z, w, d, h, tone=0, detail=None, layer=0):
        self.items.append(((layer, x + w / 2 + y + d / 2, z), lambda: self._box(x, y, z, w, d, h, tone, detail)))

    def _box(self, x, y, z, w, d, h, tone, detail):
        X, Y, Z = x + w, y + d, z + h
        self.poly([(x, y, Z), (X, y, Z), (X, Y, Z), (x, Y, Z)], TOP + tone)
        self.poly([(x, Y, z), (X, Y, z), (X, Y, Z), (x, Y, Z)], LEFT + tone)
        self.poly([(X, y, z), (X, Y, z), (X, Y, Z), (X, y, Z)], RIGHT + tone)
        if detail:
            detail(x, y, z, w, d, h)

    def stake(self, x, y, z, s, h, tip, tone=0):
        """A square post with a pyramid point."""
        def draw():
            self._box(x, y, z, s, s, h, tone, None)
            c = (x + s / 2, y + s / 2, z + h + tip)
            X, Y, Z = x + s, y + s, z + h
            self.poly([(x, Y, Z), (X, Y, Z), c], LEFT + 30 + tone)
            self.poly([(X, y, Z), (X, Y, Z), c], RIGHT + 20 + tone)
        self.items.append(((0, x + s / 2 + y + s / 2, z), draw))

    def render(self, out):
        for _, f in sorted(self.items, key=lambda t: t[0]):
            f()
        im = self.img.resize((self.img.width // S, self.img.height // S), Image.LANCZOS)
        x0, y0, x1, y1 = Image.eval(im.convert('L'), lambda v: 255 - v).point(lambda v: 255 if v > 4 else 0).getbbox()
        m = 40
        im = im.crop((x0 - m, y0 - m, x1 + m, y1 + m))
        im.save(out)
        print(out)


def palisade(out):
    sc = Scene(2000, 1800, 30, (1000, 700))
    n = 20
    sc.box(-3, -3, -1.2, n + 6, n + 6, 1.2, -10, layer=-1)  # ground slab

    def post(x, y, k):
        sc.stake(x, y, 0, 0.8, 6 + (k * 7 % 3) * 0.4, 1.3, (k % 2) * 8)

    # Four walls of pointed stakes; the near-right wall has a gate gap.
    for k in range(6, n):
        post(k + 0.1, 0.1, k)  # back right
        post(0.1, k + 0.1, k)  # back left
    for k in range(n + 1):
        post(k + 0.1, n + 0.1, k)  # front left
        if not 8 <= k <= 12:
            post(n + 0.1, k + 0.1, k)  # front right
    # Gate: two heavy posts and a lintel over the gap.
    sc.box(n - 0.2, 7.0, 0, 1.4, 1.2, 8.2, -10)
    sc.box(n - 0.2, 12.8, 0, 1.4, 1.2, 8.2, -10)
    sc.box(n - 0.1, 7.0, 8.2, 1.2, 7.0, 0.8, 18, layer=1)

    # Watchtower in the back corner: four legs, a deck, a crenellated cabin.
    def windows(x, y, z, w, d, h):
        for k in range(3):
            a = x + 0.7 + k * 1.6
            sc.poly([(a, y + d, z + 1.0), (a + 0.8, y + d, z + 1.0), (a + 0.8, y + d, z + h - 0.8), (a, y + d, z + h - 0.8)], LINE + 10)
            sc.poly([(x + w, a, z + 1.0), (x + w, a + 0.8, z + 1.0), (x + w, a + 0.8, z + h - 0.8), (x + w, a, z + h - 0.8)], LINE)
    for lx, ly in [(0, 0), (5, 0), (0, 5), (5, 5)]:
        sc.box(lx, ly, 0, 0.7, 0.7, 10, -15)
    sc.box(-0.4, -0.4, 10, 6.5, 6.5, 0.5, 10)
    sc.box(0, 0, 10.5, 5.7, 5.7, 3.6, 0, windows)
    for k in range(4):
        sc.box(k * 1.6, 5.0, 14.1, 0.7, 0.7, 0.8, 10)
        sc.box(5.0, k * 1.6, 14.1, 0.7, 0.7, 0.8, 10)
    sc.box(2.6, 2.6, 14.1, 0.3, 0.3, 4.5, -30)  # flag pole
    sc.box(2.9, 2.7, 17.0, 2.4, 0.08, 1.3, -50)  # pennant
    sc.render(out)


def rack(out):
    sc = Scene(1800, 1800, 34, (900, 800))
    sc.box(-2, -2, -1, 19, 16, 1, -10, layer=-1)  # floor plate

    def front(x, y, z, w, d, h):
        X = x + w
        units = int(h / 0.9)
        for k in range(units):
            zb = z + 0.5 + k * 0.9
            if zb + 0.7 > z + h - 0.4:
                break
            sc.poly([(X, y + 0.4, zb), (X, y + d - 0.4, zb), (X, y + d - 0.4, zb + 0.7), (X, y + 0.4, zb + 0.7)], RIGHT - 18 + (k % 3) * 9)
            for led in range(3):
                yl = y + 0.8 + led * 0.45
                sc.line((X, yl, zb + 0.35), (X, yl + 0.18, zb + 0.35), 235 if (k + led) % 4 else 255, 3)
            for v in range(6):
                yv = y + d - 0.9 - v * 0.25
                sc.line((X, yv, zb + 0.15), (X, yv, zb + 0.55), LINE)

    def side(x, y, z, w, d, h):
        Y = y + d
        for k in range(int(h / 1.4)):
            zz = z + 1.2 + k * 1.4
            sc.line((x + 0.8, Y, zz), (x + w - 0.8, Y, zz), LEFT - 40)

    def both(*a):
        front(*a)
        side(*a)

    sc.box(0, 0, 0, 5, 6, 17, 0, both)
    sc.box(0, 6.6, 0, 5, 6, 12, 6, both)
    # A switch on the floor and a UPS block beside it.
    sc.box(8.5, 3, 0, 4.5, 3.2, 1.2, 10, front)
    sc.box(8.5, 3, 1.2, 4.5, 3.2, 0.25, -10)
    sc.box(14, 9, 0, 2.2, 2.2, 2.6, 0)  # UPS block
    sc.render(out)


def vault(out):
    sc = Scene(1800, 1800, 34, (900, 800))
    sc.box(-2, -2, -1, 18, 16, 1, -10, layer=-1)  # floor plate

    # A padlock: body with a keyhole, a U shackle of three bars.
    def keyhole(x, y, z, w, d, h):
        X, cy, cz = x + w, y + d / 2, z + h * 0.55
        sc.poly([(X, cy - 0.5, cz), (X, cy + 0.5, cz), (X, cy + 0.5, cz + 1.0), (X, cy - 0.5, cz + 1.0)], LINE)
        sc.poly([(X, cy - 0.2, cz - 1.6), (X, cy + 0.2, cz - 1.6), (X, cy + 0.2, cz), (X, cy - 0.2, cz)], LINE)
        for k in range(3):  # plate rivets
            sc.line((X, y + 0.6, z + 0.8 + k * 2.4), (X, y + 0.75, z + 0.8 + k * 2.4), 240, 3)
    sc.box(1.6, 2.0, 7.5, 1.0, 1.0, 5.0, 10)  # shackle, back leg
    sc.box(1.6, 2.0, 12.5, 1.0, 6.2, 1.0, 20)  # shackle, top bar
    sc.box(0, 0, 0, 4.2, 10.2, 7.5, 0, keyhole)  # body
    sc.box(1.6, 7.2, 7.5, 1.0, 1.0, 5.0, 10, layer=1)  # shackle, front leg

    # Certificates standing in a rack: thin cards with text lines and a seal.
    def card(x, y, z, w, d, h):
        X = x + w
        for k in range(4):
            zz = z + h - 1.2 - k * 0.9
            sc.line((X, y + 0.6, zz), (X, y + d - (0.6 if k % 2 else 1.8), zz), LINE + 20, 2)
        sc.poly([(X, y + d - 1.8, z + 0.6), (X, y + d - 0.6, z + 0.6), (X, y + d - 0.6, z + 1.8), (X, y + d - 1.8, z + 1.8)], LINE)
    for k in range(3):
        sc.box(8 + k * 1.6, 1 + k * 0.4, 0, 0.35, 5.2, 7.2 - k * 0.8, 20, card)
    sc.box(7.4, 0.4, 0, 5.4, 6.6, 0.6, -20, layer=-1)  # card stand
    sc.box(10, 9, 0, 3.4, 1.4, 0.5, 0)  # a key lying flat: bow
    sc.box(10.8, 10.4, 0, 0.6, 3.2, 0.4, 0)  # blade
    sc.box(11.4, 12.4, 0, 0.6, 0.4, 0.4, 0)  # bit
    sc.render(out)


if __name__ == '__main__':
    out = Path(sys.argv[1] if len(sys.argv) > 1 else '.')
    out.mkdir(parents=True, exist_ok=True)
    palisade(out / 'palisade.png')
    rack(out / 'rack.png')
    vault(out / 'vault.png')
