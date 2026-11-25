#!/usr/bin/env python3
"""Isometric source scenes for the dashboard art, drawn from boxes on white.

    uv run --with numpy --with pillow scripts/art/render.py <out-dir>

Writes <out-dir>/palisade.png, rack.png, vault.png, beacon.png, sieve.png and console.png, the inputs for
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


def beacon(out):
    """Threat intel: a lattice mast pulling in feed packets, a receiver that
    stacks them into block lists."""
    sc = Scene(1800, 2000, 30, (900, 1000))
    sc.box(-1, -1, -1, 18, 17, 1, -10, layer=-1)  # ground slab

    # Lattice mast: four legs tapering by steps, cross braces every few units.
    for k in range(6):
        inset, z = k * 0.25, k * 3.0
        w = 3.0 - 2 * inset
        for lx, ly in [(0, 0), (w - 0.35, 0), (0, w - 0.35), (w - 0.35, w - 0.35)]:
            sc.box(1 + inset + lx, 1 + inset + ly, z, 0.35, 0.35, 3.0, -20)
        o, b = 1 + inset, 0.25  # brace ring: four bars, open in the middle
        sc.box(o, o, z + 2.8, w, b, b, 15, layer=1)
        sc.box(o, o, z + 2.8, b, w, b, 15, layer=1)
        sc.box(o, o + w - b, z + 2.8, w, b, b, 15, layer=1)
        sc.box(o + w - b, o, z + 2.8, b, w, b, 15, layer=1)
    sc.box(2.2, 2.2, 18, 0.6, 0.6, 3.5, -30)  # top spike
    # Three antenna arms at the top, pointing out over the scene.
    sc.box(2.5, 2.3, 19.5, 5.0, 0.3, 0.3, 10, layer=1)
    sc.box(2.3, 2.5, 20.5, 0.3, 4.0, 0.3, 10, layer=1)
    sc.box(2.5, 2.3, 21.3, 3.0, 0.3, 0.3, 10, layer=1)

    # Packets drifting down toward the receiver, getting smaller as they land.
    for k, (x, y, z) in enumerate([(7.5, 1.5, 17), (9.5, 3.0, 14), (11.0, 4.8, 11), (12.0, 6.6, 8.2), (12.6, 8.2, 5.8)]):
        s_ = 1.1 - k * 0.1
        sc.box(x, y, z, s_, s_, s_, 25 if k % 2 else 5)

    # Receiver: a cabinet with a vented front and status lights.
    def grille(x, y, z, w, d, h):
        X = x + w
        for k in range(4):
            zz = z + 0.8 + k * 0.9
            sc.line((X, y + 0.6, zz), (X, y + d - 0.6, zz), LINE + 10, 2)
        for led in range(3):
            yl = y + 0.7 + led * 0.6
            sc.line((X, yl, z + h - 0.6), (X, yl + 0.25, z + h - 0.6), 250, 3)
    sc.box(11, 9, 0, 3.6, 4.2, 4.6, 0, grille)

    # Block lists it has built: three sheets stacked beside it.
    def lines(x, y, z, w, d, h):
        for k in range(5):
            yy = y + 0.6 + k * 0.7
            sc.line((x + 0.6, yy, z + h), (x + w - (0.6 if k % 2 else 1.6), yy, z + h), LINE + 30, 2)
    for k in range(3):
        sc.box(4.5 + k * 0.3, 10 + k * 0.2, k * 0.45, 4.2, 4.0, 0.35, 25 - k * 5, lines)
    sc.render(out)


def sieve(out):
    """WAF rules: a gate of rule bars that stops most packets, with two bars
    lifted out where a rule is switched off, and a console of sliders for
    tuning."""
    sc = Scene(1800, 2000, 30, (900, 1000))
    sc.box(-1, -1, -1, 17, 15, 1, -10, layer=-1)  # ground slab

    # Gate: two posts and a beam, rule bars stacked between them.
    sc.box(6, 1, 0, 0.8, 0.8, 12.6, -20)
    sc.box(6, 9.4, 0, 0.8, 0.8, 12.6, -20)
    sc.box(6, 1, 12.6, 0.8, 9.2, 0.8, -10, layer=1)
    off = {3, 7}  # rules switched off: gaps in the gate
    for k in range(11):
        if k not in off:
            sc.box(6.15, 1.8, 0.8 + k * 1.1, 0.5, 7.6, 0.45, 15 if k % 2 else 5)

    # Packets: arriving from the near side, stopped ones piled at the gate,
    # two slipping through the gaps to the far side.
    for x, y, z in [(12.5, 3.0, 8.0), (11.0, 6.4, 10.5), (14.0, 0.5, 5.0)]:
        sc.box(x, y, z, 1.0, 1.0, 1.0, 25)
    for x, y, z in [(7.2, 2.4, 0), (7.2, 3.6, 0), (7.3, 3.0, 1.0), (8.4, 2.9, 0), (7.2, 7.4, 0)]:
        sc.box(x, y, z, 1.0, 1.0, 1.0, 5)
    sc.box(6.0, 4.6, 4.2, 0.9, 0.9, 0.9, 25, layer=1)  # in the lower gap
    sc.box(1.0, 11.0, 6.5, 0.9, 0.9, 0.9, 25)  # through the upper one

    # Console: sliders on a desk, one per rule group.
    def sliders(x, y, z, w, d, h):
        Z = z + h
        for k in range(4):
            xx = x + 0.7 + k * 0.9
            sc.line((xx, y + 0.5, Z), (xx, y + d - 0.5, Z), LINE + 10, 2)
    sc.box(11.0, 9.0, 0, 4.2, 3.6, 2.2, 0, sliders)
    for k, t in enumerate([0.3, 0.6, 0.45, 0.75]):
        sc.box(11.5 + k * 0.9, 9.4 + t * 2.2, 2.2, 0.4, 0.5, 0.35, 20, layer=1)
    sc.render(out)


def console(out):
    """Settings: a control desk of toggle switches and dials, a key for the
    accounts, and a ledger beside it for the audit log."""
    sc = Scene(1800, 2000, 30, (900, 1000))
    sc.box(-1, -1, -1, 17, 15, 1, -10, layer=-1)  # ground slab

    # Back panel: a tall cabinet with rows of switches, some flipped up.
    def switches(x, y, z, w, d, h):
        X = x + w
        for row in range(3):
            zz = z + 2.0 + row * 2.6
            for k in range(5):
                yy = y + 0.8 + k * 1.3
                up = (row * 5 + k) % 3 == 0
                sc.line((X, yy, zz), (X, yy, zz + (0.9 if up else -0.9)), 250 if up else LINE + 10, 3)
    sc.box(1, 1, 0, 2.6, 7.6, 9.4, -15, switches)
    sc.box(0.8, 0.8, 9.4, 3.0, 8.0, 0.5, 5, layer=1)  # cap

    # Desk: a sloped top stepped in two, with dials standing on it.
    sc.box(5, 1, 0, 5.4, 7.6, 2.6, 0)
    sc.box(5, 1, 2.6, 2.6, 7.6, 1.2, 10, layer=1)
    for k, (x, y) in enumerate([(5.6, 1.8), (5.6, 4.2), (5.6, 6.6), (8.4, 2.6), (8.4, 5.4)]):
        z = 3.8 if x < 8 else 2.6
        sc.box(x, y, z, 1.2, 1.2, 0.5, 20, layer=2)  # after both desk steps
        sc.box(x + 0.45, y + 0.45, z + 0.5, 0.3, 0.3, 0.6 + 0.2 * (k % 3), -10, layer=2)

    # Key, lying in front of the desk: bow, shaft and teeth.
    sc.box(11.2, 3.0, 0, 1.6, 1.6, 0.35, 25)
    sc.box(12.8, 3.6, 0, 3.0, 0.4, 0.3, 15)
    sc.box(15.0, 4.0, 0, 0.4, 0.5, 0.3, 15)
    sc.box(14.2, 4.0, 0, 0.4, 0.4, 0.3, 15)

    # Ledger: a closed book with its pages, and an open one on top of it.
    def pages(x, y, z, w, d, h):
        for k in range(5):
            yy = y + 0.5 + k * 0.6
            sc.line((x + 0.5, yy, z + h), (x + w - (0.5 if k % 2 else 1.4), yy, z + h), LINE + 30, 2)
    sc.box(10.6, 8.8, 0, 4.2, 4.6, 0.9, -5)
    sc.box(10.9, 9.0, 0.9, 3.6, 4.2, 0.3, 30, pages, layer=1)
    sc.render(out)


if __name__ == '__main__':
    out = Path(sys.argv[1] if len(sys.argv) > 1 else '.')
    out.mkdir(parents=True, exist_ok=True)
    palisade(out / 'palisade.png')
    rack(out / 'rack.png')
    vault(out / 'vault.png')
    beacon(out / 'beacon.png')
    sieve(out / 'sieve.png')
    console(out / 'console.png')
