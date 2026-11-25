#!/usr/bin/env python3
"""504/505 treatment for a subject image.

    uv run --with numpy --with pillow scripts/art/dissolve.py <input> <output.webp> [--palette ledger] [--seed N] [--size 1400]

The dashboard art: render.py draws the scenes, this turns them into
web/src/assets/art/*.webp (see web/README.md).

Input: a PNG with transparency, or a subject on a plain light background (it is keyed out).
Output: RGBA WebP on a transparent background, so it melts into any page colour.

Steps, following the Photoshop recipe in AGENTS.md:
  1. isolate the subject
  2. gradient-map it: indigo at the top, coral/orange toward the bottom
  3. vertical streaks: smear the lower half downward, fading out
  4. warm glow + cool shadow under the base
  5. top dispersion: erode the top edge into rising vertical dashes, column-aligned
  6. film grain
"""
import argparse
import os
import zlib

import numpy as np
from PIL import Image, ImageDraw, ImageFilter

def hexc(h):
    return np.array([int(h[i:i + 2], 16) for i in (1, 3, 5)]) / 255


# cool ramp (top), warm ramp (base), shadow tint, particle accents.
PALETTES = {
    'indigo': dict(cool=('#161654', '#3a3fd1', '#969cff'), warm=('#8c2228', '#ff6a3d', '#ffc496'), shade='#7b6cf0', accents=('#ff6a3d', '#969cff')),
    # The admin theme (static/css/ledger.css): info blue on top, danger and
    # warning at the base, success green in the sparks. Mid-tones only, so the
    # same file reads on the cream and the dark paper.
    'ledger': dict(cool=('#1d2f5c', '#2e5aa3', '#7fa4e6'), warm=('#7a2414', '#c84b31', '#e0ae6e'), shade='#5b88d9', accents=('#d9a05b', '#6aac6f')),
}


def smoothstep(a, b, x):
    t = np.clip((x - a) / (b - a), 0, 1)
    return t * t * (3 - 2 * t)


def ramp(lum, stops):
    """Map luminance 0..1 through 3 colour stops."""
    lo, mid, hi = stops
    l = lum[..., None]
    return np.where(l < 0.5, lo + (mid - lo) * (l / 0.5), mid + (hi - mid) * ((l - 0.5) / 0.5))


def isolate(img):
    rgba = np.asarray(img.convert('RGBA')).astype(np.float32) / 255
    if rgba[..., 3].min() < 0.99:  # already has transparency
        return rgba
    rgb = rgba[..., :3]
    corners = np.stack([rgb[0, 0], rgb[0, -1], rgb[-1, 0], rgb[-1, -1]])
    bg = np.median(corners, axis=0)
    dist = np.sqrt(((rgb - bg) ** 2).sum(-1))
    # Only background-coloured pixels connected to the border are background, so white
    # areas inside the subject (book pages, lit faces) survive.
    near = Image.fromarray(((dist < 0.12) * 255).astype(np.uint8)).copy()  # copy: fromarray views are read-only for floodfill
    for xy in [(0, 0), (near.width - 1, 0), (0, near.height - 1), (near.width - 1, near.height - 1)]:
        if near.getpixel(xy) == 255:
            ImageDraw.floodfill(near, xy, 128)
    outside = np.asarray(near) == 128
    hard = Image.fromarray(((~outside) * 255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(1.2))
    rgba[..., 3] = np.asarray(hard).astype(np.float32) / 255
    return rgba


def run(src, dst, seed=7, size=1400, palette='indigo'):
    pal = PALETTES[palette]
    cool_stops, warm_stops = [tuple(hexc(c) for c in pal[k]) for k in ('cool', 'warm')]
    glow_c, acc1, acc2 = hexc(pal['warm'][1]), hexc(pal['accents'][0]), hexc(pal['accents'][1])
    rng = np.random.default_rng(seed)
    img = Image.open(src)
    img.thumbnail((size, size), Image.LANCZOS)
    sub = isolate(img)

    # Pad: room above for particles, below for streaks and glow.
    h, w = sub.shape[:2]
    top_pad, bot_pad, side = int(h * 0.45), int(h * 0.22), int(w * 0.12)
    H, W = h + top_pad + bot_pad, w + side * 2
    canvas = np.zeros((H, W, 4), np.float32)
    canvas[top_pad:top_pad + h, side:side + w] = sub
    rgb, a = canvas[..., :3], canvas[..., 3]

    ys, xs = np.nonzero(a > 0.5)
    y0, y1, x0, x1 = ys.min(), ys.max(), xs.min(), xs.max()
    yy = np.arange(H)[:, None].repeat(W, 1).astype(np.float32)
    t = (yy - y0) / max(1, y1 - y0)  # 0 at subject top, 1 at bottom

    # 2. Gradient map: cool duotone everywhere, warming toward the base.
    lum = (rgb * [0.299, 0.587, 0.114]).sum(-1)
    lum = np.clip((lum - lum[a > 0.5].min()) / (np.ptp(lum[a > 0.5]) + 1e-6), 0, 1) ** 1.35
    cool = ramp(lum, cool_stops)
    warm = ramp(lum, warm_stops)
    wmix = smoothstep(0.35, 1.0, t)[..., None] * 0.9
    col = cool * (1 - wmix) + warm * wmix

    # Column texture: thin vertical bars of varying brightness through the body (504's columns).
    bars = np.repeat(rng.uniform(0.72, 1.25, W // 2 + 1), 2)[:W]
    col = np.clip(col * (1 + (bars - 1) * smoothstep(0.1, 0.8, t))[..., None], 0, 1)

    # 3. Downward streaks: per-column exponential smear of the lower body.
    decay = np.repeat(rng.uniform(0.975, 0.997, W // 3 + 1), 3)[:W]
    src_a = a * smoothstep(0.45, 0.95, t)
    sa, sc = src_a.copy(), col * src_a[..., None]
    for y in range(1, H):
        carry = sa[y - 1] * decay
        take = carry > sa[y]
        sa[y] = np.where(take, carry, sa[y])
        sc[y] = np.where(take[:, None], sc[y - 1] * decay[:, None], sc[y])
    below = np.clip((yy - y1 + (y1 - y0) * 0.05) / (bot_pad * 0.7), 0, 1)
    streak_a = sa * (1 - below) ** 2
    streak_c = sc / np.maximum(sa, 1e-6)[..., None]

    # 5. Top dispersion: erode the top of the subject, turn the lost pixels into rising dashes.
    erode_zone = 1 - smoothstep(0.0, 0.4, t)  # 1 at the very top, 0 by 40% down
    keep = rng.random((H, W)) > erode_zone ** 1.4 * 0.85
    body_a = a * np.where(erode_zone > 0, keep, 1)

    out_rgb = np.zeros((H, W, 3), np.float32)
    out_a = np.zeros((H, W), np.float32)

    def over(c, al):
        nonlocal out_rgb, out_a
        na = al + out_a * (1 - al)
        out_rgb = (c * al[..., None] + out_rgb * (out_a * (1 - al))[..., None]) / np.maximum(na, 1e-6)[..., None]
        out_a = na

    # 4. Glow and shadow under the base.
    cx, base = (x0 + x1) / 2, y1
    gw = float(x1 - x0)
    gy, gx = np.ogrid[:H, :W]
    ell = ((gx - cx) / (gw * 0.55)) ** 2 + ((gy - base) / (gw * 0.14)) ** 2
    glow_a = np.clip(1 - ell, 0, 1) ** 1.5
    glow_a = np.asarray(Image.fromarray((glow_a * 255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(gw * 0.06))) / 255
    shade = ((gx - cx - gw * 0.15) / (gw * 0.6)) ** 2 + ((gy - base - gw * 0.03) / (gw * 0.12)) ** 2
    shade_a = np.asarray(Image.fromarray((np.clip(1 - shade, 0, 1) * 255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(gw * 0.08))) / 255
    over(np.broadcast_to(hexc(pal['shade']), (H, W, 3)), shade_a * 0.35)
    over(np.broadcast_to(glow_c, (H, W, 3)), glow_a * 0.7)

    over(streak_c, np.clip(streak_a * 0.9, 0, 1))
    over(col, body_a)

    # Particles: sample from the top band of the subject, rise as vertical dashes snapped to columns.
    band = (a > 0.5) & (t < 0.45)
    by, bx = np.nonzero(band)
    n = min(len(by), int(gw * 9))
    if n:
        pick = rng.choice(len(by), n, replace=False)
        py, px = by[pick], bx[pick]
        rise = (rng.random(n) ** 2.6) * (top_pad + (y1 - y0) * 0.3) * 0.95
        dash = (1 + rng.random(n) * 5 + (rng.random(n) < 0.12) * rng.random(n) * 18).astype(int)
        width = 1 + (rng.random(n) < 0.35)
        snap = 3
        for i in range(n):
            x = int(round(px[i] / snap) * snap)
            ytop = int(py[i] - rise[i] - dash[i])
            if ytop < 0 or x >= W - 2:
                continue
            fade = max(0.1, 1 - rise[i] / (top_pad * 0.9))
            c = col[py[i], px[i]]
            if rng.random() < 0.18:
                c = acc1 if rng.random() < 0.6 else acc2
            ys_ = slice(ytop, ytop + dash[i])
            xs_ = slice(x, x + width[i])
            al = fade * (0.55 + 0.45 * rng.random())
            out_rgb[ys_, xs_] = c * al + out_rgb[ys_, xs_] * (1 - al)
            out_a[ys_, xs_] = np.maximum(out_a[ys_, xs_], al)

    # 6. Grain.
    noise = rng.normal(0, 0.035, (H, W, 1))
    out_rgb = np.clip(out_rgb + noise * (out_a[..., None] > 0), 0, 1)

    # Trim to content.
    rows, cols = np.nonzero(out_a > 0.01)
    pad = 24
    r0, r1 = max(0, rows.min() - pad), min(H, rows.max() + pad)
    c0, c1 = max(0, cols.min() - pad), min(W, cols.max() + pad)
    out = np.dstack([out_rgb, out_a])[r0:r1, c0:c1]
    im = Image.fromarray((out * 255).astype(np.uint8), 'RGBA')
    im.save(dst, quality=76, method=6)
    # Half-size copy for srcset (ArtFigure); most screens show the art ~380px wide.
    im.resize((im.width // 2, im.height // 2), Image.LANCZOS).save(dst.replace('.webp', '-sm.webp'), quality=78, method=6)
    print(f'{dst}: {c1 - c0}x{r1 - r0} (+ -sm)')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('src')
    p.add_argument('dst')
    p.add_argument('--seed', type=int, help='default: derived from the file name, so re-runs match')
    p.add_argument('--size', type=int, default=1400)
    p.add_argument('--palette', choices=sorted(PALETTES), default='indigo')
    args = p.parse_args()
    seed = args.seed if args.seed is not None else zlib.crc32(os.path.basename(args.src).encode())
    run(args.src, args.dst, seed, args.size, args.palette)
