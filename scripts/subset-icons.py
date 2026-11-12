#!/usr/bin/env python3
"""Subset the hugeicons stylesheet to the icons the admin UI uses (issue #284).

Usage: subset-icons.py FULL_CSS OUT_CSS
Writes OUT_CSS with only the used .hgi-* rules and prints their code points
(comma-separated, for pyftsubset --unicodes). `make icons` runs it.
"""
import pathlib
import re
import sys

# Class names that aren't icons: the base classes on every <i>.
NOT_ICONS = {"hgi-stroke", "hgi-rounded", "hgi-stroke-rounded"}
SOURCES = ["internal/ui/templates", "static/js/src", "internal/ui"]


def used_names():
    names = set()
    for root in SOURCES:
        for p in pathlib.Path(root).rglob("*"):
            if p.suffix in (".html", ".js", ".go") and not p.name.endswith("_test.go") and "vendor" not in p.parts:
                names |= set(re.findall(r"hgi-[a-z0-9-]+", p.read_text(encoding="utf-8")))
    return sorted(names - NOT_ICONS)


def main(full_css, out_css):
    css = pathlib.Path(full_css).read_text(encoding="utf-8-sig")
    rules = dict(re.findall(r'\.hgi-stroke\.(hgi-[a-z0-9-]+):before\{content:"([^"]+)"\}', css))
    names = used_names()
    missing = [n for n in names if n not in rules]
    if missing:
        sys.exit("not in hugeicons: " + ", ".join(missing))
    out = ['@font-face{font-family:"hgi-stroke-rounded";src:url("hgi-stroke-rounded.woff2") format("woff2");font-display:block}',
           '.hgi-stroke{font-family:"hgi-stroke-rounded" !important;font-style:normal;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;position:relative}',
           '.hgi-stroke:after{opacity:.4;position:absolute;left:0}']
    out += ['.hgi-stroke.%s:before{content:"%s"}' % (n, rules[n]) for n in names]
    pathlib.Path(out_css).write_text("".join(out) + "\n", encoding="utf-8")
    print(",".join("U+%04X" % ord(rules[n]) for n in names))


if __name__ == "__main__":
    main(*sys.argv[1:3])
