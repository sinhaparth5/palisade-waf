import type { ReactNode } from "react";
import beacon from "@/assets/art/beacon.webp";
import beaconSm from "@/assets/art/beacon-sm.webp";
import consoleArt from "@/assets/art/console.webp";
import consoleSm from "@/assets/art/console-sm.webp";
import palisade from "@/assets/art/palisade.webp";
import palisadeSm from "@/assets/art/palisade-sm.webp";
import rack from "@/assets/art/rack.webp";
import rackSm from "@/assets/art/rack-sm.webp";
import sieve from "@/assets/art/sieve.webp";
import sieveSm from "@/assets/art/sieve-sm.webp";
import vault from "@/assets/art/vault.webp";
import vaultSm from "@/assets/art/vault-sm.webp";
import { labelMono } from "@/components/layout/Page";
import { cn } from "@/lib/utils";

// Decorative scenes drawn by scripts/art (render.py, then dissolve.py with
// the ledger palette). Transparent WebP, so one file sits on both themes.
const scenes = {
  palisade: { full: palisade, sm: palisadeSm, w: 601, h: 793 },
  rack: { full: rack, sm: rackSm, w: 594, h: 917 },
  vault: { full: vault, sm: vaultSm, w: 591, h: 818 },
  beacon: { full: beacon, sm: beaconSm, w: 585, h: 976 },
  sieve: { full: sieve, sm: sieveSm, w: 583, h: 808 },
  console: { full: consoleArt, sm: consoleSm, w: 583, h: 791 },
};

// Art is decoration only: empty alt and hidden from assistive tech. Width and
// height reserve the space before it loads; size it with a width class.
export function Art({ name, className }: { name: keyof typeof scenes; className?: string }) {
  const s = scenes[name];
  return (
    <img
      src={s.sm}
      srcSet={`${s.sm} ${s.w >> 1}w, ${s.full} ${s.w}w`}
      sizes="(min-width: 640px) 280px, 200px"
      width={s.w}
      height={s.h}
      alt=""
      aria-hidden
      decoding="async"
      loading="lazy"
      draggable={false}
      className={cn("pointer-events-none h-auto select-none transition-opacity duration-700 ease-out starting:opacity-0 motion-reduce:transition-none", className)}
    />
  );
}

// ArtHero opens a page: eyebrow, title and a line of copy on the left, the
// whole scene on the right, sized to the card's height so neither its rising
// dashes nor its streaks are cut off. Hidden on phones.
export function ArtHero({ art, eyebrow, title, children }: { art: keyof typeof scenes; eyebrow: string; title: string; children: ReactNode }) {
  return (
    <section className="relative overflow-hidden border border-edge bg-card sm:min-h-[240px]">
      <div className="relative z-10 flex flex-col gap-3 p-6 sm:pr-[240px] lg:pr-[260px]">
        <p className={labelMono}>{eyebrow}</p>
        <h2 className="text-[24px] leading-tight text-ink sm:text-[30px]">{title}</h2>
        {children}
      </div>
      <Art name={art} className="absolute inset-y-3 right-4 hidden h-[calc(100%-1.5rem)] w-auto max-w-[220px] object-contain object-bottom sm:block lg:right-8" />
    </section>
  );
}
