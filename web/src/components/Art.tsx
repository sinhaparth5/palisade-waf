import type { ReactNode } from "react";
import palisade from "@/assets/art/palisade.webp";
import palisadeSm from "@/assets/art/palisade-sm.webp";
import rack from "@/assets/art/rack.webp";
import rackSm from "@/assets/art/rack-sm.webp";
import vault from "@/assets/art/vault.webp";
import vaultSm from "@/assets/art/vault-sm.webp";
import { labelMono } from "@/components/layout/Page";
import { cn } from "@/lib/utils";

// Decorative scenes drawn by scripts/art (render.py, then dissolve.py with
// the ledger palette). Transparent WebP, so one file sits on both themes.
const scenes = {
  palisade: { full: palisade, sm: palisadeSm, w: 758, h: 959 },
  rack: { full: rack, sm: rackSm, w: 687, h: 1068 },
  vault: { full: vault, sm: vaultSm, w: 753, h: 1010 },
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
// scene bleeding off the card's right edge. The scene is clipped only at the
// top (its rising dashes) and the bottom (its streaks), and hidden on phones.
export function ArtHero({ art, eyebrow, title, children }: { art: keyof typeof scenes; eyebrow: string; title: string; children: ReactNode }) {
  return (
    <section className="relative overflow-hidden border border-edge bg-card sm:min-h-[220px]">
      <div className="relative z-10 flex flex-col gap-3 p-6 sm:pr-[260px]">
        <p className={labelMono}>{eyebrow}</p>
        <h2 className="text-[24px] leading-tight text-ink sm:text-[30px]">{title}</h2>
        {children}
      </div>
      <Art name={art} className="absolute right-2 -bottom-10 hidden w-[240px] sm:block lg:right-8" />
    </section>
  );
}
