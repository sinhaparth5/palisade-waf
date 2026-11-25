import type { ReactNode } from "react";
import palisade from "@/assets/art/palisade.webp";
import palisadeSm from "@/assets/art/palisade-sm.webp";
import palisadeDark from "@/assets/art/palisade-dark.webp";
import palisadeDarkSm from "@/assets/art/palisade-dark-sm.webp";
import rack from "@/assets/art/rack.webp";
import rackSm from "@/assets/art/rack-sm.webp";
import rackDark from "@/assets/art/rack-dark.webp";
import rackDarkSm from "@/assets/art/rack-dark-sm.webp";
import vault from "@/assets/art/vault.webp";
import vaultSm from "@/assets/art/vault-sm.webp";
import vaultDark from "@/assets/art/vault-dark.webp";
import vaultDarkSm from "@/assets/art/vault-dark-sm.webp";
import beacon from "@/assets/art/beacon.webp";
import beaconSm from "@/assets/art/beacon-sm.webp";
import beaconDark from "@/assets/art/beacon-dark.webp";
import beaconDarkSm from "@/assets/art/beacon-dark-sm.webp";
import sieve from "@/assets/art/sieve.webp";
import sieveSm from "@/assets/art/sieve-sm.webp";
import sieveDark from "@/assets/art/sieve-dark.webp";
import sieveDarkSm from "@/assets/art/sieve-dark-sm.webp";
import consoleArt from "@/assets/art/console.webp";
import consoleSm from "@/assets/art/console-sm.webp";
import consoleDark from "@/assets/art/console-dark.webp";
import consoleDarkSm from "@/assets/art/console-dark-sm.webp";
import { ArtImage, drafting, type ArtPair } from "@/components/ArtImage";
import { cn } from "@/lib/utils";
import { labelMono } from "@/components/layout/Page";

// Decorative scenes drawn by scripts/art (render.py, then dissolve.py
// --palette ledger-light and ledger-dark --headroom 0.18), one file per theme.
// Sizes are what dissolve.py prints.
const scenes = {
  palisade: { light: { full: palisade, sm: palisadeSm, w: 733, h: 781 }, dark: { full: palisadeDark, sm: palisadeDarkSm, w: 742, h: 781 } },
  rack: { light: { full: rack, sm: rackSm, w: 665, h: 870 }, dark: { full: rackDark, sm: rackDarkSm, w: 673, h: 870 } },
  vault: { light: { full: vault, sm: vaultSm, w: 728, h: 821 }, dark: { full: vaultDark, sm: vaultDarkSm, w: 737, h: 821 } },
  beacon: { light: { full: beacon, sm: beaconSm, w: 611, h: 870 }, dark: { full: beaconDark, sm: beaconDarkSm, w: 618, h: 870 } },
  sieve: { light: { full: sieve, sm: sieveSm, w: 723, h: 817 }, dark: { full: sieveDark, sm: sieveDarkSm, w: 731, h: 817 } },
  console: { light: { full: consoleArt, sm: consoleSm, w: 723, h: 794 }, dark: { full: consoleDark, sm: consoleDarkSm, w: 731, h: 794 } },
} satisfies Record<string, ArtPair>;

// Size it with a width class; className must not set display (see ArtImage).
export function Art({ name, className }: { name: keyof typeof scenes; className?: string }) {
  return <ArtImage art={scenes[name]} sizes="(min-width: 640px) 240px, 200px" className={className} />;
}

export type Stat = { label: string; value: ReactNode; tone?: "danger" | "warning" };

const statCols = { 1: "sm:grid-cols-1", 2: "sm:grid-cols-2", 3: "sm:grid-cols-3", 4: "sm:grid-cols-4", 5: "sm:grid-cols-5" } as const;

// ArtHero opens a page: eyebrow, title and copy on the left, the scene on
// the right over a drafting grid, and an optional strip of key figures along
// the bottom. The scene is hidden on phones.
export function ArtHero({ art, eyebrow, title, stats, children }: { art: keyof typeof scenes; eyebrow: string; title: string; stats?: Stat[]; children: ReactNode }) {
  return (
    <section className="relative overflow-hidden border border-edge bg-card">
      <div className={cn(drafting, "[mask-image:linear-gradient(to_right,transparent_30%,black_75%)]")} />
      <div className="relative sm:min-h-[220px]">
        <div className="relative z-10 flex flex-col gap-3 p-6 sm:pr-[300px] lg:pr-[340px]">
          <p className={labelMono}>{eyebrow}</p>
          <h2 className="text-[24px] leading-tight text-ink sm:text-[30px]">{title}</h2>
          {children}
        </div>
        <div className="absolute inset-y-0 right-0 hidden w-[280px] sm:block lg:right-6 lg:w-[320px]">
          <Art name={art} className="absolute right-0 bottom-0 h-[calc(100%-0.75rem)] w-auto max-w-full object-contain object-right-bottom" />
        </div>
      </div>
      {stats && stats.length > 0 && (
        <dl className={cn("relative z-10 grid grid-cols-2 gap-px border-t border-edge bg-edge", statCols[Math.min(stats.length, 5) as keyof typeof statCols])}>
          {stats.map((s) => (
            <div key={s.label} className="bg-card px-6 py-3">
              <dt className={labelMono}>{s.label}</dt>
              <dd className={cn("mt-1 flex items-center gap-2 font-mono text-[18px] tabular-nums", s.tone === "danger" ? "text-red-600" : s.tone === "warning" ? "text-amber-700" : "text-ink")}>
                {s.tone && <span aria-hidden className={cn("h-2 w-2 rounded-full", s.tone === "danger" ? "bg-danger" : "bg-warning")} />}
                {s.value}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </section>
  );
}
