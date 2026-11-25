import palisade from "@/assets/art/palisade.webp";
import palisadeSm from "@/assets/art/palisade-sm.webp";
import rack from "@/assets/art/rack.webp";
import rackSm from "@/assets/art/rack-sm.webp";
import { cn } from "@/lib/utils";

// Decorative scenes drawn by scripts/art (render.py, then dissolve.py with
// the ledger palette). Transparent WebP, so one file sits on both themes.
const scenes = {
  palisade: { full: palisade, sm: palisadeSm, w: 758, h: 959 },
  rack: { full: rack, sm: rackSm, w: 687, h: 1068 },
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
