import { cn } from "@/lib/utils";

// One rendering of a scene: full file, half-size file, full pixel size.
export type ArtFile = { full: string; sm: string; w: number; h: number };
export type ArtPair = { light: ArtFile; dark: ArtFile };

// ArtImage shows the light or dark rendering of a scene (dissolve.py
// --palette ledger-light / ledger-dark) for the current theme. The other one
// is display:none and lazy, so the browser never fetches it. className goes on
// both images and must not set display. Decorative only: empty alt, hidden
// from assistive tech; width and height reserve the space before it loads.
export function ArtImage({ art, sizes, className, priority }: { art: ArtPair; sizes: string; className?: string; priority?: boolean }) {
  // priority goes to the one the theme shows now; the other stays lazy.
  const dark = document.documentElement.dataset.theme === "dark";
  return (
    <>
      <Img f={art.light} sizes={sizes} priority={priority && !dark} className={cn("dark:hidden", className)} />
      <Img f={art.dark} sizes={sizes} priority={priority && dark} className={cn("hidden dark:block", className)} />
    </>
  );
}

const Img = ({ f, sizes, className, priority }: { f: ArtFile; sizes: string; className: string; priority?: boolean }) => (
  <img
    src={f.sm}
    srcSet={`${f.sm} ${f.w >> 1}w, ${f.full} ${f.w}w`}
    sizes={sizes}
    width={f.w}
    height={f.h}
    alt=""
    aria-hidden
    decoding="async"
    loading={priority ? undefined : "lazy"}
    fetchPriority={priority ? "high" : undefined}
    draggable={false}
    className={cn(
      "pointer-events-none h-auto select-none",
      // Lazy art fades in; the priority image is the page's main one and shows at once.
      !priority && "transition-opacity duration-700 ease-out starting:opacity-0 motion-reduce:transition-none",
      className,
    )}
  />
);

// A faint ruled grid, like drafting paper, from the theme's hairline colour.
// Absolute: put it first inside a relative, overflow-hidden box.
export const drafting =
  "pointer-events-none absolute inset-0 bg-[linear-gradient(to_right,var(--color-rule)_1px,transparent_1px),linear-gradient(to_bottom,var(--color-rule)_1px,transparent_1px)] bg-size-[32px_32px] opacity-60";
