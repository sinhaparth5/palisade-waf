import { useId, type ReactNode } from "react";
import { Slot } from "radix-ui";
import { cn } from "@/lib/utils";

// Shared page structure: every page builds from these instead of one-off
// class strings, so widths, gaps, titles and actions line up everywhere.
// One spacing scale: gap-6 between blocks, px-5 sm:px-6 inside cards.

export const labelMono = "font-mono text-[11px] font-medium uppercase tracking-[.08em] text-slate-500";

// Page is the content column inside the shell: one padding, one gap.
export function Page({ children }: { children: ReactNode }) {
  return <div className="flex flex-col gap-6">{children}</div>;
}

// PageHeader: breadcrumb, title (also the tab title) and the page's actions,
// always in the same place.
export function PageHeader({ title, actions }: { title: string; actions?: ReactNode }) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-4">
      <title>{`Palisade · ${title}`}</title>
      <div>
        <p className={cn(labelMono, "mb-1")}>Admin / {title}</p>
        <h1 className="text-[22px] leading-tight text-ink sm:text-[26px]">{title}</h1>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

// Card has fixed slots: category + title + action in the header, the body,
// and a footer whose buttons sit bottom-right even when a Grid row stretches
// the card.
export function Card({
  cat,
  title,
  action,
  footer,
  className,
  children,
}: {
  cat?: string;
  title?: string;
  action?: ReactNode;
  footer?: ReactNode;
  className?: string;
  children: ReactNode;
}) {
  return (
    <section className={cn("flex flex-col border border-edge bg-card", className)}>
      {(title || action) && (
        <div className="flex items-center justify-between gap-4 border-b border-edge px-5 py-4 sm:px-6">
          <div className="min-w-0">
            {cat && <p className={cn(labelMono, "mb-[2px]")}>{cat}</p>}
            {title && <h2 className="font-mono text-[15px] font-medium uppercase tracking-[.04em] text-ink">{title}</h2>}
          </div>
          {action && <div className="flex shrink-0 items-center gap-2">{action}</div>}
        </div>
      )}
      <div className="flex-1 px-5 py-4 sm:px-6">{children}</div>
      {footer && <div className="flex flex-wrap justify-end gap-2 border-t border-edge px-5 py-3 sm:px-6">{footer}</div>}
    </section>
  );
}

const columns = { 1: "", 2: "lg:grid-cols-2", 3: "md:grid-cols-2 xl:grid-cols-3" } as const;

// Grid: cards in a row share height (grid stretch + Card's flex column).
export function Grid({ cols = 2, children }: { cols?: keyof typeof columns; children: ReactNode }) {
  return <div className={cn("grid grid-cols-1 gap-6", columns[cols])}>{children}</div>;
}

// FormRow: label, control, help and error in the same order and spacing in
// every form. The control (one element) gets the id, aria-describedby and
// aria-invalid, so the label and messages are announced with it.
export function FormRow({
  label,
  help,
  error,
  children,
}: {
  label: string;
  help?: ReactNode;
  error?: string;
  children: ReactNode;
}) {
  const id = useId();
  const described = [help && `${id}-help`, error && `${id}-error`].filter(Boolean).join(" ") || undefined;
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className={labelMono}>
        {label}
      </label>
      <Slot.Root id={id} aria-describedby={described} aria-invalid={error ? true : undefined}>
        {children}
      </Slot.Root>
      {help && (
        <p id={`${id}-help`} className="text-xs text-slate-600">
          {help}
        </p>
      )}
      {error && (
        <p id={`${id}-error`} className="text-xs text-red-600">
          {error}
        </p>
      )}
    </div>
  );
}
