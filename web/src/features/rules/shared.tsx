import { useState, type ReactNode } from "react";
import { Card, FormRow, labelMono } from "@/components/layout/Page";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from "@/components/ui/dialog";
import { useLogApps } from "@/features/logs/api";
import { ApiError } from "@/lib/api";
import { can } from "@/lib/boot";
import { cn } from "@/lib/utils";
import type { RuleType } from "./api";

// Pieces the IP Rules and Geo Rules pages share: the add form's scope and
// action fields, the overview, and the rule list with bulk remove.

export const field = "min-h-11 w-full rounded-sm border border-edge bg-card px-3 py-2 text-[13px] text-ink aria-invalid:border-red-500";
export const btn =
  "flex min-h-11 cursor-pointer items-center justify-center gap-[6px] rounded-sm border border-edge bg-transparent px-4 py-2 font-mono text-[12px] uppercase tracking-[.04em] text-ink hover:bg-surface disabled:cursor-default disabled:opacity-50";
export const primary = cn(btn, "border-ink bg-ink text-canvas hover:bg-ink/90");
export const help = "text-[12px] text-slate-500";
export const tag = "inline-flex shrink-0 items-center gap-[6px] rounded-sm border border-edge px-2 py-[3px] font-mono text-[11px] uppercase tracking-[.04em]";

// fieldError is the server's message for one field of a failed write.
export const fieldError = (err: unknown, name: string) => (err instanceof ApiError ? err.fields?.[name] : undefined);

// formError is a failed write's message when no field carries it.
export function FormError({ error, fields }: { error: unknown; fields: string[] }) {
  if (!error || fields.some((f) => fieldError(error, f))) return null;
  return (
    <p role="alert" className="text-[13px] text-red-600">
      {(error instanceof ApiError && error.message) || "Couldn't save. Try again."}
    </p>
  );
}

export function RuleBadge({ type }: { type: RuleType }) {
  return (
    <span className={cn(tag, type === "block" ? "text-red-600" : "text-green-600")}>
      <span aria-hidden className={cn("h-2 w-2 rounded-full", type === "block" ? "bg-red-500" : "bg-green-500")} />
      {type}
    </span>
  );
}

// ScopeAction is the add form's Scope select and Block/Allow radios, read
// from FormData as app_name and rule_type.
export function ScopeAction({ error }: { error: unknown }) {
  const { data: apps } = useLogApps();
  const scopeErr = fieldError(error, "app_name");
  return (
    <>
      <FormRow label="Scope" error={scopeErr}>
        <select name="app_name" className={field}>
          <option value="">Global (all apps)</option>
          {apps?.map((a) => (
            <option key={a} value={a}>
              {a} only
            </option>
          ))}
        </select>
      </FormRow>
      <fieldset className="min-w-0">
        <legend className={cn(labelMono, "mb-[6px]")}>Action</legend>
        <div className="flex min-h-11 items-center gap-4">
          <label className="flex cursor-pointer items-center gap-2">
            <input type="radio" name="rule_type" value="block" defaultChecked className="accent-red-500" />
            <span className="font-mono text-[13px] text-red-600 uppercase">Block</span>
          </label>
          <label className="flex cursor-pointer items-center gap-2">
            <input type="radio" name="rule_type" value="allow" className="accent-ink" />
            <span className="font-mono text-[13px] text-green-600 uppercase">Allow</span>
          </label>
        </div>
      </fieldset>
    </>
  );
}

export function Overview({ block, allow, what }: { block: number; allow: number; what: string }) {
  const total = block + allow;
  const pct = (n: number) => (total ? Math.round((n * 100) / total) : 0);
  return (
    <Card title="Rules overview">
      <div className="flex flex-col gap-4">
        {(
          [
            ["Block rules", `deny matching ${what}`, block, "bg-red-500"],
            ["Allow rules", "whitelist, bypasses other blocks", allow, "bg-green-500"],
          ] as const
        ).map(([title, sub, n, fill]) => (
          <div key={title}>
            <div className="mb-1 flex items-baseline justify-between gap-3">
              <span className="text-[13px] font-medium text-ink">{title}</span>
              <span className="font-mono text-[13px] text-ink tabular-nums">
                {n} <span className="text-slate-500">· {pct(n)}%</span>
              </span>
            </div>
            <div className="h-2 bg-surface">
              <div className={cn("h-full", fill, pctWidth(pct(n)))} />
            </div>
            <p className={cn(help, "mt-1")}>{sub}</p>
          </div>
        ))}
      </div>
    </Card>
  );
}

// Widths as classes in 5% steps: a style attribute would break the CSP.
const widths = ["w-0", "w-[5%]", "w-[10%]", "w-[15%]", "w-[20%]", "w-[25%]", "w-[30%]", "w-[35%]", "w-[40%]", "w-[45%]", "w-[50%]", "w-[55%]", "w-[60%]", "w-[65%]", "w-[70%]", "w-[75%]", "w-[80%]", "w-[85%]", "w-[90%]", "w-[95%]", "w-full"];
export const pctWidth = (pct: number) => widths[Math.round(Math.min(100, Math.max(0, pct)) / 5)]!;

// RuleList shows rules with a checkbox each (admins only) and removes the
// ticked ones, or one row from its own button, after a confirmation.
export function RuleList<R>({
  rows,
  id,
  label,
  row,
  empty,
  remove,
  footer,
}: {
  rows: R[];
  id: (r: R) => number;
  label: (r: R) => string;
  row: (r: R) => ReactNode;
  empty: string;
  remove: { mutate: (ids: number[], o: { onSuccess: () => void }) => void; isPending: boolean; error: unknown };
  footer?: ReactNode;
}) {
  const admin = can("admin");
  const [picked, setPicked] = useState<Set<number>>(new Set());
  const [confirm, setConfirm] = useState<number[] | null>(null);
  // Only ids still on screen count: a refetch may have dropped some.
  const shown = rows.map(id);
  const selected = shown.filter((i) => picked.has(i));
  const toggle = (i: number) => setPicked((s) => (s.has(i) ? new Set([...s].filter((x) => x !== i)) : new Set(s).add(i)));
  const allOn = shown.length > 0 && selected.length === shown.length;
  const named = (ids: number[]) => (ids.length === 1 ? label(rows.find((r) => id(r) === ids[0])!) : `${ids.length} rules`);

  return (
    <>
      {admin && rows.length > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-3 pb-3">
          <label className="flex cursor-pointer items-center gap-2 text-[13px] text-slate-600">
            <input type="checkbox" checked={allOn} onChange={() => setPicked(allOn ? new Set() : new Set(shown))} className="h-4 w-4 accent-ink" />
            Select all on this page
          </label>
          <button type="button" disabled={selected.length === 0} onClick={() => setConfirm(selected)} className={cn(btn, "text-red-600")}>
            <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-delete-02 text-[13px]" />
            Remove selected{selected.length > 0 && ` (${selected.length})`}
          </button>
        </div>
      )}
      {remove.error != null && (
        <p role="alert" className="px-3 pt-3 text-[13px] text-red-600">
          {(remove.error instanceof ApiError && remove.error.message) || "Couldn't remove. Try again."}
        </p>
      )}
      {rows.length === 0 ? (
        <p className={cn(labelMono, "py-10 text-center")}>{empty}</p>
      ) : (
        <ul>
          {rows.map((r) => (
            <li key={id(r)} className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line px-3 py-3 last:border-b-0 hover:bg-surface">
              {admin && <input type="checkbox" aria-label={`Select ${label(r)}`} checked={picked.has(id(r))} onChange={() => toggle(id(r))} className="h-4 w-4 accent-ink" />}
              {row(r)}
              {admin && (
                <button type="button" aria-label={`Remove ${label(r)}`} onClick={() => setConfirm([id(r)])} className="flex h-11 w-11 items-center justify-center rounded-sm text-slate-500 hover:bg-red-50 hover:text-red-600 sm:h-8 sm:w-8">
                  <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-delete-02 text-[14px]" />
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      {footer}
      <Dialog open={confirm !== null} onOpenChange={(open) => !open && setConfirm(null)}>
        <DialogContent className="rounded-none border-edge bg-canvas sm:max-w-md">
          <DialogTitle className="text-[16px] text-ink">Remove {confirm && named(confirm)}?</DialogTitle>
          <DialogDescription className="text-[13px] text-slate-600">Traffic it matched goes through the other rules again straight away.</DialogDescription>
          <DialogFooter>
            <button type="button" onClick={() => setConfirm(null)} className={btn}>
              Cancel
            </button>
            <button
              type="button"
              disabled={remove.isPending}
              onClick={() => {
                const ids = confirm ?? [];
                remove.mutate(ids, { onSuccess: () => setPicked((s) => new Set([...s].filter((x) => !ids.includes(x)))) });
                setConfirm(null);
              }}
              className={cn(btn, "border-red-600 bg-red-600 text-white hover:bg-red-700")}
            >
              Remove
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

// SettingsCard is one settings form: viewers see it read-only, admins save
// it with one button and see the server's field errors under each field.
export function SettingsCard({
  title,
  intro,
  onSubmit,
  pending,
  error,
  fields,
  children,
}: {
  title: string;
  intro: ReactNode;
  onSubmit: (f: FormData) => void;
  pending: boolean;
  error: unknown;
  fields: string[];
  children: ReactNode;
}) {
  const admin = can("admin");
  return (
    <Card title={title}>
      {/* A full-height column, so in a row of stretched cards every Save
          button sits on the same line at the bottom. */}
      <div className="flex h-full flex-col">
      <p className={cn(help, "mb-4")}>{intro}</p>
      <form
        className="flex flex-1 flex-col"
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit(new FormData(e.currentTarget));
        }}
      >
        <fieldset disabled={!admin} className="flex flex-1 flex-col gap-4">
          {children}
          <FormError error={error} fields={fields} />
          {admin && (
            <button type="submit" disabled={pending} className={cn(primary, "mt-auto")}>
              <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-checkmark-circle-02 text-sm" />
              Save &amp; apply
            </button>
          )}
        </fieldset>
      </form>
      </div>
    </Card>
  );
}

export function Toggle({ name, label, on }: { name: string; label: string; on: boolean }) {
  return (
    <label className="flex cursor-pointer items-center justify-between gap-3">
      <span className="text-[13px] font-medium text-ink">{label}</span>
      <input type="checkbox" name={name} defaultChecked={on} className="h-5 w-5 accent-ink" />
    </label>
  );
}

export function Num({ name, label, value, error, min, max, step, className }: { name: string; label: string; value: number | string; error: unknown; min?: number; max?: number; step?: number; className?: string }) {
  return (
    <div className={cn("min-w-0", className)}>
      <FormRow label={label} error={fieldError(error, name)}>
        <input name={name} type={typeof value === "number" ? "number" : "text"} min={min} max={max} step={step} defaultValue={value} className={field} />
      </FormRow>
    </div>
  );
}
