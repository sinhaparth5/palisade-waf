import type { ReactNode } from "react";
import { toast } from "sonner";
import { labelMono } from "@/components/layout/Page";
import { FormError, help, primary } from "@/features/rules/shared";
import { can } from "@/lib/boot";
import { cn } from "@/lib/utils";

// Form pieces every tab of the service dialog shares.

// TabForm is one form inside a tab: a heading and intro, the fields, the
// server's error, and Save for admins. locked keeps it read-only for
// admins too (a Docker-managed routing tab).
export function TabForm({
  title,
  intro,
  onSubmit,
  pending,
  error,
  fields,
  locked,
  children,
}: {
  title?: string;
  intro?: ReactNode;
  onSubmit: (f: FormData) => void;
  pending: boolean;
  error: unknown;
  fields: string[];
  locked?: boolean;
  children: ReactNode;
}) {
  const edit = can("admin") && !locked;
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(new FormData(e.currentTarget));
      }}
      className="border-line not-first:mt-6 not-first:border-t not-first:pt-5"
    >
      <fieldset disabled={!edit} className="flex min-w-0 flex-col gap-4">
        {title && <h3 className={cn(labelMono, "text-ink")}>{title}</h3>}
        {intro && <p className={cn(help, "leading-normal")}>{intro}</p>}
        {children}
        <FormError error={error} fields={fields} />
        {edit && (
          <button type="submit" disabled={pending} className={primary}>
            <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-checkmark-circle-02 text-sm" />
            Save &amp; apply
          </button>
        )}
      </fieldset>
    </form>
  );
}

export const saved = () => toast.success("Saved and applied.");
export const str = (f: FormData, k: string) => String(f.get(k) ?? "").trim();
export const num = (f: FormData, k: string) => Number(f.get(k) || 0);
export const code = "bg-surface px-1 font-mono text-[11px]";

// Choice is a radio drawn as a bordered card with a title and a line of copy.
export function Choice({ name, value, on, title, copy }: { name: string; value: string; on: boolean; title: string; copy: string }) {
  return (
    <label className="flex cursor-pointer items-start gap-3 rounded-sm border border-line p-3 hover:border-edge has-checked:border-edge has-checked:bg-surface">
      <input type="radio" name={name} value={value} defaultChecked={on} className="mt-[3px] shrink-0 accent-ink" />
      <span>
        <span className="block text-[13px] font-semibold text-ink">{title}</span>
        <span className="mt-[2px] block text-[12px] text-slate-500">{copy}</span>
      </span>
    </label>
  );
}
