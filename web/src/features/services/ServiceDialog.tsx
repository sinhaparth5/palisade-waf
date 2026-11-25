import { useState, type ReactNode } from "react";
import { toast } from "sonner";
import { useConfirm } from "@/components/Confirm";
import { FormRow } from "@/components/layout/Page";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { FormError, btn, field, fieldError, help } from "@/features/rules/shared";
import { can } from "@/lib/boot";
import { cn } from "@/lib/utils";
import { BotTab, GateTab, UploadsTab } from "./Protection";
import { BackendsTab, HostsTab, RateLimitTab } from "./Routing";
import { useDeleteService, useSetService, type Service, type ServicesPage } from "./api";

// ServiceDialog holds every setting of one service in tabs. Admins save one
// form at a time; viewers see the same forms disabled. A Docker-managed
// service's name, hosts and backends come from its container labels.

export type TabProps = { s: Service; d: ServicesPage };

const tabs: { id: string; label: string; show?: (s: Service) => boolean; body: (p: TabProps) => ReactNode }[] = [
  { id: "ratelimit", label: "Rate limit", body: ({ s }) => <RateLimitTab key={JSON.stringify(s.rate_limit)} s={s} /> },
  { id: "backends", label: "Backends", body: ({ s }) => <BackendsTab key={JSON.stringify({ ...s.backends, health: null })} s={s} /> },
  { id: "hosts", label: "Hosts", show: (s) => !!s.host, body: ({ s }) => <HostsTab key={JSON.stringify(s.hosts)} s={s} /> },
  { id: "bot", label: "Bot", body: ({ s }) => <BotTab key={JSON.stringify(s.bot)} s={s} /> },
  { id: "uploads", label: "Uploads", body: ({ s }) => <UploadsTab key={JSON.stringify(s.uploads)} s={s} /> },
  { id: "gate", label: "Availability", body: ({ s }) => <GateTab key={JSON.stringify(s.gate)} s={s} /> },
];

export function ServiceDialog({ d, s, onClose }: { d: ServicesPage; s: Service; onClose: () => void }) {
  const admin = can("admin");
  const shown = tabs.filter((t) => !t.show || t.show(s));
  const [tab, setTab] = useState(shown[0]!.id);
  const current = shown.find((t) => t.id === tab) ?? shown[0]!;
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[92dvh] overflow-y-auto rounded-none border-edge bg-canvas sm:max-w-3xl">
        <DialogTitle className="font-mono text-[15px] font-medium uppercase tracking-[.04em] text-ink">
          {admin ? "Edit" : "View"} {s.name}
        </DialogTitle>
        <DialogDescription className="text-[12px] text-slate-500">
          {s.host || s.prefix} → {s.backends.urls[0] ?? "no running container"}
        </DialogDescription>
        {admin && !s.docker && <Rename key={s.name} s={s} />}
        {s.docker && (
          <p className={cn(help, "leading-normal")}>
            Managed by Docker: the name, hosts and backends come from the container's <span className="font-mono">palisade.*</span> labels. Every other setting is yours to change.
          </p>
        )}
        <div role="tablist" aria-label="Service settings" className="flex flex-wrap gap-1 border border-edge p-1">
          {shown.map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              id={`svc-tab-${t.id}`}
              aria-selected={t.id === current.id}
              aria-controls="svc-tabpanel"
              onClick={() => setTab(t.id)}
              className="min-h-9 flex-1 cursor-pointer whitespace-nowrap rounded-sm px-2 font-mono text-[11px] uppercase tracking-[.04em] text-slate-500 hover:text-ink aria-selected:bg-ink aria-selected:text-canvas"
            >
              {t.label}
            </button>
          ))}
        </div>
        <div role="tabpanel" id="svc-tabpanel" aria-labelledby={`svc-tab-${current.id}`} className="min-w-0">
          {current.body({ s, d })}
        </div>
        {admin && <Remove s={s} onRemoved={onClose} />}
      </DialogContent>
    </Dialog>
  );
}

function Rename({ s }: { s: Service }) {
  const save = useSetService<{ name: string }>(s.id, "name");
  const [name, setName] = useState(s.name);
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate({ name }, { onSuccess: () => toast.success(`Renamed to ${name.trim()}.`) });
      }}
      className="flex flex-col gap-2"
    >
      <FormRow label="Name" error={fieldError(save.error, "name")} help="Rules, exceptions and feedback move with the name. Past log entries keep the old one.">
        <input value={name} onChange={(e) => setName(e.target.value)} maxLength={255} className={field} />
      </FormRow>
      <FormError error={save.error} fields={["name"]} />
      <button type="submit" disabled={save.isPending || name.trim() === s.name} className={cn(btn, "self-start")}>
        Rename
      </button>
    </form>
  );
}

function Remove({ s, onRemoved }: { s: Service; onRemoved: () => void }) {
  const remove = useDeleteService();
  const [dialog, ask] = useConfirm();
  return (
    <div className="border-t border-line pt-4">
      <FormError error={remove.error} fields={[]} />
      <button
        type="button"
        onClick={() =>
          ask({
            title: `Remove ${s.name}?`,
            body: "Its traffic stops being routed straight away, and its settings are deleted. Rules scoped to it stay until you remove them.",
            label: "Remove",
            run: () =>
              remove.mutate(s.id, {
                onSuccess: () => {
                  toast.success(`Removed ${s.name}.`);
                  onRemoved();
                },
              }),
          })
        }
        className={cn(btn, "w-full border-red-300 text-red-600 hover:bg-red-50")}
      >
        Remove this service
      </button>
      {dialog}
    </div>
  );
}
