import { useState, type ChangeEvent, type FormEvent } from "react";
import { toast } from "sonner";
import { ArtHero } from "@/components/Art";
import { Card, FormRow, Page, PageHeader, labelMono } from "@/components/layout/Page";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from "@/components/ui/dialog";
import { FormError, btn, field, fieldError, help, primary, tag } from "@/features/rules/shared";
import { ApiError } from "@/lib/api";
import { can } from "@/lib/boot";
import { cn } from "@/lib/utils";
import { plural, since, useAddCrowdSec, useAddFeed, useDeleteSource, useIntel, useSetEnabled, useSync, type IntelPage, type Preset, type Source } from "./api";

// Threat Intel (issue #353): IP/CIDR feeds and CrowdSec LAPIs whose entries
// block below the operator's own IP rules.

export function ThreatIntelPage() {
  const { data, isError } = useIntel();
  return (
    <Page>
      <PageHeader title="Threat Intel" />
      <ArtHero art="beacon" eyebrow="Global defense signal" title="Curated intelligence, enforced locally.">
        <p className="max-w-[56ch] text-[14px] leading-relaxed text-slate-600">
          Pull trusted IP and CIDR feeds on a schedule and block what they list. Your own allow rules always win.
        </p>
        {data && <Summary d={data} />}
      </ArtHero>
      {can("admin") && <AddFeed presets={data?.presets ?? []} added={data?.sources.map((s) => s.url) ?? []} />}
      <Card cat="Security" title="Threat Intel Feeds" action={data && <span className={cn(tag, "text-slate-600")}>{plural(data.sources.length, "feed")}</span>}>
        {isError ? (
          <p role="alert" className="py-6 text-red-600">
            Couldn't load the feeds. Reload to try again.
          </p>
        ) : !data ? (
          <p className={cn(labelMono, "py-10 text-center")}>Loading…</p>
        ) : (
          <SourceList sources={data.sources} />
        )}
      </Card>
    </Page>
  );
}

function Summary({ d }: { d: IntelPage }) {
  const active = d.sources.filter((s) => s.enabled);
  const failing = d.sources.filter((s) => s.last_error).length;
  return (
    <p className="flex flex-wrap items-center gap-x-5 gap-y-1 font-mono text-[12px] uppercase tracking-[.06em] text-ink">
      <span>
        {active.length} of {plural(d.sources.length, "source")} active
      </span>
      <span>{plural(active.reduce((n, s) => n + s.ips + s.ranges, 0), "entry", "entries")} blocking</span>
      {failing > 0 && (
        <span className="flex items-center gap-2 text-red-600">
          <span className="h-2 w-2 rounded-full bg-danger" />
          {failing} failing to sync
        </span>
      )}
    </p>
  );
}

function SourceList({ sources }: { sources: Source[] }) {
  const remove = useDeleteSource();
  const toggle = useSetEnabled();
  const sync = useSync();
  const [confirm, setConfirm] = useState<Source | null>(null);
  if (sources.length === 0) return <p className={cn(labelMono, "py-10 text-center")}>No feeds yet. Add one or pick a preset.</p>;
  const failed = remove.error ?? toggle.error ?? sync.error;
  const icon = "flex h-11 w-11 items-center justify-center rounded-sm border border-edge text-ink hover:bg-surface disabled:opacity-50 sm:h-8 sm:w-8";
  return (
    <>
      {failed != null && (
        <p role="alert" className="pb-3 text-[13px] text-red-600">
          {(failed instanceof ApiError && failed.message) || "Couldn't save. Try again."}
        </p>
      )}
      <ul>
        {sources.map((s) => {
          const syncing = sync.isPending && sync.variables === s.id;
          return (
            <li key={s.id} className="flex flex-wrap items-start gap-x-4 gap-y-2 border-b border-line py-4 first:pt-1 last:border-b-0">
              <div className="min-w-0 flex-1 basis-64">
                <p className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-ink">{s.label}</span>
                  {s.kind === "crowdsec" && <span className={cn(tag, "text-slate-600")}>CrowdSec</span>}
                  {s.push && <span className={cn(tag, "text-slate-600")}>Pushes autobans</span>}
                </p>
                <p className="mt-1 truncate font-mono text-[11px] text-slate-500" title={s.url}>
                  {s.url}
                </p>
                <p className="mt-2 text-[12px] text-slate-500">
                  {since(s.last_synced_at)}
                  {s.kind === "feed" && ` · every ${s.interval_hours} h`}
                </p>
                {s.last_error && <p className="mt-1 break-words text-[12px] text-red-600">{s.last_error}</p>}
              </div>
              <div className="text-right font-mono text-[12px] text-ink">
                {s.ips + s.ranges > 0 ? (
                  <>
                    <p>{plural(s.ips, "IP")}</p>
                    {s.ranges > 0 && <p className="text-slate-500">{plural(s.ranges, "range")}</p>}
                  </>
                ) : (
                  <p className="text-slate-500">No entries</p>
                )}
              </div>
              <span className={cn(tag, "text-ink")}>
                <span aria-hidden className={cn("h-2 w-2 rounded-full", s.enabled ? "bg-success" : "bg-slate-400")} />
                {s.enabled ? "Active" : "Paused"}
              </span>
              {can("admin") && (
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    aria-label={`Sync ${s.label} now`}
                    disabled={syncing}
                    onClick={() =>
                      sync.mutate(s.id, {
                        onSuccess: (n) => (n.last_error ? toast.error(`${n.label}: ${n.last_error}`) : toast.success(`Synced ${n.label}.`)),
                      })
                    }
                    className={icon}
                  >
                    <i aria-hidden className={cn("hgi hgi-stroke hgi-rounded hgi-refresh text-[13px]", syncing && "animate-spin motion-reduce:animate-none")} />
                  </button>
                  <button type="button" aria-label={`${s.enabled ? "Pause" : "Resume"} ${s.label}`} onClick={() => toggle.mutate({ id: s.id, enabled: !s.enabled })} className={icon}>
                    <i aria-hidden className={cn("hgi hgi-stroke hgi-rounded text-[13px]", s.enabled ? "hgi-pause" : "hgi-play")} />
                  </button>
                  <button type="button" aria-label={`Delete ${s.label}`} onClick={() => setConfirm(s)} className={cn(icon, "border-transparent text-slate-500 hover:bg-red-50 hover:text-red-600")}>
                    <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-delete-02 text-[14px]" />
                  </button>
                </div>
              )}
            </li>
          );
        })}
      </ul>
      <Dialog open={confirm !== null} onOpenChange={(open) => !open && setConfirm(null)}>
        <DialogContent className="rounded-none border-edge bg-canvas sm:max-w-md">
          <DialogTitle className="text-[16px] text-ink">Delete {confirm?.label}?</DialogTitle>
          <DialogDescription className="text-[13px] text-slate-600">
            {confirm?.kind === "crowdsec"
              ? "Its decisions stop blocking now, and the bouncer key and machine credentials are removed."
              : "Its entries stop blocking now. You can add the feed again later."}
          </DialogDescription>
          <DialogFooter>
            <button type="button" onClick={() => setConfirm(null)} className={btn}>
              Cancel
            </button>
            <button
              type="button"
              onClick={() => {
                const s = confirm!;
                remove.mutate(s.id, { onSuccess: () => toast.success(`Deleted ${s.label}.`) });
                setConfirm(null);
              }}
              className={cn(btn, "border-red-600 bg-red-600 text-white hover:bg-red-700")}
            >
              Delete
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

const code = "bg-surface px-1 font-mono text-[11px]";

function AddFeed({ presets, added }: { presets: Preset[]; added: string[] }) {
  const add = useAddFeed();
  const empty = { label: "", url: "", interval_hours: "24" };
  const [form, setForm] = useState(empty);
  const set = (k: keyof typeof empty) => (e: ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const submit = (e: FormEvent) => {
    e.preventDefault();
    add.mutate(
      { label: form.label, url: form.url, interval_hours: Number(form.interval_hours) || 0 },
      {
        onSuccess: () => {
          toast.success(`Added ${form.label.trim()}. It syncs within a minute.`);
          setForm(empty);
        },
      },
    );
  };
  return (
    <Card title="Add Feed">
      <form onSubmit={submit} className="grid grid-cols-1 items-start gap-4 md:grid-cols-2 xl:grid-cols-[1fr_1.5fr_.7fr_auto]">
        <FormRow label="Label" error={fieldError(add.error, "label")}>
          <input value={form.label} onChange={set("label")} placeholder="e.g. Tor Exit Nodes" className={field} />
        </FormRow>
        <FormRow label="URL" error={fieldError(add.error, "url")}>
          <input type="url" value={form.url} onChange={set("url")} placeholder="https://…/iplist.txt" className={cn(field, "font-mono")} />
        </FormRow>
        <FormRow label="Sync every (hours)" error={fieldError(add.error, "interval_hours")}>
          <input type="number" min={1} value={form.interval_hours} onChange={set("interval_hours")} className={field} />
        </FormRow>
        <button type="submit" disabled={add.isPending} className={cn(primary, "xl:mt-[22px]")}>
          <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-add-01 text-sm" />
          Add Feed
        </button>
        <div className="md:col-span-2 xl:col-span-4">
          <FormError error={add.error} fields={["label", "url", "interval_hours"]} />
        </div>
      </form>

      <div className="mt-5 border-t border-line pt-4">
        <p className={cn(labelMono, "mb-3")}>Quick-add presets</p>
        <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {presets.map((p) => {
            const has = added.includes(p.url);
            return (
              <li key={p.url}>
                <button
                  type="button"
                  disabled={has || add.isPending}
                  onClick={() => add.mutate(p, { onSuccess: () => toast.success(`Added ${p.label}.`) })}
                  className="flex min-h-11 w-full items-center justify-between gap-2 rounded-sm border border-edge bg-card px-3 py-2 text-left text-[12px] font-medium text-ink hover:bg-surface disabled:cursor-default disabled:opacity-60 disabled:hover:bg-card"
                >
                  <span>{p.label}</span>
                  <span className="shrink-0 text-[11px] text-slate-500">{has ? "Added" : `every ${p.interval_hours} h`}</span>
                </button>
              </li>
            );
          })}
        </ul>
      </div>

      <AddCrowdSec />

      <div className={cn(help, "mt-4 grid grid-cols-1 gap-2 border-t border-line pt-4 leading-[1.6] md:grid-cols-2")}>
        <p>
          Feeds are plain-text lists of IPs and CIDRs, one per line. Lines starting with <code className={code}>#</code> or <code className={code}>;</code> are comments.
        </p>
        <p>Intel blocks rank below your IP Rules: your allow rules always win.</p>
      </div>
    </Card>
  );
}

function AddCrowdSec() {
  const add = useAddCrowdSec();
  const empty = { label: "CrowdSec", url: "", api_key: "", machine_login: "", machine_password: "" };
  const [form, setForm] = useState(empty);
  const set = (k: keyof typeof empty) => (e: ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const err = (k: keyof typeof empty) => fieldError(add.error, k);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    add.mutate(form, {
      onSuccess: () => {
        toast.success(`Added ${form.label.trim()}. The first sync runs within 30 seconds.`);
        setForm(empty);
      },
    });
  };
  return (
    <form onSubmit={submit} className="mt-5 border-t border-line pt-4">
      <p className={cn(labelMono, "mb-3")}>CrowdSec LAPI</p>
      <div className="grid grid-cols-1 items-start gap-4 md:grid-cols-2 xl:grid-cols-3">
        <FormRow label="Label" error={err("label")}>
          <input value={form.label} onChange={set("label")} className={field} />
        </FormRow>
        <FormRow label="LAPI URL" error={err("url")}>
          <input type="url" value={form.url} onChange={set("url")} placeholder="http://127.0.0.1:8080" className={cn(field, "font-mono")} />
        </FormRow>
        <FormRow label="Bouncer API key" error={err("api_key")}>
          <input type="password" autoComplete="off" value={form.api_key} onChange={set("api_key")} placeholder="cscli bouncers add palisade" className={cn(field, "font-mono")} />
        </FormRow>
        <FormRow label="Machine login (optional)" error={err("machine_login")}>
          <input autoComplete="off" value={form.machine_login} onChange={set("machine_login")} placeholder="cscli machines add palisade" className={cn(field, "font-mono")} />
        </FormRow>
        <FormRow label="Machine password (optional)" error={err("machine_password")}>
          <input type="password" autoComplete="new-password" value={form.machine_password} onChange={set("machine_password")} className={cn(field, "font-mono")} />
        </FormRow>
        <button type="submit" disabled={add.isPending} className={cn(primary, "xl:mt-[22px]")}>
          <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-add-01 text-sm" />
          Add LAPI
        </button>
      </div>
      <div className="mt-3">
        <FormError error={add.error} fields={Object.keys(empty)} />
      </div>
      <p className={cn(help, "mt-3 leading-[1.6]")}>
        Polled every 30 seconds; after the first sync only changes are transferred. Ban decisions block (logged as <code className={code}>ip_blocked:crowdsec</code>) until CrowdSec expires them; captcha decisions
        are ignored. With machine credentials every autoban is also pushed as a <code className={code}>palisade/autoban</code> alert, so other bouncers on the LAPI block the IP for the same ban length. Keys are stored
        sealed and never shown again.
      </p>
    </form>
  );
}
