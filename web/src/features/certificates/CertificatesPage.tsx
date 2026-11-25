import { useState, type ChangeEvent, type FormEvent } from "react";
import { toast } from "sonner";
import { ArtHero } from "@/components/Art";
import { Card, FormRow, Page, PageHeader, labelMono } from "@/components/layout/Page";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from "@/components/ui/dialog";
import { FormError, btn, field, fieldError, help, primary, tag } from "@/features/rules/shared";
import { ApiError } from "@/lib/api";
import { boot, can } from "@/lib/boot";
import { cn } from "@/lib/utils";
import { expiry, fmtDate, useAddCert, useCerts, useDeleteCert, type Cert, type CertsPage, type ServiceTLS } from "./api";

// Certificates (issue #352): the shared pool services pick from, and each
// host-matched service's TLS at a glance. Changing a service's TLS stays on
// the Services page.

export function CertificatesPage() {
  const { data, isError } = useCerts();
  return (
    <Page>
      <PageHeader title="Certificates" />
      <ArtHero art="vault" eyebrow="TLS inventory" title="Every TLS identity in one place.">
        <p className="max-w-[56ch] text-[14px] leading-relaxed text-slate-600">
          Store certificate and key pairs once, check what they cover and when they run out, then assign them to the services that match.
        </p>
        {data && <Summary d={data} />}
      </ArtHero>
      {can("admin") && <AddCertificate />}
      <div className="grid grid-cols-1 items-start gap-6 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <Card cat="TLS" title="Saved Certificates" action={data && <span className={cn(tag, "text-slate-600")}>{data.certs.length === 1 ? "1 cert" : `${data.certs.length} certs`}</span>}>
          {isError ? <LoadError /> : !data ? <Loading /> : <CertList certs={data.certs} />}
        </Card>
        <Card cat="TLS" title="Service TLS">
          {isError ? <LoadError /> : !data ? <Loading /> : <ServiceList d={data} />}
        </Card>
      </div>
    </Page>
  );
}

const Loading = () => <p className={cn(labelMono, "py-10 text-center")}>Loading…</p>;
const LoadError = () => (
  <p role="alert" className="py-6 text-red-600">
    Couldn't load the certificates. Reload to try again.
  </p>
);

function Summary({ d }: { d: CertsPage }) {
  const soon = d.certs.filter((c) => expiry(c.expires_at).dot !== "bg-success").length;
  return (
    <p className="flex flex-wrap items-center gap-x-5 gap-y-1 font-mono text-[12px] uppercase tracking-[.06em] text-ink">
      <span>{d.certs.length} in the pool</span>
      <span>{d.services.filter((s) => s.mode !== "none").length} of {d.services.length} host services on TLS</span>
      {soon > 0 && (
        <span className="flex items-center gap-2 text-amber-700">
          <span className="h-2 w-2 rounded-full bg-warning" />
          {soon} {soon === 1 ? "needs" : "need"} attention
        </span>
      )}
    </p>
  );
}

function Expiry({ at }: { at?: string }) {
  const e = expiry(at);
  return (
    <span className={cn("flex items-center gap-2 whitespace-nowrap text-[12px]", e.tone)}>
      <span aria-hidden className={cn("h-2 w-2 rounded-full", e.dot)} />
      {e.label}
      {at && <span className="text-slate-500">· {fmtDate(at)}</span>}
    </span>
  );
}

function CertList({ certs }: { certs: Cert[] }) {
  const remove = useDeleteCert();
  const [confirm, setConfirm] = useState<Cert | null>(null);
  if (certs.length === 0) return <p className={cn(labelMono, "py-10 text-center")}>No certificates saved yet</p>;
  return (
    <>
      {remove.error != null && (
        <p role="alert" className="pb-3 text-[13px] text-red-600">
          {(remove.error instanceof ApiError && remove.error.message) || "Couldn't delete. Try again."}
        </p>
      )}
      <ul>
        {certs.map((c) => (
          <li key={c.id} className="flex flex-wrap items-start gap-x-4 gap-y-2 border-b border-line py-4 first:pt-1 last:border-b-0">
            <div className="min-w-0 flex-1">
              <p className="truncate font-mono text-[14px] font-medium text-ink">{c.name}</p>
              <ul aria-label={`Domains on ${c.name}`} className="mt-2 flex flex-wrap gap-[6px]">
                {c.domains.map((d) => (
                  <li key={d} className="rounded-sm border border-line bg-canvas px-2 py-[3px] font-mono text-[11px] text-slate-600">
                    {d}
                  </li>
                ))}
              </ul>
              <p className="mt-2 text-[12px] text-slate-500">{c.services.length ? `Serving ${c.services.join(", ")}` : "Not assigned to a service"}</p>
            </div>
            <Expiry at={c.expires_at} />
            {can("admin") && (
              <button type="button" aria-label={`Delete ${c.name}`} onClick={() => setConfirm(c)} className="flex h-11 w-11 items-center justify-center rounded-sm text-slate-500 hover:bg-red-50 hover:text-red-600 sm:h-8 sm:w-8">
                <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-delete-02 text-[14px]" />
              </button>
            )}
          </li>
        ))}
      </ul>
      <Dialog open={confirm !== null} onOpenChange={(open) => !open && setConfirm(null)}>
        <DialogContent className="rounded-none border-edge bg-canvas sm:max-w-md">
          <DialogTitle className="text-[16px] text-ink">Delete {confirm?.name}?</DialogTitle>
          <DialogDescription className="text-[13px] text-slate-600">
            {confirm?.services.length
              ? `${confirm.services.join(", ")} will lose TLS and serve plain HTTP until you give ${confirm.services.length === 1 ? "it" : "them"} another certificate.`
              : "No service uses it. The certificate and its key are removed from disk."}
          </DialogDescription>
          <DialogFooter>
            <button type="button" onClick={() => setConfirm(null)} className={btn}>
              Cancel
            </button>
            <button
              type="button"
              disabled={remove.isPending}
              onClick={() => {
                const c = confirm!;
                remove.mutate(c.id, { onSuccess: () => toast.success(`Deleted ${c.name}.`) });
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

const modes: Record<ServiceTLS["mode"], string> = { auto: "Let's Encrypt", pool: "Pool", custom: "Uploaded", none: "No TLS" };

function ServiceList({ d }: { d: CertsPage }) {
  const needEmail = !d.acme_email && d.services.some((s) => s.mode === "auto");
  return (
    <>
      {needEmail && (
        <p role="status" className="mb-4 border border-amber-300 bg-amber-50 px-4 py-3 text-[12px] leading-normal text-amber-800">
          Let's Encrypt needs a contact email before it can issue. Add one from a service's TLS settings.
        </p>
      )}
      {d.services.length === 0 ? (
        <p className={cn(help, "py-6")}>No host-matched services yet. TLS needs a service that matches by host name.</p>
      ) : (
        <ul>
          {d.services.map((s) => (
            <li key={s.name} className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-line py-3 first:pt-1 last:border-b-0">
              <div className="min-w-0 flex-1">
                <p className="truncate font-mono text-[13px] uppercase tracking-[.04em] text-ink">{s.name}</p>
                <p className="truncate font-mono text-[12px] text-slate-500">{s.host}</p>
              </div>
              <span className={cn(tag, s.mode === "none" ? "text-slate-500" : "text-ink")}>
                {modes[s.mode]}
                {s.cert && ` · ${s.cert}`}
              </span>
              {(s.mode === "pool" || s.mode === "custom") && (
                <div className="basis-full">
                  <Expiry at={s.expires_at} />
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      <p className={cn(help, "mt-4 border-t border-line pt-4")}>
        Change a service's TLS on the{" "}
        <a href={`${boot.admin}/app/services`} className="text-ink underline">
          Services
        </a>{" "}
        page.
      </p>
    </>
  );
}

// AddCertificate saves a PEM pair to the pool. Each field takes a paste or a
// file; the name fills from the certificate's file name if it's empty.
function AddCertificate() {
  const add = useAddCert();
  const empty = { name: "", cert_pem: "", key_pem: "" };
  const [form, setForm] = useState(empty);
  const set = (k: keyof typeof empty) => (e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const load = (k: "cert_pem" | "key_pem") => async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setForm((f) => ({ ...f, [k]: text, name: k === "cert_pem" && !f.name ? file.name.replace(/\.[^.]+$/, "") : f.name }));
    e.target.value = "";
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    add.mutate(form, {
      onSuccess: (c) => {
        toast.success(c.name === form.name.trim() ? `Saved ${c.name}.` : `Saved as ${c.name}: that name was taken.`);
        setForm(empty);
      },
    });
  };
  const upload = (k: "cert_pem" | "key_pem", label: string, accept: string) => (
    <>
      Paste the PEM, or{" "}
      <label className="cursor-pointer text-ink underline">
        <input type="file" accept={accept} onChange={load(k)} className="sr-only" />
        {label}
      </label>
      .
    </>
  );
  const pem = cn(field, "min-h-32 resize-y font-mono text-[12px]");
  return (
    <Card title="Add Certificate">
      <form onSubmit={submit} className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="lg:col-span-2">
          <FormRow label="Name" error={fieldError(add.error, "name")}>
            <input value={form.name} onChange={set("name")} placeholder="e.g. cloudflare-example-com" className={field} />
          </FormRow>
        </div>
        <FormRow label="Certificate (PEM)" help={upload("cert_pem", "upload a .pem / .crt", ".pem,.crt,.cer")} error={fieldError(add.error, "cert_pem")}>
          <textarea value={form.cert_pem} onChange={set("cert_pem")} rows={5} placeholder={"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"} className={pem} />
        </FormRow>
        <FormRow label="Private key (PEM)" help={upload("key_pem", "upload a .pem / .key", ".pem,.key")} error={fieldError(add.error, "key_pem")}>
          <textarea value={form.key_pem} onChange={set("key_pem")} rows={5} placeholder={"-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----"} className={pem} />
        </FormRow>
        <div className="flex flex-col gap-3 lg:col-span-2">
          <FormError error={add.error} fields={["name", "cert_pem", "key_pem"]} />
          <button type="submit" disabled={add.isPending} className={cn(primary, "self-start")}>
            <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-add-circle text-sm" />
            Save certificate
          </button>
        </div>
      </form>
      <div className={cn(help, "mt-5 border-t border-line pt-4 leading-[1.6]")}>
        <p className={cn(labelMono, "mb-2")}>Cloudflare origin certs</p>
        Cloudflare → SSL/TLS → Origin Server → <strong>Create Certificate</strong> covers your domain and <code className="bg-surface px-1 font-mono text-[11px]">*.domain</code> in one cert. Set SSL/TLS mode to{" "}
        <strong>Full (strict)</strong>, then assign it to each matching service.
      </div>
    </Card>
  );
}
