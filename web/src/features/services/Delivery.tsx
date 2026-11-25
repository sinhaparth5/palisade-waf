import { useState } from "react";
import { toast } from "sonner";
import { FormRow } from "@/components/layout/Page";
import { FormError, Toggle, btn, field, fieldError, help } from "@/features/rules/shared";
import { boot, can } from "@/lib/boot";
import { fmtTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Choice, TabForm, code, num, saved, str } from "./form";
import { lines, usePurge, useSetService, type Cache, type MTLSWrite, type Service, type ServicesPage, type TLSWrite } from "./api";

// The Cache tab (Varnish, compression, purge) and the TLS tab (certificate,
// HTTP/3, client certificates) of the service dialog.

const mono = cn(field, "font-mono");
const warn = "border border-amber-300 bg-amber-50 p-3 text-[12px] leading-normal text-amber-800";
const settings = (
  <a href={`${boot.admin}/app/settings#settings-infrastructure`} className="text-ink underline">
    Settings
  </a>
);

export function CacheTab({ s, d }: { s: Service; d: ServicesPage }) {
  return (
    <>
      <CacheForm key={JSON.stringify([s.cache, s.compress])} s={s} varnish={d.varnish} />
      {can("admin") && <Purge s={s} />}
    </>
  );
}

function CacheForm({ s, varnish }: { s: Service; varnish: boolean }) {
  const save = useSetService<Cache & { compress: boolean }>(s.id, "cache");
  const e = save.error;
  const c = s.cache;
  return (
    <TabForm
      intro={<>Route this service's clean, WAF-inspected traffic through the local Varnish cache to serve static assets from memory.</>}
      pending={save.isPending}
      error={e}
      fields={["session_cookie", "ttl_floor", "ttl_ceiling", "grace", "keep", "rules"]}
      onSubmit={(f) =>
        save.mutate(
          {
            enabled: f.has("enabled"),
            by_session: f.has("by_session"),
            session_cookie: str(f, "session_cookie"),
            ttl_floor: num(f, "ttl_floor"),
            ttl_ceiling: num(f, "ttl_ceiling"),
            grace: num(f, "grace"),
            keep: num(f, "keep"),
            rules: str(f, "rules"),
            compress: f.has("compress"),
          },
          { onSuccess: saved },
        )
      }
    >
      {!varnish && <p className={warn}>The Varnish integration is off, so caching has no effect yet. Turn it on in {settings}.</p>}
      <Toggle name="enabled" label="Cache this service" on={c.enabled} />

      <div className="border-t border-line pt-4">
        <Toggle name="by_session" label="Cache by session" on={c.by_session} />
      </div>
      <p className={cn(help, "-mt-2 leading-normal")}>
        Also cache logged-in traffic, partitioned per session: each session gets its own cached copy instead of Varnish refusing any request that carries a cookie. Short TTL (10s) once on.
      </p>
      <FormRow label="Session cookie name" error={fieldError(e, "session_cookie")}>
        <input name="session_cookie" defaultValue={c.session_cookie} placeholder="e.g. session_id, connect.sid" autoComplete="off" className={mono} />
      </FormRow>

      <p className="border-t border-line pt-4 text-[13px] font-semibold text-ink">Tuning</p>
      <p className={cn(help, "-mt-2 leading-normal")}>Override Varnish's defaults for this service. Leave blank for the built-in behaviour (1h floor for static assets, no ceiling, 30s grace and keep).</p>
      <div className="grid grid-cols-2 gap-3">
        {(
          [
            ["ttl_floor", "TTL floor (s)", c.ttl_floor, "e.g. 3600"],
            ["ttl_ceiling", "TTL ceiling (s)", c.ttl_ceiling, "e.g. 86400"],
            ["grace", "Grace (s)", c.grace, "30"],
            ["keep", "Keep (s)", c.keep, "30"],
          ] as const
        ).map(([n, l, v, p]) => (
          <FormRow key={n} label={l} error={fieldError(e, n)}>
            <input name={n} type="number" min={0} defaultValue={v || ""} placeholder={p} className={field} />
          </FormRow>
        ))}
      </div>
      <FormRow
        label="Path rules"
        error={fieldError(e, "rules")}
        help={
          <>
            One <code className={code}>cache /path</code> or <code className={code}>bypass /path</code> per line; the path is a prefix and the longest match wins. <code className={code}>cache</code> stores matching responses like static
            assets, shared by every visitor: cookies and <code className={code}>Set-Cookie</code> are dropped, so never use it for per-user pages. <code className={code}>bypass</code> sends requests straight to the backend.
          </>
        }
      >
        <textarea name="rules" rows={4} spellCheck={false} defaultValue={c.rules} placeholder={"cache /assets/\ncache /api/public/\nbypass /api/"} className={mono} />
      </FormRow>

      <div className="border-t border-line pt-4">
        <Toggle name="compress" label="Compress responses" on={s.compress} />
      </div>
      <p className={cn(help, "-mt-2 leading-normal")}>
        Compresses text responses (HTML, CSS, JavaScript, JSON, SVG) over 1 KB with zstd or gzip, whichever the browser supports, when the backend didn't already. Doesn't need Varnish. Images, video, event streams and WebSockets pass
        through unchanged.
      </p>
    </TabForm>
  );
}

function Purge({ s }: { s: Service }) {
  const purge = usePurge(s.id);
  const [path, setPath] = useState("");
  return (
    <form
      onSubmit={(ev) => {
        ev.preventDefault();
        purge.mutate(path.trim(), { onSuccess: () => toast.success(path.trim() ? `Purged ${path.trim()}*.` : "Purged.") });
      }}
      className="mt-6 flex flex-col gap-3 border-t border-line pt-5"
    >
      <p className={cn(help, "leading-normal")}>Evict what Varnish holds for this service, everything or only URLs under a path. Useful right after deploying new content.</p>
      <FormRow label="Path prefix (empty = everything)" error={fieldError(purge.error, "path")}>
        <input value={path} onChange={(ev) => setPath(ev.target.value)} placeholder="/blog/" autoComplete="off" className={mono} />
      </FormRow>
      <FormError error={purge.error} fields={["path"]} />
      <button type="submit" disabled={purge.isPending} className={btn}>
        Purge cached content
      </button>
    </form>
  );
}

export function TLSTab({ s, d }: { s: Service; d: ServicesPage }) {
  return (
    <>
      <CertForm key={JSON.stringify(s.tls)} s={s} d={d} />
      <HTTP3Form key={String(s.tls.http3)} s={s} listener={d.http3_listener} />
      <MTLSForm key={JSON.stringify(s.tls.mtls)} s={s} />
    </>
  );
}

function current(s: Service) {
  const t = s.tls;
  if (t.cert_id) return `Serving ${t.cert_name} from the certificate pool.`;
  if (t.mode === "custom") return `Serving an uploaded certificate${t.expires_at ? `, valid until ${fmtTime(t.expires_at)}` : ""}.`;
  if (t.mode === "auto") return "Let's Encrypt issues a certificate on the first HTTPS connection.";
  return "No certificate of its own: HTTPS uses the server's default.";
}

function CertForm({ s, d }: { s: Service; d: ServicesPage }) {
  const save = useSetService<TLSWrite>(s.id, "tls");
  const e = save.error;
  const t = s.tls;
  const [mode, setMode] = useState<TLSWrite["mode"]>(t.cert_id ? "pool" : t.mode || (d.certificates.length ? "pool" : "custom"));
  const choices: [TLSWrite["mode"], string][] = [
    ["pool", "Saved certificate"],
    ["custom", "Upload"],
    ["auto", "Let's Encrypt"],
    ["none", "None"],
  ];
  return (
    <TabForm
      title="Certificate"
      intro={current(s)}
      pending={save.isPending}
      error={e}
      fields={["mode", "cert_id", "cert_pem", "key_pem", "acme_email"]}
      onSubmit={(f) =>
        save.mutate(
          { mode, cert_id: num(f, "cert_id") || undefined, cert_pem: str(f, "cert_pem") || undefined, key_pem: str(f, "key_pem") || undefined, acme_email: str(f, "acme_email") || undefined },
          { onSuccess: saved },
        )
      }
    >
      <fieldset className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <legend className="sr-only">Certificate source</legend>
        {choices.map(([v, l]) => (
          <label key={v} className="flex min-h-11 cursor-pointer items-center gap-2 rounded-sm border border-line px-3 text-[13px] text-ink has-checked:border-edge has-checked:bg-surface">
            <input type="radio" name="source" value={v} checked={mode === v} onChange={() => setMode(v)} className="accent-ink" />
            {l}
          </label>
        ))}
      </fieldset>
      {mode === "pool" &&
        (d.certificates.length ? (
          <FormRow label="Certificate" error={fieldError(e, "cert_id")}>
            <select name="cert_id" defaultValue={t.cert_id || d.certificates[0]!.id} className={field}>
              {d.certificates.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                  {c.domains && ` · ${c.domains}`}
                </option>
              ))}
            </select>
          </FormRow>
        ) : (
          <p className={help}>
            No certificates in the pool yet.{" "}
            <a href={`${boot.admin}/app/certificates`} className="text-ink underline">
              Add one on Certificates
            </a>
            .
          </p>
        ))}
      {mode === "custom" && (
        <>
          <FormRow label="Certificate (PEM)" error={fieldError(e, "cert_pem")}>
            <textarea name="cert_pem" rows={4} spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" className={cn(mono, "text-[12px]")} />
          </FormRow>
          <FormRow label="Private key (PEM)" error={fieldError(e, "key_pem")} help="Written to disk on this server, never stored in the database.">
            <textarea name="key_pem" rows={4} spellCheck={false} placeholder="-----BEGIN PRIVATE KEY-----" className={cn(mono, "text-[12px]")} />
          </FormRow>
        </>
      )}
      {mode === "auto" && (
        <>
          <p className={cn(help, "leading-normal")}>A certificate is issued from Let's Encrypt the first time this domain gets a real HTTPS connection.</p>
          {!d.acme_email && (
            <FormRow label="Let's Encrypt email" error={fieldError(e, "acme_email")} help="Let's Encrypt sends renewal notices and account alerts here. It is not shown publicly.">
              <input name="acme_email" type="email" required placeholder="you@example.com" autoComplete="email" className={field} />
            </FormRow>
          )}
        </>
      )}
      {mode === "none" && <p className={help}>The service stops presenting a certificate of its own.</p>}
    </TabForm>
  );
}

function HTTP3Form({ s, listener }: { s: Service; listener: boolean }) {
  const save = useSetService<{ enabled: boolean }>(s.id, "http3");
  return (
    <TabForm
      title="HTTP/3 (QUIC)"
      intro="Offers HTTP/3 to browsers on this domain. HTTP/2 stays the default and the fallback."
      pending={save.isPending}
      error={save.error}
      fields={[]}
      onSubmit={(f) => save.mutate({ enabled: f.has("enabled") }, { onSuccess: saved })}
    >
      {!listener && (
        <p className={warn}>
          The HTTP/3 listener is off, so this has no effect yet. Start Palisade with <code className={code}>--listen-h3 :443</code> and allow UDP 443 through the firewall.
        </p>
      )}
      <Toggle name="enabled" label="Offer HTTP/3" on={s.tls.http3} />
    </TabForm>
  );
}

function MTLSForm({ s }: { s: Service }) {
  const save = useSetService<MTLSWrite>(s.id, "mtls");
  const e = save.error;
  const m = s.tls.mtls;
  return (
    <TabForm
      title="Client certificates (mTLS)"
      intro={
        <>
          Only clients holding a certificate from your CA get through. A request without one gets 403, logged as <code className={code}>mtls_required</code>. The backend receives <code className={code}>X-Client-Cert-Verified</code>,{" "}
          <code className={code}>-Subject</code> and <code className={code}>-Fingerprint</code> (SHA-256); clients can't set these themselves. Revocation (CRL/OCSP) is not checked.
        </>
      }
      pending={save.isPending}
      error={e}
      fields={["mode", "ca", "allow"]}
      onSubmit={(f) => save.mutate({ mode: str(f, "mode") as MTLSWrite["mode"], ca: str(f, "ca"), allow: lines(str(f, "allow")) }, { onSuccess: saved })}
    >
      <p className={warn}>Clients must connect to Palisade directly. Behind Cloudflare's proxy, TLS ends at Cloudflare and no client certificate reaches this server.</p>
      <fieldset className="flex flex-col gap-2">
        <legend className="sr-only">Client certificate mode</legend>
        <Choice name="mode" value="off" on={m.mode === "off"} title="Off" copy="No client certificate is asked for." />
        <Choice name="mode" value="optional" on={m.mode === "optional"} title="Optional" copy="Forward the result to the backend, never block." />
        <Choice name="mode" value="required" on={m.mode === "required"} title="Required" copy="403 without a valid certificate." />
        {fieldError(e, "mode") && <p className="text-xs text-red-600">{fieldError(e, "mode")}</p>}
      </fieldset>
      <FormRow label="Client CA certificate(s), PEM" error={fieldError(e, "ca")} help={m.ca_set ? "A CA is saved. Leave this empty to keep it." : undefined}>
        <textarea name="ca" rows={4} spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" className={cn(mono, "text-[12px]")} />
      </FormRow>
      <FormRow label="Allowlist (optional, one per line)" error={fieldError(e, "allow")} help="Subject CN, SAN DNS name or SHA-256 fingerprint.">
        <textarea name="allow" rows={3} spellCheck={false} defaultValue={m.allow.join("\n")} className={cn(mono, "text-[12px]")} />
      </FormRow>
    </TabForm>
  );
}
