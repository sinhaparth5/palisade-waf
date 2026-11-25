import { useState } from "react";
import { FormRow, labelMono } from "@/components/layout/Page";
import { field, fieldError, help } from "@/features/rules/shared";
import { cn } from "@/lib/utils";
import { Choice, TabForm, code, num, saved, str } from "./form";
import { lines, useSetService, type Backends, type Hosts, type RateLimit, type Service } from "./api";

// The routing tabs: rate limit, backends and extra hostnames.

const mono = cn(field, "font-mono");

export function RateLimitTab({ s }: { s: Service }) {
  const save = useSetService<RateLimit>(s.id, "rate-limit");
  const e = save.error;
  const r = s.rate_limit;
  return (
    <TabForm
      intro="Per client, on top of the global limit. Set 0 or leave blank to fall through to the global limit from Settings."
      pending={save.isPending}
      error={e}
      fields={["rps", "burst", "path_rules"]}
      onSubmit={(f) => save.mutate({ rps: num(f, "rps"), burst: num(f, "burst"), path_rules: str(f, "path_rules") }, { onSuccess: saved })}
    >
      <div className="grid grid-cols-2 gap-3">
        <FormRow label="Requests / second" error={fieldError(e, "rps")}>
          <input name="rps" type="number" min={0} step={0.1} defaultValue={r.rps || ""} placeholder="e.g. 10" className={field} />
        </FormRow>
        <FormRow label="Burst" error={fieldError(e, "burst")}>
          <input name="burst" type="number" min={0} defaultValue={r.burst || ""} placeholder="auto (2× RPS)" className={field} />
        </FormRow>
      </div>
      <FormRow
        label="Path limits"
        error={fieldError(e, "path_rules")}
        help={
          <>
            One <span className="font-mono">METHOD /path rate burst</span> per line. <span className="font-mono">*</span> matches any method; the path is a prefix and the longest match wins. Rate is{" "}
            <span className="font-mono">N/s</span>, <span className="font-mono">N/m</span> or <span className="font-mono">N/h</span> per client.
          </>
        }
      >
        <textarea name="path_rules" rows={4} spellCheck={false} defaultValue={r.path_rules} placeholder={"POST /password-reset 5/h 3\n* /search 2/s 10\nGET /export 10/m 2"} className={mono} />
      </FormRow>
    </TabForm>
  );
}

export function BackendsTab({ s }: { s: Service }) {
  const save = useSetService<Backends>(s.id, "backends");
  const e = save.error;
  const b = s.backends;
  return (
    <TabForm
      intro="Requests are spread across every backend listed. A backend that stops answering leaves the rotation, and GET or HEAD requests that hit it are retried once on another backend."
      locked={s.docker}
      pending={save.isPending}
      error={e}
      fields={["urls", "lb_policy", "health_path", "health_interval", "ca"]}
      onSubmit={(f) =>
        save.mutate(
          { urls: lines(str(f, "urls")), lb_policy: str(f, "lb_policy") as Backends["lb_policy"], health_path: str(f, "health_path"), health_interval: num(f, "health_interval"), ca: str(f, "ca") },
          { onSuccess: saved },
        )
      }
    >
      <FormRow label="Backends, one per line" error={fieldError(e, "urls")} help="The first is the primary. All must share the same base path.">
        <textarea name="urls" rows={4} defaultValue={b.urls.join("\n")} placeholder={"http://10.0.0.5:3000\nhttp://10.0.0.6:3000"} className={mono} />
      </FormRow>
      <fieldset className="flex flex-col gap-2">
        <legend className={cn(labelMono, "mb-2")}>Balancing</legend>
        {(
          [
            ["round_robin", "Round robin", "Each backend takes the next request in turn."],
            ["least_conn", "Least connections", "Each request goes to the backend with the fewest requests in progress. Better when some requests are much slower than others."],
          ] as const
        ).map(([v, t, d]) => (
          <Choice key={v} name="lb_policy" value={v} on={b.lb_policy === v} title={t} copy={d} />
        ))}
        {fieldError(e, "lb_policy") && <p className="text-xs text-red-600">{fieldError(e, "lb_policy")}</p>}
      </fieldset>
      <div className="grid grid-cols-2 gap-3">
        <FormRow label="Health check path" error={fieldError(e, "health_path")}>
          <input name="health_path" defaultValue={b.health_path} placeholder="/healthz" autoComplete="off" className={mono} />
        </FormRow>
        <FormRow label="Every (seconds)" error={fieldError(e, "health_interval")}>
          <input name="health_interval" type="number" min={1} max={3600} defaultValue={b.health_interval || ""} placeholder="10" className={field} />
        </FormRow>
      </div>
      <p className={cn(help, "leading-normal")}>
        With a path set, each backend is checked on that path and leaves the rotation until it answers 2xx or 3xx again. Leave it blank to judge backends by real traffic only: one that fails sits out for 10 seconds, then gets traffic again.
      </p>
      <FormRow
        label="Trusted backend certificate (PEM)"
        error={fieldError(e, "ca")}
        help="For HTTPS backends with a self-signed or private certificate. Paste the backend's own certificate to accept exactly that one, or your private CA to check the chain and hostname against it. Leave blank to use the system's trusted CAs. Never paste a private key."
      >
        <textarea name="ca" rows={3} spellCheck={false} defaultValue={b.ca} placeholder="-----BEGIN CERTIFICATE-----" className={cn(mono, "text-[12px]")} />
      </FormRow>
    </TabForm>
  );
}

export function HostsTab({ s }: { s: Service }) {
  const save = useSetService<Hosts>(s.id, "hosts");
  const e = save.error;
  const [aliases, setAliases] = useState(s.hosts.aliases.join("\n"));
  const names = [s.host, ...lines(aliases)];
  return (
    <TabForm
      intro={
        <>
          Other hostnames that reach this service, such as <span className="font-mono">www.</span> in front of the main domain. They share every setting and rule, and automatic TLS issues certificates for them too.
        </>
      }
      locked={s.docker}
      pending={save.isPending}
      error={e}
      fields={["aliases", "canonical"]}
      onSubmit={(f) => save.mutate({ aliases: lines(aliases), canonical: str(f, "canonical") }, { onSuccess: saved })}
    >
      <FormRow label="Extra hostnames, one per line" error={fieldError(e, "aliases")}>
        <textarea rows={3} value={aliases} onChange={(ev) => setAliases(ev.target.value)} placeholder="www.example.com" className={mono} />
      </FormRow>
      <FormRow label="Redirect the other names to" error={fieldError(e, "canonical")}>
        <select name="canonical" defaultValue={s.hosts.canonical} className={field}>
          <option value="">Don't redirect, serve every name</option>
          {names.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
      </FormRow>
      <div className={cn(help, "border border-line bg-surface p-3 leading-[1.6]")}>
        <p className="mb-1 font-semibold text-ink">Using Cloudflare</p>
        Add a proxied (orange cloud) DNS record for every name, e.g. <span className={code}>www</span> as a CNAME to the main domain. Set SSL/TLS to <strong>Full (strict)</strong>; Flexible loops against this WAF's HTTPS redirect. Automatic TLS works
        through the proxy, or upload a Cloudflare Origin Certificate covering every name on the TLS tab.
      </div>
    </TabForm>
  );
}
