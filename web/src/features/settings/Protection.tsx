import { useState } from "react";
import { toast } from "sonner";
import { Card, FormRow } from "@/components/layout/Page";
import { Num, SettingsCard, Toggle, btn, field, fieldError, help } from "@/features/rules/shared";
import { boot, can } from "@/lib/boot";
import { cn } from "@/lib/utils";
import { useSetProtection, type AIAction, type Bot, type RateLimit, type Varnish } from "./api";

// Protection and infrastructure: global bot, rate-limit and trusted-IP
// settings, Varnish, downloads of the database and config, and the WAF
// reload note. Viewers see the forms read-only.

const code = "bg-surface px-1 font-mono text-[11px]";
const saved = () => toast.success("Saved and applied. No restart needed.");
const num = (f: FormData, k: string) => Number(f.get(k));
const str = (f: FormData, k: string) => String(f.get(k) ?? "");

const aiCategories = [
  { key: "ai_training", label: "Training", hint: "GPTBot, ClaudeBot, CCBot, Bytespider" },
  { key: "ai_search", label: "AI search", hint: "OAI-SearchBot, Claude-SearchBot, PerplexityBot" },
  { key: "ai_user", label: "User fetch", hint: "ChatGPT-User, Claude-User, Perplexity-User" },
] as const;

export function BotCard({ v }: { v: Bot }) {
  const save = useSetProtection<Omit<Bot, "captcha_secret_set"> & { captcha_secret: string }>("bot");
  const e = save.error;
  const servicesLink = (
    <a href={`${boot.admin}/app/services`} className="text-ink underline">
      Services
    </a>
  );
  return (
    <SettingsCard
      title="Bot Protection"
      intro={
        <>
          JS proof-of-work challenge for suspicious clients. Browsers solve it silently in under a second; scanners and headless bots can't. Per-service overrides are on the {servicesLink} page.
        </>
      }
      pending={save.isPending}
      error={e}
      fields={["threshold", "ttl", "captcha_provider", "captcha_site_key", "captcha_secret", ...aiCategories.map((c) => c.key)]}
      onSubmit={(f) =>
        save.mutate(
          {
            enabled: f.has("enabled"),
            threshold: num(f, "threshold"),
            ttl: num(f, "ttl"),
            captcha_provider: str(f, "captcha_provider") as Bot["captcha_provider"],
            captcha_site_key: str(f, "captcha_site_key"),
            captcha_secret: str(f, "captcha_secret"),
            ai_training: str(f, "ai_training") as AIAction,
            ai_search: str(f, "ai_search") as AIAction,
            ai_user: str(f, "ai_user") as AIAction,
          },
          { onSuccess: saved },
        )
      }
    >
      <Toggle name="enabled" label="Enable bot protection" on={v.enabled} />
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Num name="threshold" label="Anomaly threshold" value={v.threshold} min={1} max={100} error={e} />
        <Num name="ttl" label="Bypass cookie TTL (seconds)" value={v.ttl} min={60} error={e} />
      </div>
      <p className={help}>A challenge is issued at the threshold score: scanners score 10 or more, browsers usually 0–2. A solved challenge stays valid for the TTL (3600 = 1 hour).</p>
      <FormRow
        label="CAPTCHA fallback"
        error={fieldError(e, "captcha_provider")}
        help="Shown when a browser can't run the proof-of-work, e.g. over plain HTTP or with locked-down JavaScript. The token is checked with the provider before the bypass cookie is issued."
      >
        <select name="captcha_provider" defaultValue={v.captcha_provider} className={field}>
          <option value="">Off</option>
          <option value="turnstile">Cloudflare Turnstile</option>
          <option value="hcaptcha">hCaptcha</option>
        </select>
      </FormRow>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <FormRow label="Site key" error={fieldError(e, "captcha_site_key")}>
          <input name="captcha_site_key" autoComplete="off" defaultValue={v.captcha_site_key} className={field} />
        </FormRow>
        <FormRow label={v.captcha_secret_set ? "Secret key (saved; blank keeps it)" : "Secret key"} error={fieldError(e, "captcha_secret")}>
          <input name="captcha_secret" type="password" autoComplete="off" placeholder={v.captcha_secret_set ? "••••••••••••" : ""} className={field} />
        </FormRow>
      </div>
      <div className="border-t border-line pt-3">
        <p className="text-[13px] font-medium text-ink">AI crawlers</p>
        <p className={cn(help, "mt-[2px] mb-3 leading-[1.6]")}>
          Default for every service; each service can override it. Block refuses any client whose User-Agent names the category. Allow lets a crawler skip the challenge only once its source is verified: Meta's by network, OpenAI's,
          Anthropic's and Perplexity's after you pin their published IP ranges with <code className={code}>--trusted-crawlers</code>. Challenge needs bot protection on. robots.txt, sitemaps and llms.txt stay readable.
        </p>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          {aiCategories.map((c) => (
            <FormRow key={c.key} label={c.label} error={fieldError(e, c.key)} help={c.hint}>
              <select name={c.key} defaultValue={v[c.key]} className={field}>
                <option value="">No policy</option>
                <option value="allow">Allow verified</option>
                <option value="challenge">Challenge</option>
                <option value="block">Block</option>
              </select>
            </FormRow>
          ))}
        </div>
      </div>
    </SettingsCard>
  );
}

export function RateLimitCard({ v }: { v: RateLimit }) {
  const save = useSetProtection<RateLimit>("rate-limit");
  const e = save.error;
  return (
    <SettingsCard
      title="Rate Limiting"
      intro="Global per-IP token-bucket limiter, applied to every request before the WAF. Per-service limits are set on the Services page. Bucket state is kept in memory and saved every 10 s, so it survives restarts."
      pending={save.isPending}
      error={e}
      fields={["rps", "burst"]}
      onSubmit={(f) => save.mutate({ enabled: f.has("enabled"), rps: num(f, "rps"), burst: num(f, "burst") }, { onSuccess: saved })}
    >
      <Toggle name="enabled" label="Enable global rate limiting" on={v.enabled} />
      <div className="grid grid-cols-2 gap-3">
        <Num name="rps" label="Requests / second per IP" value={v.rps} min={0.1} step={0.1} error={e} />
        <Num name="burst" label="Burst" value={v.burst} min={1} error={e} />
      </div>
      <p className={help}>Off = no global per-IP limit; per-service limits and automatic banning still apply.</p>
    </SettingsCard>
  );
}

export function TrustedIPsCard({ ips }: { ips: string[] }) {
  const save = useSetProtection<{ trusted_ips: string }>("trusted-ips");
  const [text, setText] = useState(ips.join("\n"));
  return (
    <SettingsCard
      title="Trusted IPs"
      intro="Requests from these addresses are never blocked: they skip IP and geo rules, the bot challenge, rate limits, the WAF and automatic banning. They are still proxied and logged. Only add addresses you control, such as your office, a monitor or your own servers."
      pending={save.isPending}
      error={save.error}
      fields={["trusted_ips"]}
      onSubmit={() => save.mutate({ trusted_ips: text }, { onSuccess: saved })}
    >
      <FormRow label="Trusted IPs" error={fieldError(save.error, "trusted_ips")} help="One IP address or CIDR range per line, IPv4 or IPv6.">
        <textarea
          rows={4}
          value={text}
          onChange={(ev) => setText(ev.target.value)}
          placeholder={"203.0.113.10\n198.51.100.0/24\n2001:db8::/64"}
          className={cn(field, "resize-y font-mono text-[12px]")}
        />
      </FormRow>
    </SettingsCard>
  );
}

export function VarnishCard({ v }: { v: Varnish }) {
  const save = useSetProtection<Varnish>("varnish");
  return (
    <SettingsCard
      title="Varnish Cache"
      intro={
        <>
          Caches static assets and cache-eligible endpoints in a local Varnish daemon. Traffic is WAF-inspected first; cache misses come back to the WAF, which routes them to the right backend, so the Varnish config never
          changes when services do. Turn caching on per service on the Services page. The installer sets Varnish up (or see <code className={code}>deploy/varnish/README.md</code>).
        </>
      }
      pending={save.isPending}
      error={save.error}
      fields={["addr"]}
      onSubmit={(f) => save.mutate({ enabled: f.has("enabled"), addr: str(f, "addr") }, { onSuccess: saved })}
    >
      <Toggle name="enabled" label="Route cache-enabled services through Varnish" on={v.enabled} />
      <FormRow label="Varnish listen address" error={fieldError(save.error, "addr")} help="Must be loopback (127.0.0.1, ::1 or localhost), so nothing reaches the cache without passing the WAF.">
        <input name="addr" defaultValue={v.addr} placeholder="127.0.0.1:6081" className={cn(field, "font-mono")} />
      </FormRow>
    </SettingsCard>
  );
}

// A download is a plain form POST: the browser saves the file, and POST
// keeps a cross-site link from starting one (the files hold secrets).
function Download({ title, path, label, children }: { title: string; path: string; label: string; children: React.ReactNode }) {
  return (
    <Card title={title}>
      <p className={cn(help, "mb-4 leading-[1.6]")}>{children}</p>
      <form action={`${boot.admin}${path}`} method="POST">
        <input type="hidden" name="_csrf" value={boot.csrf} />
        <button type="submit" className={btn}>
          <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-download-02 text-base" />
          {label}
        </button>
      </form>
    </Card>
  );
}

export function InfraCards() {
  return (
    <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-2">
      {can("owner") && (
        <>
          <Download title="Database backup" path="/settings/backup" label="Download waf.db">
            A consistent snapshot of <code className={code}>waf.db</code>: request logs, services, IP and geo rules, and settings. Safe to run while the WAF is live.
          </Download>
          <Download title="Configuration export" path="/settings/config-export" label="Download config">
            Services, rules, users and settings as JSON, without the request log. Secrets stay sealed under <code className={code}>--db-key-file</code>, or are left out without one. Load it with{" "}
            <code className={code}>palisade config import</code>.
          </Download>
        </>
      )}
      <Card title="WAF rules">
        <p className={help}>
          To reload WAF rules from the <code className={code}>--waf-rules</code> directory without restarting, send SIGHUP to the process:
        </p>
        <pre className="mt-3 overflow-x-auto rounded-sm bg-surface px-4 py-3 font-mono text-[12px] text-ink">kill -HUP $(pidof palisade)</pre>
        <p className={cn(help, "mt-2")}>The engine swaps in place: requests in flight finish on the old rules, new ones use the reloaded set.</p>
      </Card>
    </div>
  );
}
