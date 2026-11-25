import { FormRow } from "@/components/layout/Page";
import { Toggle, field, fieldError, help } from "@/features/rules/shared";
import { boot } from "@/lib/boot";
import { cn } from "@/lib/utils";
import { Choice, TabForm, code, num, saved, str } from "./form";
import { lines, useSetService, type Bot, type Gate, type Service, type Uploads } from "./api";

// The Bot, Availability and Uploads tabs.

const settings = (
  <a href={`${boot.admin}/settings#settings-protection`} className="text-ink underline">
    Settings
  </a>
);

const aiCategories = [
  { key: "training", label: "Training", hint: "GPTBot, ClaudeBot, CCBot, Bytespider" },
  { key: "search", label: "AI search", hint: "OAI-SearchBot, Claude-SearchBot, PerplexityBot" },
  { key: "user", label: "User fetch", hint: "ChatGPT-User, Claude-User, Perplexity-User" },
] as const;

const sub = "border-t border-line pt-4 text-[13px] font-semibold text-ink";

export function BotTab({ s }: { s: Service }) {
  const save = useSetService<Bot>(s.id, "bot");
  const e = save.error;
  const b = s.bot;
  return (
    <TabForm
      intro={<>How bot protection applies to this service. The global setting is in {settings}.</>}
      pending={save.isPending}
      error={e}
      fields={["mode", "ai_training", "ai_search", "ai_user", "login_paths", "breach_action", "breach_fields"]}
      onSubmit={(f) =>
        save.mutate(
          {
            mode: str(f, "mode") as Bot["mode"],
            ai: Object.fromEntries(aiCategories.map((c) => [c.key, str(f, `ai_${c.key}`)]).filter(([, v]) => v)),
            login_paths: lines(str(f, "login_paths")),
            breach_action: str(f, "breach_action") as Bot["breach_action"],
            breach_fields: str(f, "breach_fields").split(/[\s,]+/).filter(Boolean),
          },
          { onSuccess: saved },
        )
      }
    >
      <fieldset className="flex flex-col gap-2">
        <legend className="sr-only">Bot protection</legend>
        <Choice name="mode" value="inherit" on={b.mode === "inherit"} title="Inherit global setting" copy="Use whatever is configured in Settings. This is the default." />
        <Choice name="mode" value="always" on={b.mode === "always"} title="Always challenge" copy="Every client must solve the JS challenge before reaching this service, whatever its score. Useful for sensitive admin or API endpoints." />
        <Choice name="mode" value="off" on={b.mode === "off"} title="Disabled for this service" copy="No bot challenge for this service, even if it is on globally. Use for public APIs or monitoring endpoints hit by legitimate automation." />
      </fieldset>

      <p className={sub}>AI crawlers</p>
      <p className={cn(help, "-mt-2 leading-normal")}>
        Overrides the default in {settings} per category. Block refuses any client whose User-Agent names the category; Allow only skips the challenge for a crawler verified by its source address.
      </p>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {aiCategories.map((c) => (
          <FormRow key={c.key} label={c.label} error={fieldError(e, `ai_${c.key}`)} help={c.hint}>
            <select name={`ai_${c.key}`} defaultValue={b.ai[c.key] ?? ""} className={field}>
              <option value="">Inherit</option>
              <option value="allow">Allow verified</option>
              <option value="challenge">Challenge</option>
              <option value="block">Block</option>
            </select>
          </FormRow>
        ))}
      </div>

      <p className={sub}>Login protection</p>
      <p className={cn(help, "-mt-2 leading-normal")}>
        Against credential stuffing. Every client must solve the bot challenge before reaching these paths, even with bot protection off for this service, and each client may submit to them 5 times at once, then once every 12 seconds.
        Loading the page doesn't count. The challenge needs bot protection on in {settings}; the limit always applies.
      </p>
      <FormRow label="Login paths, one per line (empty = off)" error={fieldError(e, "login_paths")}>
        <textarea name="login_paths" rows={3} defaultValue={b.login_paths.join("\n")} placeholder={"/login\n/wp-login.php"} className={cn(field, "font-mono")} />
      </FormRow>

      <p className={sub}>Leaked password check</p>
      <p className={cn(help, "-mt-2 leading-normal")}>
        Checks passwords sent to the login paths above against known data breaches (Have I Been Pwned). Only the first 5 characters of the password's SHA-1 hash leave this server. If the lookup fails or takes over 300 ms, the login
        goes through unchecked. A hit is logged as <code className={code}>leaked_password</code>, counts toward autoban, and reaches the backend with <code className={code}>X-Palisade-Leaked-Password: 1</code> so the app can ask for a
        password reset.
      </p>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <FormRow label="Action" error={fieldError(e, "breach_action")}>
          <select name="breach_action" defaultValue={b.breach_action} className={field}>
            <option value="">Off</option>
            <option value="log">Log and tell the backend</option>
            <option value="block">Block the login (403)</option>
          </select>
        </FormRow>
        <FormRow label="Password field names" error={fieldError(e, "breach_fields")} help="Empty = password, passwd, pass, pwd.">
          <input name="breach_fields" defaultValue={b.breach_fields.join(" ")} autoComplete="off" placeholder="password" className={cn(field, "font-mono")} />
        </FormRow>
      </div>
    </TabForm>
  );
}

export function GateTab({ s }: { s: Service }) {
  const save = useSetService<Gate & { new_bypass: boolean }>(s.id, "gate");
  const e = save.error;
  const g = s.gate;
  return (
    <TabForm
      pending={save.isPending}
      error={e}
      fields={["start", "end", "message", "max_active", "idle_mins", "wait_message"]}
      onSubmit={(f) =>
        save.mutate(
          {
            maintenance: f.has("maintenance"),
            message: str(f, "message"),
            start: str(f, "start"),
            end: str(f, "end"),
            new_bypass: f.has("new_bypass"),
            waiting_room: f.has("waiting_room"),
            max_active: num(f, "max_active"),
            idle_mins: num(f, "idle_mins"),
            wait_message: str(f, "wait_message"),
            crawlers: str(f, "crawlers") as Gate["crawlers"],
          },
          { onSuccess: saved },
        )
      }
    >
      <Toggle name="maintenance" label="Maintenance mode" on={g.maintenance} />
      <p className={cn(help, "-mt-2 leading-normal")}>
        Visitors get a 503 maintenance page with <code className={code}>Retry-After</code> instead of a raw backend error. Trusted IPs and anyone who opened the bypass link still reach the backend, so the team can test the deploy.
      </p>
      <FormRow label="Message (empty = a generic one)" error={fieldError(e, "message")}>
        <textarea name="message" rows={2} maxLength={500} defaultValue={g.message} placeholder="We're upgrading the database and will be back shortly." className={field} />
      </FormRow>
      <div className="grid grid-cols-2 gap-3">
        <FormRow label="Starts (UTC, optional)" error={fieldError(e, "start")}>
          <input name="start" type="datetime-local" defaultValue={g.start} className={field} />
        </FormRow>
        <FormRow label="Ends (UTC, optional)" error={fieldError(e, "end")}>
          <input name="end" type="datetime-local" defaultValue={g.end} className={field} />
        </FormRow>
      </div>
      {g.bypass && (
        <div className="flex flex-col gap-2">
          <p className="text-[12px] text-slate-600">Bypass link (sets a cookie for 12 hours)</p>
          <p className="wrap-anywhere border border-line bg-surface px-3 py-2 font-mono text-[12px] text-ink">{`https://${s.host || location.host}/?palisade_bypass=${g.bypass}`}</p>
          <label className="flex cursor-pointer items-center gap-2 text-[12px] text-slate-600">
            <input type="checkbox" name="new_bypass" className="accent-ink" /> Replace it (links already shared stop working)
          </label>
        </div>
      )}

      <div className="border-t border-line pt-4">
        <Toggle name="waiting_room" label="Waiting room" on={g.waiting_room} />
      </div>
      <p className={cn(help, "-mt-2 leading-normal")}>
        Lets a fixed number of visitors in at a time; the rest wait in line, first come first served, on a page that refreshes itself. Each place is tied to the visitor's browser and network, so it can't be shared. The queue lives in
        this Palisade's memory: a restart sends waiting visitors to the back.
      </p>
      <div className="grid grid-cols-2 gap-3">
        <FormRow label="Max active visitors" error={fieldError(e, "max_active")}>
          <input name="max_active" type="number" min={1} defaultValue={g.max_active || ""} placeholder="500" className={field} />
        </FormRow>
        <FormRow label="Session length (minutes idle)" error={fieldError(e, "idle_mins")}>
          <input name="idle_mins" type="number" min={1} defaultValue={g.idle_mins || 10} className={field} />
        </FormRow>
      </div>
      <FormRow label="Queue page message (empty = a generic one)" error={fieldError(e, "wait_message")}>
        <textarea name="wait_message" rows={2} maxLength={500} defaultValue={g.wait_message} placeholder="Tickets go on sale at noon. Thanks for waiting!" className={field} />
      </FormRow>
      <FormRow label="Verified search crawlers">
        <select name="crawlers" defaultValue={g.crawlers} className={field}>
          <option value="bypass">Let them through (never queued)</option>
          <option value="deny">Answer 503 until the rush is over</option>
        </select>
      </FormRow>
    </TabForm>
  );
}

export function UploadsTab({ s }: { s: Service }) {
  const save = useSetService<Uploads>(s.id, "uploads");
  const e = save.error;
  const u = s.uploads;
  return (
    <TabForm
      intro={
        <>
          For S3-compatible services that accept JavaScript files with <code className={code}>PutObject</code>: JavaScript bodies stream to the backend instead of hitting the WAF's 128 KiB inspected-body limit.
        </>
      }
      pending={save.isPending}
      error={e}
      fields={["multipart_mb", "malware_scan"]}
      onSubmit={(f) => save.mutate({ large_js: f.has("large_js"), multipart_mb: num(f, "multipart_mb"), malware_scan: str(f, "malware_scan") as Uploads["malware_scan"] }, { onSuccess: saved })}
    >
      <Toggle name="large_js" label="Allow large JavaScript uploads" on={u.large_js} />
      <p className="border border-amber-300 bg-amber-50 p-3 text-[12px] leading-normal text-amber-800">
        JavaScript request bodies are then not deeply inspected, and the default CRS method and content-type rules are relaxed so S3 <code className={code}>PUT</code> works. Other header checks, IP rules, rate limits and bot protection
        stay on. Only turn this on for a trusted upload endpoint.
      </p>
      <FormRow
        label="Multipart upload limit (MiB)"
        error={fieldError(e, "multipart_mb")}
        help="Form uploads larger than this get a 413. 0 keeps the default of 12.5 MiB; the most is 256 MiB. The WAF holds each upload in memory while it checks it, so a high limit costs that much RAM per upload in flight."
      >
        <input name="multipart_mb" type="number" min={0} max={256} defaultValue={u.multipart_mb} className={field} />
      </FormRow>
      <FormRow
        label="Malware scan"
        error={fieldError(e, "malware_scan")}
        help={
          <>
            Sends each file in a form upload to ClamAV, after the WAF. Needs Palisade started with <code className={code}>--clamd</code>. Logged as <code className={code}>malware_upload</code> with the signature. If clamd is down, slow or
            the file is over its size limit, the upload goes through and is logged as <code className={code}>malware_scan_error</code>.
          </>
        }
      >
        <select name="malware_scan" defaultValue={u.malware_scan} className={field}>
          <option value="">Off</option>
          <option value="log">Log only</option>
          <option value="block">Block: refuse the upload with a 403</option>
        </select>
      </FormRow>
    </TabForm>
  );
}
