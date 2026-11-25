import { useState, type ReactNode } from "react";
import { FormRow } from "@/components/layout/Page";
import { field, fieldError, help } from "@/features/rules/shared";
import { can } from "@/lib/boot";
import { fmtTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Choice, TabForm, code, saved, str } from "./form";
import { lines, useOpenAPI, useSetService, type CSP, type JWT, type MCP, type Mode3, type OpenAPI, type Policy, type Service } from "./api";

// The Requests tab (schema, OpenAPI, MCP, JWT, request policy) and the
// Responses tab (script inventory, cookies, response inspection). Each
// check is its own form and route, as in the HTMX Schema tab.

const mono = cn(field, "font-mono");
const words = (s: string) => s.split(/[\s,]+/).filter(Boolean);

function ModeSelect({ e, children, value, onChange }: { e: unknown; children: ReactNode; value?: string; onChange?: (v: string) => void }) {
  return (
    <FormRow label="Mode" error={fieldError(e, "mode")}>
      <select name="mode" {...(onChange ? { value, onChange: (ev) => onChange(ev.target.value) } : { defaultValue: value })} className={field}>
        {children}
      </select>
    </FormRow>
  );
}

export function RequestsTab({ s }: { s: Service }) {
  return (
    <>
      <SchemaForm key={JSON.stringify(s.schema)} s={s} />
      <OpenAPIForm s={s} />
      <MCPForm key={JSON.stringify(s.mcp)} s={s} />
      <JWTForm key={JSON.stringify(s.jwt)} s={s} />
      <PolicyForm key={JSON.stringify(s.policy)} s={s} />
    </>
  );
}

export function ResponsesTab({ s }: { s: Service }) {
  return (
    <>
      <CSPForm key={JSON.stringify(s.csp)} s={s} />
      <CookiesForm key={JSON.stringify(s.cookies)} s={s} />
      <ResponsesForm key={s.responses} s={s} />
    </>
  );
}

function SchemaForm({ s }: { s: Service }) {
  const save = useSetService<Service["schema"]>(s.id, "schema");
  const e = save.error;
  return (
    <TabForm
      title="JSON Schema"
      intro="Validate this service's JSON request bodies against a JSON Schema before they reach the backend. It catches malformed or unexpected fields that generic WAF rules can't know are wrong for this endpoint. It complements the WAF, it doesn't replace it."
      pending={save.isPending}
      error={e}
      fields={["schema", "mode"]}
      onSubmit={(f) => save.mutate({ mode: str(f, "mode") as Mode3, schema: str(f, "schema") }, { onSuccess: saved })}
    >
      <FormRow label="JSON Schema" error={fieldError(e, "schema")}>
        <textarea name="schema" rows={8} spellCheck={false} defaultValue={s.schema.schema} placeholder='{"type": "object", "required": ["email"], "properties": {"email": {"type": "string", "format": "email"}}}' className={mono} />
      </FormRow>
      <fieldset className="flex flex-col gap-2">
        <legend className="sr-only">Schema mode</legend>
        <Choice name="mode" value="off" on={s.schema.mode === "off"} title="Off" copy="No schema validation. This is the default." />
        <Choice name="mode" value="log" on={s.schema.mode === "log"} title="Log only" copy="Mismatches are recorded on the request log but never block traffic. Good for checking a new schema against real requests before enforcing it." />
        <Choice name="mode" value="enforce" on={s.schema.mode === "enforce"} title="Enforce" copy="A JSON body that doesn't match the schema is rejected with 400 before it reaches the backend." />
      </fieldset>
    </TabForm>
  );
}

function OpenAPIForm({ s }: { s: Service }) {
  const q = useOpenAPI(s.id);
  if (q.isError)
    return (
      <p role="alert" className="mt-6 border-t border-line pt-5 text-[12px] text-red-600">
        Couldn't load the OpenAPI spec.
      </p>
    );
  if (!q.data) return <p className={cn(help, "mt-6 border-t border-line pt-5")}>Loading…</p>;
  return <OpenAPIFields key={JSON.stringify(q.data)} s={s} o={q.data} />;
}

function OpenAPIFields({ s, o }: { s: Service; o: OpenAPI }) {
  const save = useSetService<OpenAPI>(s.id, "openapi");
  const e = save.error;
  const [spec, setSpec] = useState(o.spec);
  return (
    <TabForm
      title="OpenAPI spec"
      intro={
        <>
          Only the routes and methods your OpenAPI 3.x document declares get through. Required parameters, parameter types and JSON bodies are checked against it too. Paths are matched after the service prefix is stripped, and a{" "}
          <code className={code}>servers</code> base path such as <code className={code}>/v1</code> may be present or not. For routes it declares, the spec replaces the JSON Schema above. Logged as{" "}
          <code className={code}>openapi_violation</code>.
        </>
      }
      pending={save.isPending}
      error={e}
      fields={["spec", "mode"]}
      onSubmit={(f) => save.mutate({ mode: str(f, "mode") as Mode3, spec: spec.trim() }, { onSuccess: saved })}
    >
      <FormRow label="Load from file (JSON or YAML)">
        <input
          type="file"
          accept=".json,.yaml,.yml,application/json,application/yaml"
          onChange={async (ev) => {
            const file = ev.target.files?.[0];
            if (file) setSpec(await file.text());
          }}
          className="block w-full text-[12px] text-slate-600 file:mr-3 file:rounded-sm file:border file:border-edge file:bg-card file:px-3 file:py-[6px] file:text-[12px] file:text-ink"
        />
      </FormRow>
      <FormRow label="Spec (empty = none)" error={fieldError(e, "spec")}>
        <textarea rows={8} spellCheck={false} value={spec} onChange={(ev) => setSpec(ev.target.value)} placeholder={"openapi: 3.0.3\npaths:\n  /users/{id}:\n    get: {}"} className={mono} />
      </FormRow>
      <ModeSelect e={e} value={o.mode}>
        <option value="off">Off (keep the spec, don't check)</option>
        <option value="log">Log only</option>
        <option value="enforce">Enforce: 404 unknown route, 405 method, 400 bad request</option>
      </ModeSelect>
    </TabForm>
  );
}

function MCPForm({ s }: { s: Service }) {
  const save = useSetService<MCP>(s.id, "mcp");
  const e = save.error;
  const m = s.mcp;
  return (
    <TabForm
      title="MCP endpoint guard"
      intro={
        <>
          Structural checks for a Model Context Protocol server on Streamable HTTP. A browser <code className={code}>Origin</code> must be on the list (or, with none listed, match the request host), which stops DNS rebinding. POST bodies must
          be JSON-RPC 2.0, and only the listed methods and <code className={code}>tools/call</code> tool names get through; an empty list allows any. It does not detect prompt injection. Logged as <code className={code}>mcp_violation</code>.
        </>
      }
      pending={save.isPending}
      error={e}
      fields={["mode", "path", "origins", "methods", "tools"]}
      onSubmit={(f) =>
        save.mutate(
          { mode: str(f, "mode") as Mode3, path: str(f, "path"), origins: lines(str(f, "origins")), methods: lines(str(f, "methods")), tools: lines(str(f, "tools")) },
          { onSuccess: saved },
        )
      }
    >
      <FormRow label="Endpoint path (after the service prefix)" error={fieldError(e, "path")}>
        <input name="path" defaultValue={m.path} placeholder="/mcp" autoComplete="off" className={mono} />
      </FormRow>
      <FormRow label="Allowed origins, one per line" error={fieldError(e, "origins")}>
        <textarea name="origins" rows={2} defaultValue={m.origins.join("\n")} placeholder="https://app.example.com" className={mono} />
      </FormRow>
      <FormRow label="Allowed methods, one per line" error={fieldError(e, "methods")} help={<><code className={code}>notifications/*</code> matches a namespace.</>}>
        <textarea name="methods" rows={3} defaultValue={m.methods.join("\n")} placeholder={"initialize\nnotifications/*\ntools/list\ntools/call"} className={mono} />
      </FormRow>
      <FormRow label="Allowed tools, one per line" error={fieldError(e, "tools")}>
        <textarea name="tools" rows={2} defaultValue={m.tools.join("\n")} placeholder="search_docs" className={mono} />
      </FormRow>
      <ModeSelect e={e} value={m.mode}>
        <option value="off">Off</option>
        <option value="log">Log only</option>
        <option value="enforce">Enforce: 403 origin, method or tool, 400 bad JSON-RPC</option>
      </ModeSelect>
    </TabForm>
  );
}

function JWTForm({ s }: { s: Service }) {
  const save = useSetService<JWT>(s.id, "jwt");
  const e = save.error;
  const j = s.jwt;
  return (
    <TabForm
      title="JWT verification"
      intro={
        <>
          Checks the <code className={code}>Authorization: Bearer</code> token on protected paths before the request reaches the backend: signature, <code className={code}>exp</code> (required), <code className={code}>nbf</code>, issuer
          and audience, with a minute of clock skew. Only RS*, PS*, ES* and EdDSA are accepted. The verified <code className={code}>sub</code> is sent as <code className={code}>X-Auth-Subject</code>; a client copy is always dropped.
          Trusted IPs are checked too. Logged as <code className={code}>jwt_invalid</code>.
        </>
      }
      pending={save.isPending}
      error={e}
      fields={["mode"]}
      onSubmit={(f) =>
        save.mutate(
          {
            mode: str(f, "mode") as Mode3,
            jwks_url: str(f, "jwks_url"),
            public_key: str(f, "public_key"),
            issuer: str(f, "issuer"),
            audience: str(f, "audience"),
            algorithms: words(str(f, "algorithms")),
            prefixes: lines(str(f, "prefixes")),
          },
          { onSuccess: saved },
        )
      }
    >
      <FormRow label="JWKS URL">
        <input name="jwks_url" type="url" defaultValue={j.jwks_url} placeholder="https://idp.example.com/.well-known/jwks.json" className={mono} />
      </FormRow>
      <FormRow label="Or a PEM public key">
        <textarea name="public_key" rows={3} spellCheck={false} defaultValue={j.public_key} placeholder="-----BEGIN PUBLIC KEY-----" className={cn(mono, "text-[12px]")} />
      </FormRow>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <FormRow label="Issuer (iss, empty = any)">
          <input name="issuer" defaultValue={j.issuer} placeholder="https://idp.example.com" autoComplete="off" className={mono} />
        </FormRow>
        <FormRow label="Audience (aud, empty = any)">
          <input name="audience" defaultValue={j.audience} placeholder="api" autoComplete="off" className={mono} />
        </FormRow>
      </div>
      <FormRow label="Allowed algorithms (empty = every asymmetric one)">
        <input name="algorithms" defaultValue={j.algorithms.join(" ")} placeholder="RS256 ES256" autoComplete="off" className={mono} />
      </FormRow>
      <FormRow label="Protected paths, one per line (after the service prefix, empty = all)">
        <textarea name="prefixes" rows={2} defaultValue={j.prefixes.join("\n")} placeholder="/api" className={mono} />
      </FormRow>
      <ModeSelect e={e} value={j.mode}>
        <option value="off">Off</option>
        <option value="log">Log only</option>
        <option value="enforce">Enforce: 401 without a valid token</option>
      </ModeSelect>
    </TabForm>
  );
}

const presets = {
  json: { label: "JSON API", methods: "GET POST PUT PATCH DELETE OPTIONS", types: "application/json", kib: 1024 },
  forms: { label: "HTML forms", methods: "GET POST", types: "application/x-www-form-urlencoded multipart/form-data", kib: 10240 },
  uploads: { label: "Uploads", methods: "GET POST PUT", types: "multipart/form-data application/octet-stream image/* video/* application/pdf", kib: 102400 },
};

function PolicyForm({ s }: { s: Service }) {
  const save = useSetService<Policy>(s.id, "policy");
  const e = save.error;
  const p = s.policy;
  const [v, setV] = useState({ methods: p.methods.join(" "), types: p.content_types.join(" "), kib: p.max_body_kib ? String(p.max_body_kib) : "" });
  return (
    <TabForm
      title="Request policy"
      intro={
        <>
          What this service accepts, checked before the WAF. Other methods get 405, a body with another <code className={code}>Content-Type</code> 415, a larger body 413, logged as <code className={code}>policy_violation</code>.{" "}
          <code className={code}>HEAD</code> is allowed with <code className={code}>GET</code>; <code className={code}>type/*</code> matches a family. Leave a field empty to allow anything. Trusted IPs skip it.
        </>
      }
      pending={save.isPending}
      error={e}
      fields={["mode", "methods", "content_types", "max_body_kib"]}
      onSubmit={(f) => save.mutate({ mode: str(f, "mode") as Mode3, methods: words(v.methods), content_types: words(v.types), max_body_kib: Number(v.kib || 0) }, { onSuccess: saved })}
    >
      <FormRow label="Preset">
        <select
          value=""
          onChange={(ev) => {
            const x = presets[ev.target.value as keyof typeof presets];
            if (x) setV({ methods: x.methods, types: x.types, kib: String(x.kib) });
          }}
          className={field}
        >
          <option value="">Choose to fill the fields…</option>
          {Object.entries(presets).map(([k, x]) => (
            <option key={k} value={k}>
              {x.label}
            </option>
          ))}
        </select>
      </FormRow>
      <FormRow label="Allowed methods" error={fieldError(e, "methods")}>
        <input value={v.methods} onChange={(ev) => setV({ ...v, methods: ev.target.value })} placeholder="GET POST" autoComplete="off" className={mono} />
      </FormRow>
      <FormRow label="Allowed request content types" error={fieldError(e, "content_types")}>
        <input value={v.types} onChange={(ev) => setV({ ...v, types: ev.target.value })} placeholder="application/json" autoComplete="off" className={mono} />
      </FormRow>
      <FormRow label="Maximum body size (KiB, 0 = no limit)" error={fieldError(e, "max_body_kib")}>
        <input type="number" min={0} max={1048576} value={v.kib} onChange={(ev) => setV({ ...v, kib: ev.target.value })} placeholder="0" className={field} />
      </FormRow>
      <ModeSelect e={e} value={p.mode}>
        <option value="off">Off</option>
        <option value="log">Log only</option>
        <option value="enforce">Enforce</option>
      </ModeSelect>
    </TabForm>
  );
}

function CSPForm({ s }: { s: Service }) {
  const save = useSetService<Pick<CSP, "mode" | "policy" | "approved">>(s.id, "csp");
  const e = save.error;
  const c = s.csp;
  const [mode, setMode] = useState(c.mode);
  const submit = (f: FormData, m: CSP["mode"]) => save.mutate({ mode: m, policy: str(f, "policy"), approved: f.getAll("approved").map(String) }, { onSuccess: saved });
  return (
    <TabForm
      title="Script inventory (CSP)"
      intro={
        <>
          Adds a <code className={code}>Content-Security-Policy-Report-Only</code> header to HTML pages. Browsers report every script the policy doesn't allow to <code className={code}>/_cz/csp-report</code>, and each new source is added to the
          inventory below and sent as an alert (webhook "New script sources", and email). Leave out <code className={code}>report-uri</code> and <code className={code}>report-to</code>; Palisade adds them.
        </>
      }
      pending={save.isPending}
      error={e}
      fields={["mode", "policy"]}
      onSubmit={(f) => submit(f, mode)}
    >
      <FormRow label="Policy" error={fieldError(e, "policy")}>
        <textarea name="policy" rows={2} spellCheck={false} defaultValue={c.policy} placeholder="script-src 'self'" className={mono} />
      </FormRow>
      <ModeSelect e={e} value={mode} onChange={(v) => setMode(v as CSP["mode"])}>
        <option value="off">Off</option>
        <option value="report">Report only</option>
        <option value="enforce">Enforce: block sources not approved</option>
      </ModeSelect>
      <fieldset className="flex flex-col gap-2">
        <legend className="mb-1 text-[13px] font-semibold text-ink">Approved sources</legend>
        <p className={cn(help, "leading-normal")}>
          Enforce sends <code className={code}>Content-Security-Policy</code> with the policy's <code className={code}>script-src</code> plus the sources ticked here. Other sources are blocked and still reported, so a new one shows up here
          for approval.
        </p>
        {c.scripts?.length ? (
          <ul className="flex flex-col divide-y divide-line border border-line">
            {c.scripts.map((sc) => (
              <li key={sc.origin}>
                <label className="flex cursor-pointer items-start gap-3 px-3 py-2">
                  <input type="checkbox" name="approved" value={sc.origin} defaultChecked={c.approved.includes(sc.origin)} className="mt-[3px] accent-ink" />
                  <span className="min-w-0">
                    <span className="block wrap-anywhere font-mono text-[12px] text-ink">{sc.origin}</span>
                    <span className="block text-[11px] text-slate-500">
                      first on {sc.page} · {fmtTime(sc.first_seen)}
                    </span>
                  </span>
                </label>
              </li>
            ))}
          </ul>
        ) : (
          <p className={help}>No script sources reported yet.</p>
        )}
        {c.full && <p className="text-[12px] text-amber-800">The inventory is full: new sources are no longer recorded.</p>}
      </fieldset>
      {c.recent && mode === "enforce" && (
        <p role="alert" className="border border-amber-300 bg-amber-50 p-3 text-[12px] leading-normal text-amber-800">
          New script sources were reported in the last 7 days. The inventory may not have settled; enforcing now can break pages that load them.
        </p>
      )}
      {c.mode === "enforce" && can("admin") && (
        <button type="button" disabled={save.isPending} onClick={(ev) => submit(new FormData(ev.currentTarget.form!), "report")} className={cn(field, "cursor-pointer text-center hover:bg-surface")}>
          Return to report-only
        </button>
      )}
    </TabForm>
  );
}

function CookiesForm({ s }: { s: Service }) {
  const save = useSetService<Service["cookies"]>(s.id, "cookies");
  const e = save.error;
  return (
    <TabForm
      title="Harden backend cookies"
      intro={
        <>
          Adds <code className={code}>HttpOnly</code>, <code className={code}>SameSite=Lax</code> and, on HTTPS, <code className={code}>Secure</code> to every <code className={code}>Set-Cookie</code> from the backend that lacks them.
          Attributes the backend already set are kept. List cookies the page's JavaScript must read, or that must be sent cross-site, to leave them alone.
        </>
      }
      pending={save.isPending}
      error={e}
      fields={["exempt"]}
      onSubmit={(f) => save.mutate({ enabled: str(f, "enabled") === "on", exempt: words(str(f, "exempt")) }, { onSuccess: saved })}
    >
      <FormRow label="Leave these cookies alone" error={fieldError(e, "exempt")}>
        <input name="exempt" defaultValue={s.cookies.exempt.join(", ")} placeholder="csrftoken, theme" autoComplete="off" className={mono} />
      </FormRow>
      <FormRow label="Cookie hardening">
        <select name="enabled" defaultValue={s.cookies.enabled ? "on" : "off"} className={field}>
          <option value="off">Off</option>
          <option value="on">On</option>
        </select>
      </FormRow>
    </TabForm>
  );
}

function ResponsesForm({ s }: { s: Service }) {
  const save = useSetService<{ mode: Service["responses"] }>(s.id, "responses");
  const e = save.error;
  return (
    <TabForm
      title="Inspect responses"
      intro={
        <>
          Checks the backend's replies for leaked SQL errors, stack traces, PHP/Java/IIS error pages and web shells with the OWASP CRS outbound rules. Logged as <code className={code}>response_leak</code>. Only HTML, plain text, JSON and XML
          up to 64 KiB are inspected; binary, streaming and larger responses pass through untouched. Each inspected response adds about 0.5 ms per KiB.
        </>
      }
      pending={save.isPending}
      error={e}
      fields={["mode"]}
      onSubmit={(f) => save.mutate({ mode: str(f, "mode") as Service["responses"] }, { onSuccess: saved })}
    >
      <ModeSelect e={e} value={s.responses}>
        <option value="">Off</option>
        <option value="log">Log only</option>
        <option value="block">Block: replace the response with a 502</option>
      </ModeSelect>
    </TabForm>
  );
}
