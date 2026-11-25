// bun run smoke: loads the production build (static/app/dist) in jsdom the
// way Go serves it and checks it renders; `login` checks the sign-in page's
// own build (dist/login) instead. Unit tests run the dev build; this
// is what proves the unbrand renames (build/palisade.ts) left a working app,
// and that nothing at runtime still names a library.
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { JSDOM, VirtualConsole } from "jsdom";

const login = process.argv[2] === "login";
const dist = fileURLToPath(new URL(login ? "../../static/app/dist/login/" : "../../static/app/dist/", import.meta.url));
const base = login ? "/admin/login/" : "/admin/";
const html = (await readFile(`${dist}${login ? "login.html" : "index.html"}`, "utf8"))
  .replaceAll("{{.Base}}", base)
  .replaceAll("{{.AdminPath}}", "/admin")
  .replace(/\{\{\.(\w+)\}\}/g, (_, k: string) => ({ Role: "owner", Demo: "false", Stage: "" })[k] ?? "x");

// A quiet console: jsdom logs "not implemented" for scrollTo.
const dom = new JSDOM(html, { url: `http://localhost${login ? "/admin/login" : "/admin/"}`, virtualConsole: new VirtualConsole() });
const w = dom.window as unknown as Record<string, unknown>;
for (const k of Object.getOwnPropertyNames(w)) if (!(k in globalThis)) (globalThis as Record<string, unknown>)[k] = w[k];
// jsdom has no EventSource; the notification stream just stays silent.
const EventSource = class extends dom.window.EventTarget {
  close() {}
};
Object.assign(globalThis, { EventSource, window: w, document: dom.window.document, navigator: dom.window.navigator, location: dom.window.location, history: dom.window.history });

const fail = (msg: string) => {
  console.error(`smoke: ${msg}`);
  process.exit(1);
};

const entry = html.match(new RegExp(`<script type="module"[^>]*src="${base}(assets/[^"]+)"`))?.[1];
if (!entry) fail("no entry script in index.html");
await import(`${dist}${entry}`);

const doc = dom.window.document;
for (let i = 0; i < 50 && !doc.querySelector("#palisade h1"); i++) await new Promise((r) => setTimeout(r, 20));
if (doc.querySelector("#palisade h1")?.textContent !== (login ? "Welcome back" : "Dashboard")) fail(`app did not render: ${doc.body.innerHTML.slice(0, 300)}`);

// Nothing a console, devtools or an extension can read should name a library.
const leak = /react|tanstack|(?<!in)vite|radix|sonner|cmdk|__TSR/i; // not "invite"
const keys = [...doc.querySelectorAll("*")].flatMap((el) => [...Object.keys(el), ...el.getAttributeNames()]);
const globals = [...Object.getOwnPropertyNames(w), ...Object.getOwnPropertySymbols(w).map(String)].filter((k) => leak.test(k));
const found = [...keys, ...globals, ...Object.keys((dom.window.history.state as object) ?? {})].filter((k) => leak.test(k));
if (found.length) fail(`library names at runtime: ${[...new Set(found)].join(", ")}`);
if (!keys.some((k) => k.startsWith("__plFiber"))) fail("renamed fiber key not found: did the unbrand rules change?");

console.log(`smoke: ${login ? "login" : "production"} build renders, no library names at runtime`);
process.exit(0);
