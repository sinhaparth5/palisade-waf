// Vite plugins that fit the build to the Go server (internal/ui/app.go).
import { readFile, readdir, writeFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { brotliCompressSync, gzipSync, constants } from "node:zlib";
import type { Plugin } from "vite";

// goTemplate points the built index.html's asset URLs at {{.Base}}, which Go
// fills with "<admin path>/app/". Relative URLs would break on deep routes
// (/admin/app/logs/5), and <base href> is ruled out by the CSP's base-uri 'none'.
export function goTemplate(): Plugin {
  return {
    name: "palisade:go-template",
    apply: "build",
    transformIndexHtml: {
      order: "post",
      handler: (html) => {
        const out = html.replace(/(src|href)="\.\/assets\//g, '$1="{{.Base}}assets/');
        if (out.includes('="./')) throw new Error("index.html still has a relative URL Go can't serve");
        return out;
      },
    },
  };
}

// precompress writes .br and .gz next to every text asset; Go picks one by
// Accept-Encoding, so nothing is compressed per request.
export function precompress(): Plugin {
  let outDir = "";
  return {
    name: "palisade:precompress",
    apply: "build",
    configResolved: (c) => void (outDir = c.build.outDir),
    async closeBundle() {
      const dir = join(outDir, "assets");
      // closeBundle runs after a failed build too; let that error through.
      const names = await readdir(dir).catch(() => null);
      if (!names) return;
      for (const name of names) {
        if (!/\.(js|css|svg|json|md)$/.test(name)) continue;
        const file = join(dir, name);
        if ((await stat(file)).size < 1024) continue;
        const body = await readFile(file);
        await writeFile(`${file}.br`, brotliCompressSync(body, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } }));
        await writeFile(`${file}.gz`, gzipSync(body, { level: 9 }));
      }
    },
  };
}

// sonnerNoInlineStyle drops the <style> sonner injects at import, which the
// admin CSP (style-src 'self' + nonce) would block; src/index.css imports
// sonner's stylesheet instead. Fails the build if sonner changes shape.
export function sonnerNoInlineStyle(): Plugin {
  return {
    name: "palisade:sonner-no-inline-style",
    enforce: "pre",
    transform(code, id) {
      if (!/[\\/]sonner[\\/]dist[\\/]index\.m?js$/.test(id)) return;
      const out = code.replace(/__insertCSS\("(?:[^"\\]|\\.)*"\);?/, "");
      if (out === code) this.error("sonner no longer calls __insertCSS: recheck its inline <style> against the admin CSP");
      return out;
    },
  };
}

// unbrand renames the names libraries leave in the built JS and CSS (globals
// that devtools and fingerprinting extensions look for, DOM property keys,
// history state keys, attributes, error links), so the app reads as Palisade
// end to end. A rule that stops matching fails the build, and so does any
// library name left in the output afterwards: a new dependency or version
// gets a rule here before it ships. `bun run smoke` checks the renamed build
// still renders.

// Names several files must agree on (a JS attribute and its CSS selector,
// React's symbols in react and react-dom). Renamed before Rolldown hashes the
// file names, in unminified code (either quote style), so a rule change gives
// new names and the year-long immutable cache can't mix old and new files.
export const sharedRules: [RegExp, string][] = [
  // React DevTools and extensions find React through this hook; renamed,
  // React never registers with them.
  [/__REACT_DEVTOOLS_GLOBAL_HOOK__/g, "__PL_DT__"],
  // Property keys React puts on DOM nodes, events and components:
  // __reactFiber$, _reactRootContainer, _reactInternals, $$reactFormReplay, ...
  [/(\b_{1,2}|\$\$)react(?=[A-Z])/g, "$1pl"],
  [/\breactFragments\b/g, "plFragments"],
  [/\bis(Pure)?ReactComponent\b/g, "is$1PlComponent"],
  [/Symbol\.for\((["'`])react\./g, "Symbol.for($1pl."],
  [/(["'`])react-dom\1/g, "$1pl-dom$1"], // renderer name, only reported to devtools
  [/(["'`])react-transition\1/g, "$1pl-transition$1"], // navigation API info tag
  // The router puts itself on window; nothing reads it back.
  [/self\.__TSR_ROUTER__\s*=\s*this/g, "0"],
  [/__TSR_/g, "__pl_"], // history.state keys
  [/sonner/g, "pltoast"], // data-sonner-*, class names, keyframes
  [/data-slot/g, "data-part"], // shadcn's marker attribute
  [/data-react-aria-top-layer/g, "data-pl-layer"], // sonner marks toasts for react-aria
];

// Text inside one file: error messages (only safe once minified, when no
// identifier is left named React) and helpers Vite adds after hashing.
export const localRules: [RegExp, string][] = [
  [/; visit `\+\w+\+` for the full message or use the non-minified dev environment for full errors and additional helpful warnings\./g, ""],
  [/Minified React error #/g, "Error #"],
  [/https:\/\/react\.dev\/errors\//g, ""],
  [/tanstack_router_reload/g, "pl_reload"],
  [/vite:preloadError/g, "pl:preloadError"],
  [/__vite__mapDeps/g, "__pl_deps"],
  [/\bReact\b/g, "UI"], // remaining error text; last, after the specific rules
];

const leak = /\w*(?:react|tanstack|vite|rolldown|radix|sonner|shadcn|__TSR|data-slot)[\w-]*/gi;

// unbrander applies rules and counts what each one matched, across calls.
export function unbrander(rules: [RegExp, string][]) {
  const hits = rules.map(() => 0);
  return {
    apply: (text: string) =>
      rules.reduce((s, [re, to], i) => {
        hits[i]! += s.match(re)?.length ?? 0;
        return s.replace(re, to);
      }, text),
    dead: () => rules.filter((_, i) => hits[i] === 0).map(([re]) => re.source),
  };
}

export const leftovers = (texts: string[]) => [...new Set(texts.flatMap((s) => s.match(leak) ?? []))];

export function unbrand(): Plugin {
  let shared = unbrander(sharedRules);
  let local = unbrander(localRules);
  return {
    name: "palisade:unbrand",
    apply: "build",
    buildStart() {
      shared = unbrander(sharedRules);
      local = unbrander(localRules);
    },
    transform(code, id) {
      if (/\.css(\?|$)/.test(id)) return shared.apply(code);
    },
    renderChunk: { order: "post", handler: (code) => shared.apply(code) },
    generateBundle: {
      order: "post",
      handler(_, bundle) {
        const texts: string[] = [];
        for (const f of Object.values(bundle)) {
          if (f.type === "chunk") texts.push((f.code = local.apply(f.code)));
          else if (f.fileName.endsWith(".css")) texts.push((f.source = local.apply(String(f.source))));
        }
        const dead = [...shared.dead(), ...local.dead()];
        if (dead.length) this.error(`unbrand rules no longer match (library changed?): ${dead.join(", ")}`);
        const left = leftovers(texts);
        if (left.length) this.error(`library names left in the build, add an unbrand rule: ${left.join(", ")}`);
      },
    },
  };
}

// devPalisade runs `bun run dev` against a local Palisade: every admin request
// except the app itself is proxied there, and the app's HTML gets the session
// values (CSRF, role, ...) from the page Go renders for the same cookie.
// Needs one `make web` first so Go has an index.html to render.
export function devPalisade(target: string): Plugin {
  const admin = "/admin";
  return {
    name: "palisade:dev",
    apply: "serve",
    config: () => ({
      server: {
        proxy: { [`^${admin}(?!/app(/|$))`]: { target, changeOrigin: false, ws: true } },
      },
    }),
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        const url = req.url ?? "";
        if (!url.startsWith(`${admin}/app`) || !(req.headers.accept ?? "").includes("text/html")) return next();
        const go = await fetch(new URL(`${admin}/app/`, target), {
          headers: { cookie: req.headers.cookie ?? "" },
          redirect: "manual",
        }).catch(() => null);
        if (!go) return void res.writeHead(502).end(`Palisade is not running at ${target}`);
        if (go.status !== 200) {
          res.writeHead(go.status === 404 ? 404 : 302, { location: go.headers.get("location") ?? `${admin}/login` });
          return void res.end(go.status === 404 ? "Run `make web` once so Palisade has an index.html to render." : "");
        }
        const body = (await go.text()).match(/<body([^>]*)>/)?.[1] ?? "";
        const src = await readFile(new URL("../index.html", import.meta.url), "utf8");
        const html = await server.transformIndexHtml(url, src
            .replace(/<body[^>]*>/, `<body${body}>`)
            .replaceAll("{{.AdminPath}}", admin)
            .replaceAll("{{.Asset}}", "dev"));
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.end(html);
      });
    },
  };
}
