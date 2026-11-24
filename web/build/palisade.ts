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
      for (const name of await readdir(dir)) {
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
