import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { createWriteStream, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { request, type APIRequestContext } from "@playwright/test";

const root = resolve(import.meta.dirname, "../..");

// Starts Palisade on a temp DB, seeds one of each record the pages list, and
// saves a signed-in browser state per role (E2E_DIR/<role>.json). Returns
// the teardown.
export default async function setup() {
  const dir = mkdtempSync(join(tmpdir(), "palisade-e2e-"));
  const bin = join(dir, "palisade");
  execFileSync("go", ["build", "-o", bin, "."], { cwd: root, stdio: "inherit" });

  const pass = `e2e-${randomBytes(12).toString("hex")}`;
  writeFileSync(join(dir, "pw"), `${pass}\n`);
  execFileSync(bin, ["setup", "--db", "waf.db", "--admin-email", "owner@example.com", "--password-file", "pw"], { cwd: dir, stdio: "inherit" });

  // A backend for the seeded service (adding one probes it).
  const backend = createServer((_, res) => res.end("ok")).listen(0, "127.0.0.1");
  await once(backend, "listening");
  const backendURL = `http://127.0.0.1:${(backend.address() as AddressInfo).port}`;

  const srv = spawn(bin, ["--listen", "127.0.0.1:0", "--db", "waf.db"], { cwd: dir, stdio: ["ignore", "pipe", "pipe"] });
  const log = createWriteStream(join(dir, "palisade.log"));
  srv.stdout.pipe(log);
  const base = await new Promise<string>((ok, fail) => {
    let out = "";
    srv.stderr.on("data", (b: Buffer) => {
      log.write(b);
      out += b;
      const m = /palisade listening on (\S+)/.exec(out);
      if (m) ok(`http://${m[1]}`);
    });
    srv.on("exit", (code) => fail(new Error(`palisade exited (${code}):\n${out}`)));
  });

  const teardown = async () => {
    srv.kill("SIGTERM");
    backend.close();
    rmSync(dir, { recursive: true, force: true });
  };
  try {
    const owner = await request.newContext({ baseURL: base });
    await check(owner.post("/admin/login", { form: { email: "owner@example.com", password: pass } }), "owner sign-in");
    const csrf = /data-csrf="([^"]+)"/.exec(await (await owner.get("/admin/")).text())?.[1];
    if (!csrf) throw new Error("owner sign-in didn't reach the app");
    const post = (path: string, data: object) => check(owner.post(`/admin/api${path}`, { data, headers: { "X-CSRF-Token": csrf, Accept: "application/json" } }), `POST ${path}`);

    execFileSync(bin, ["gencert", "--hosts", "shop.example.com", "--cert", "c.pem", "--key", "k.pem"], { cwd: dir });
    await post("/services", { name: "shop", match_type: "host", match_value: "shop.example.com", backend: backendURL, rate_limit_rps: 0, rate_limit_burst: 0 });
    await post("/certificates", { name: "shop", cert_pem: readFileSync(join(dir, "c.pem"), "utf8"), key_pem: readFileSync(join(dir, "k.pem"), "utf8") });
    await post("/ip-rules", { ip: "203.0.113.9", app_name: "", rule_type: "block" });
    await post("/geo-rules", { country_code: ["RU"], app_name: "", rule_type: "block" });
    await post("/waf-rules/exceptions", { rule_id: 942100, service: "shop", reason: "noisy" });
    await post("/waf-rules/custom", { rule: `SecRule ARGS "@contains x" "id:1000001,phase:2,deny"`, service: "", note: "" });
    await post("/threat-intel", { label: "Feed", url: `${backendURL}/list.txt`, interval_hours: 24 });
    await owner.get("/?id=1%27%20OR%20%271%27=%271"); // a request log row

    for (const role of ["admin", "viewer"]) {
      const res = await post("/settings/users", { email: `${role}@example.com`, role });
      const { link } = (await res.json()) as { link?: string };
      if (!link) throw new Error(`no invite link for ${role}`);
      const ctx = await request.newContext({ baseURL: base });
      await check(ctx.post(link, { form: { email: `${role}@example.com`, password: pass, confirm_password: pass } }), `${role} invite`);
      await ctx.storageState({ path: join(dir, `${role}.json`) });
      await ctx.dispose();
    }
    await owner.dispose();
  } catch (e) {
    await teardown();
    throw e;
  }
  process.env.E2E_BASE = base;
  process.env.E2E_DIR = dir;
  return teardown;
}

async function check(res: ReturnType<APIRequestContext["post"]>, what: string) {
  const r = await res;
  if (!r.ok()) throw new Error(`${what}: ${r.status()} ${await r.text()}`);
  return r;
}
