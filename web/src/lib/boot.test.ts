import { asRole } from "@/test/boot";
import { boot, can } from "./boot";

describe("boot", () => {
  it("reads what Go rendered onto <body>", () => {
    expect(boot).toMatchObject({ admin: "/admin", csrf: "test-csrf", role: "owner", demo: false, waf: true, nonce: "test-nonce" });
  });

  it("falls back to safe defaults when <body> has no values", async () => {
    const saved = { ...document.body.dataset };
    for (const k of Object.keys(saved)) delete document.body.dataset[k];
    vi.resetModules();
    try {
      const fresh = await import("./boot");
      // Least privilege: no role rendered means viewer.
      expect(fresh.boot).toEqual({ admin: "/admin", csrf: "", role: "viewer", email: "", demo: false, version: "", waf: false, pro: false, nonce: "" });
      expect(fresh.can("admin")).toBe(false);
    } finally {
      Object.assign(document.body.dataset, saved);
    }
  });

  it.each([
    ["viewer", { viewer: true, admin: false, owner: false }],
    ["admin", { viewer: true, admin: true, owner: false }],
    ["owner", { viewer: true, admin: true, owner: true }],
  ] as const)("can() as %s", (role, want) => {
    asRole(role);
    expect({ viewer: can("viewer"), admin: can("admin"), owner: can("owner") }).toEqual(want);
  });

  it("denies everything to an unknown role", () => {
    boot.role = "root" as never;
    expect(can("viewer")).toBe(false);
  });
});
