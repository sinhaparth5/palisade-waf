import { api, ApiError } from "@/lib/api";
import { mockApi, reply } from "@/test/api-mock";

describe("api", () => {
  let assign: ReturnType<typeof vi.fn>;
  beforeEach(() => {
    assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign });
  });

  it("resolves paths under the admin path and parses JSON", async () => {
    mockApi({ "GET /api/v1/stats": { total: 3 } });
    await expect(api("/api/v1/stats")).resolves.toEqual({ total: 3 });
  });

  it("sends the CSRF token on writes only", async () => {
    const mock = mockApi({ "GET /api/v1/x": {}, "POST /api/v1/x": {} });
    await api("api/v1/x");
    await api("api/v1/x", { method: "POST", body: JSON.stringify({ a: 1 }) });
    const [read, write] = mock.calls();
    expect(read!.headers.has("X-CSRF-Token")).toBe(false);
    expect(write!.headers.get("X-CSRF-Token")).toBe("test-csrf");
    expect(write!.headers.get("Content-Type")).toBe("application/json");
    expect(write!.json).toEqual({ a: 1 });
  });

  it("returns null for 204", async () => {
    mockApi({ "DELETE /api/v1/x/1": reply(204) });
    await expect(api("api/v1/x/1", { method: "DELETE" })).resolves.toBeNull();
  });

  it.each([
    ["JSON error body", reply(400, { error: "invalid", message: "bad host", fields: { host: "required" } }),
      { status: 400, code: "invalid", message: "bad host", fields: { host: "required" } }],
    ["no JSON body", new Response("boom", { status: 500, statusText: "Internal Server Error" }),
      { status: 500, code: "error", message: "Internal Server Error" }],
  ])("turns an error (%s) into ApiError", async (_, res, want) => {
    mockApi({ "POST /api/v1/x": res });
    const err = await api("api/v1/x", { method: "POST" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject(want);
  });

  it("sends the browser to login on 401", async () => {
    mockApi({ "GET /api/v1/me": reply(401) });
    await expect(api("api/v1/me")).rejects.toMatchObject({ status: 401 });
    expect(assign).toHaveBeenCalledWith("/admin/login");
  });

  it("sends the browser to login on a redirect (sessionAuth on an expired session)", async () => {
    // fetch with redirect: "manual" gives an opaqueredirect, which a real
    // Response can't be built as, so stub fetch directly.
    vi.stubGlobal("fetch", vi.fn(async () => ({ type: "opaqueredirect", status: 0, ok: false })));
    await expect(api("api/v1/me")).rejects.toMatchObject({ status: 401 });
    expect(assign).toHaveBeenCalledWith("/admin/login");
  });
});
