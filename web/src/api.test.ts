import { afterEach, expect, test, vi } from "vitest";
import { api, ApiError } from "./api";

const fetchMock = vi.fn();
vi.stubGlobal("fetch", fetchMock);
document.body.dataset.csrf = "tok";

afterEach(() => fetchMock.mockReset());

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

test("writes carry the CSRF token, reads do not", async () => {
  fetchMock.mockResolvedValue(json(200, {}));
  await api("services");
  await api("services", { method: "POST", body: "{}" });
  const [read, write] = fetchMock.mock.calls.map(([, init]) => new Headers(init.headers));
  expect(read!.has("X-CSRF-Token")).toBe(false);
  expect(write!.get("X-CSRF-Token")).toBe("tok");
});

test("error responses become ApiError with code and fields", async () => {
  fetchMock.mockResolvedValue(json(400, { error: "invalid", message: "bad host", fields: { host: "required" } }));
  const err = await api("services", { method: "POST" }).catch((e) => e);
  expect(err).toBeInstanceOf(ApiError);
  expect(err).toMatchObject({ status: 400, code: "invalid", fields: { host: "required" } });
});

test("401 sends the browser to login", async () => {
  const assign = vi.fn();
  vi.stubGlobal("location", { ...window.location, assign });
  fetchMock.mockResolvedValue(json(401, {}));
  await expect(api("me")).rejects.toMatchObject({ status: 401 });
  expect(assign).toHaveBeenCalledOnce();
});
