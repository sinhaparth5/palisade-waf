import { vi } from "vitest";

// mockApi replaces fetch with a table of admin API routes, keyed
// "METHOD /path" relative to the admin path ("GET /api/v1/stats").
// A request no route matches fails the test, so a page can't quietly call
// an endpoint the test didn't expect. vitest unstubs fetch after each test.
//
//   const api = mockApi({
//     "GET /api/v1/services": [{ id: 1, name: "web" }],
//     "POST /api/v1/services": (req) => reply(201, { id: 2, ...req.json }),
//     "DELETE /api/v1/services/1": reply(409, { error: "docker_managed", message: "..." }),
//   });
//   ...
//   expect(api.calls("POST /api/v1/services")[0]!.json).toEqual({ name: "api" });

export type ApiRequest = {
  method: string;
  path: string; // without the admin path, with the query string
  headers: Headers;
  json: unknown; // parsed JSON body, or undefined
};

// A JSON body (answered 200), a Response, or a function of the request.
// Listed without `unknown` so a handler's `req` parameter gets its type.
type Responder = ((req: ApiRequest) => unknown) | Response | object | string | number | boolean | null;

export function reply(status: number, body?: unknown): Response {
  return status === 204
    ? new Response(null, { status })
    : new Response(JSON.stringify(body ?? {}), { status, headers: { "Content-Type": "application/json" } });
}

// pending never answers: for asserting loading states.
export const pending = () => new Promise<never>(() => {});

export function mockApi(routes: Record<string, Responder>, admin = "/admin") {
  const log: (ApiRequest & { key: string })[] = [];

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(String(input), "http://palisade.test");
    const method = (init.method ?? "GET").toUpperCase();
    const path = url.pathname.replace(admin, "") + url.search;
    const req: ApiRequest = {
      method,
      path,
      headers: new Headers(init.headers),
      json: typeof init.body === "string" && init.body ? JSON.parse(init.body) : undefined,
    };
    const key = `${method} ${path}`;
    log.push({ ...req, key });

    const route = key in routes ? routes[key] : routes[`${method} ${url.pathname.replace(admin, "")}`];
    if (route === undefined) throw new Error(`mockApi: unexpected ${key}`);
    const out: unknown = typeof route === "function" ? await route(req) : route;
    // A fresh Response per call: a body can only be read once.
    return out instanceof Response ? out.clone() : reply(200, out);
  });
  vi.stubGlobal("fetch", fetchMock);

  return {
    fetch: fetchMock,
    // calls("POST /api/v1/x") lists the requests sent to one route, in order.
    calls: (key?: string) => (key ? log.filter((r) => r.key === key || r.key.split("?")[0] === key) : log),
  };
}
