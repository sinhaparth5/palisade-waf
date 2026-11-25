import { screen, within } from "@testing-library/react";
import { mockApi, pending, reply } from "@/test/api-mock";
import { asRole } from "@/test/boot";
import { renderRoute } from "@/test/render";
import type { CacheStats } from "./api";
import { base, openEdit, svc } from "./fixtures";

describe("services page", () => {
  it("shows loading, a failed read and an empty list", async () => {
    mockApi({ ...base([]), "GET /api/services": pending });
    const r = await renderRoute("/services");
    expect(screen.getAllByText("Loading…").length).toBeGreaterThan(0);
    r.unmount();
    mockApi({ ...base([]), "GET /api/services": reply(500, {}) });
    const r2 = await renderRoute("/services");
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't load the services");
    r2.unmount();
    mockApi(base([]));
    await renderRoute("/services");
    expect(await screen.findByText("No services configured yet")).toBeInTheDocument();
  });

  it("lists services with their health, backends and what they turn on", async () => {
    mockApi(
      base([
        svc({
          rate_limit: { rps: 10, burst: 0, path_rules: "" },
          docker: true,
          known: true,
          healthy: false,
          tls: { mode: "auto", cert_id: 0, cert_name: "", expires_at: "", http3: true, mtls: { mode: "required", ca_set: true, allow: [] } },
          backends: {
            urls: ["http://a:1", "http://b:1"],
            health: [
              { url: "http://a:1", healthy: true, known: true },
              { url: "http://b:1", healthy: false, known: true },
            ],
            lb_policy: "round_robin",
            health_path: "",
            health_interval: 0,
            ca: "",
          },
        }),
        svc({ id: 2, name: "api", host: "", prefix: "/api" }),
      ]),
    );
    await renderRoute("/services");
    const list = within((await screen.findByRole("heading", { name: "Configured Services" })).closest("section")!);
    expect(await list.findByRole("img", { name: /Unreachable/ })).toBeInTheDocument();
    for (const t of ["docker", "10/s", "Auto TLS (Let's Encrypt)", "HTTP/3", "mTLS: required", "http://b:1"]) expect(list.getByText(t)).toBeInTheDocument();
    expect(list.getByText(/\/api → http:\/\/10.0.0.5:3000/)).toBeInTheDocument();
    expect(screen.getByText("1 unreachable")).toBeInTheDocument();
  });

  it("adds a service step by step and shows why the server refused it", async () => {
    let fail = true;
    const api = mockApi({
      ...base([]),
      "POST /api/services": () => (fail ? reply(400, { error: "invalid", message: "dial tcp: connection refused. Fix the backend and try again." }) : reply(201, {})),
    });
    const { user } = await renderRoute("/services");
    const c = within((await screen.findByRole("heading", { name: "Add Service" })).closest("section")!);
    await user.click(c.getByRole("button", { name: "Next" }));
    expect(c.getByText("This field is required.")).toBeInTheDocument();
    await user.type(c.getByLabelText("Service name"), "shop");
    await user.click(c.getByRole("button", { name: "Next" }));
    await user.click(c.getByLabelText("Path prefix"));
    await user.type(c.getByLabelText("Path prefix", { selector: "input:not([type=radio])" }), "/shop");
    await user.click(c.getByRole("button", { name: "Next" }));
    await user.type(c.getByLabelText("Backend URL"), "http://127.0.0.1:3000");
    await user.type(c.getByLabelText("Requests / second (optional)"), "5");
    await user.click(c.getByRole("button", { name: "Next" }));
    await user.click(c.getByRole("button", { name: /Create service/ }));
    expect(await c.findByRole("alert")).toHaveTextContent("connection refused");
    fail = false;
    await user.click(c.getByRole("button", { name: /Create service/ }));
    await vi.waitFor(() => expect(api.calls("POST /api/services")).toHaveLength(2));
    expect(api.calls("POST /api/services")[1]!.json).toEqual({ name: "shop", match_type: "prefix", match_value: "/shop", backend: "http://127.0.0.1:3000", rate_limit_rps: 5, rate_limit_burst: 0 });
    expect(await c.findByLabelText("Service name")).toHaveValue("");
  });

  it("edits the rate limit, backends and hosts, and renames", async () => {
    let fail = true;
    const api = mockApi({
      ...base([svc()]),
      "PUT /api/services/1/rate-limit": () => (fail ? reply(400, { error: "invalid", message: "x", fields: { path_rules: "line 1: bad rate" } }) : reply(204)),
      "PUT /api/services/1/backends": reply(204),
      "PUT /api/services/1/hosts": reply(204),
      "PUT /api/services/1/name": reply(204),
    });
    const { user } = await renderRoute("/services");
    const d = await openEdit(user);
    await user.type(d.getByLabelText("Requests / second"), "2.5");
    await user.type(d.getByLabelText("Path limits"), "GET /x nope");
    await user.click(d.getByRole("button", { name: /Save/ }));
    expect(await d.findByText("line 1: bad rate")).toBeInTheDocument();
    fail = false;
    await user.click(d.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/services/1/rate-limit")).toHaveLength(2));
    expect(api.calls("PUT /api/services/1/rate-limit")[1]!.json).toEqual({ rps: 2.5, burst: 0, path_rules: "GET /x nope" });

    await user.click(d.getByRole("tab", { name: "Backends" }));
    await user.type(d.getByLabelText("Backends, one per line"), "\nhttp://10.0.0.6:3000\n");
    await user.click(d.getByLabelText(/Least connections/));
    await user.type(d.getByLabelText("Health check path"), "/healthz");
    await user.click(d.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() =>
      expect(api.calls("PUT /api/services/1/backends")[0]?.json).toEqual({ urls: ["http://10.0.0.5:3000", "http://10.0.0.6:3000"], lb_policy: "least_conn", health_path: "/healthz", health_interval: 0, ca: "" }),
    );

    await user.click(d.getByRole("tab", { name: "Hosts" }));
    await user.type(d.getByLabelText("Extra hostnames, one per line"), "www.blog.example.com");
    await user.selectOptions(d.getByLabelText("Redirect the other names to"), "blog.example.com");
    await user.click(d.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/services/1/hosts")[0]?.json).toEqual({ aliases: ["www.blog.example.com"], canonical: "blog.example.com" }));

    await user.clear(d.getByLabelText("Name"));
    await user.type(d.getByLabelText("Name"), "journal");
    await user.click(d.getByRole("button", { name: "Rename" }));
    await vi.waitFor(() => expect(api.calls("PUT /api/services/1/name")[0]?.json).toEqual({ name: "journal" }));
  });

  it("locks the routing tabs of a Docker-managed service and hides Hosts for a prefix", async () => {
    mockApi(base([svc({ docker: true, host: "", prefix: "/app" })]));
    const { user } = await renderRoute("/services");
    const d = await openEdit(user);
    expect(d.getByText(/Managed by Docker/)).toBeInTheDocument();
    expect(d.queryByLabelText("Name")).toBeNull();
    expect(d.queryByRole("tab", { name: "Hosts" })).toBeNull();
    await user.click(d.getByRole("tab", { name: "Backends" }));
    expect(d.getByLabelText("Backends, one per line")).toBeDisabled();
    expect(d.queryByRole("button", { name: /Save/ })).toBeNull();
    await user.click(d.getByRole("tab", { name: "Rate limit" }));
    expect(d.getByRole("button", { name: /Save/ })).toBeEnabled();
  });

  it("removes a service after confirming", async () => {
    const api = mockApi({ ...base([svc()]), "DELETE /api/services/1": reply(204) });
    const { user } = await renderRoute("/services");
    const d = await openEdit(user);
    await user.click(d.getByRole("button", { name: "Remove this service" }));
    await user.click(within((await screen.findAllByRole("dialog")).at(-1)!).getByRole("button", { name: "Remove" }));
    await vi.waitFor(() => expect(api.calls("DELETE /api/services/1")).toHaveLength(1));
  });

  it("shows viewers the settings read-only", async () => {
    asRole("viewer");
    mockApi(base([svc()]));
    const { user } = await renderRoute("/services");
    expect(screen.queryByRole("heading", { name: "Add Service" })).toBeNull();
    const d = await openEdit(user);
    expect(d.getByRole("heading", { name: "View blog" })).toBeInTheDocument();
    expect(d.getByLabelText("Requests / second")).toBeDisabled();
    expect(d.queryByRole("button", { name: /Save|Rename|Remove/ })).toBeNull();
  });

  it("shows the cache numbers, or why there are none", async () => {
    mockApi({
      ...base([]),
      "GET /api/services/cache-stats": {
        enabled: true,
        stats: { ratio: "75.0%", objects: 12, used: "3 MiB", total: "256 MiB", evicted: 2 },
        services: [{ app: "blog", hits: 3, misses: 1, passes: 0, errors: 4, ratio: "75.0%" }],
      } satisfies CacheStats,
    });
    const r = await renderRoute("/services");
    const c = within((await screen.findByRole("heading", { name: "Cache performance" })).closest("section")!);
    expect(await c.findByText("3 MiB / 256 MiB")).toBeInTheDocument();
    expect(c.getByText(/evicting objects/)).toBeInTheDocument();
    expect(c.getByRole("link", { name: "4" })).toHaveAttribute("href", "/admin/logs?app=blog&status=cache_error&mode=history");
    r.unmount();
    mockApi({ ...base([]), "GET /api/services/cache-stats": { enabled: true, stats_error: "varnishstat: not found", services: [] } });
    await renderRoute("/services");
    expect(await screen.findByText("varnishstat: not found")).toBeInTheDocument();
    expect(screen.getByText("No cached traffic in the last 24 hours.")).toBeInTheDocument();
  });
});
