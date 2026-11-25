import { within } from "@testing-library/react";
import { mockApi, pending, reply } from "@/test/api-mock";
import { asRole } from "@/test/boot";
import { renderRoute } from "@/test/render";
import { base, openEdit, svc } from "./fixtures";

type Scope = ReturnType<typeof within>;
const form = (d: Scope, title: string) => within(d.getByRole("heading", { name: title }).closest("form")!);
const spec = "openapi: 3.0.3\npaths:\n  /users: {}";

describe("services: request and response checks", () => {
  it("saves the schema, OpenAPI spec, JWT and request policy", async () => {
    let fail = true;
    const api = mockApi({
      ...base([svc()]),
      "GET /api/services/1/openapi": { mode: "off", spec },
      "PUT /api/services/1/schema": () => (fail ? reply(400, { error: "invalid", message: "x", fields: { schema: "Not a valid JSON Schema: unexpected EOF" } }) : reply(204)),
      "PUT /api/services/1/openapi": reply(204),
      "PUT /api/services/1/jwt": reply(400, { error: "invalid", message: "set a JWKS URL or a public key" }),
      "PUT /api/services/1/policy": reply(204),
    });
    const { user } = await renderRoute("/services");
    const d = await openEdit(user);
    await user.click(d.getByRole("tab", { name: "Requests" }));

    const sc = form(d, "JSON Schema");
    await user.type(sc.getByLabelText("JSON Schema"), "{{");
    await user.click(sc.getByLabelText(/Enforce/));
    await user.click(sc.getByRole("button", { name: /Save/ }));
    expect(await sc.findByText("Not a valid JSON Schema: unexpected EOF")).toBeInTheDocument();
    fail = false;
    await user.click(sc.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/services/1/schema")).toHaveLength(2));
    expect(api.calls("PUT /api/services/1/schema")[1]!.json).toEqual({ mode: "enforce", schema: "{" });

    const oa = form(d, "OpenAPI spec");
    expect(await oa.findByDisplayValue(/openapi: 3.0.3/)).toBeInTheDocument();
    await user.selectOptions(oa.getByLabelText("Mode"), "log");
    await user.click(oa.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/services/1/openapi")[0]?.json).toEqual({ mode: "log", spec }));

    const jwt = form(d, "JWT verification");
    await user.type(jwt.getByLabelText("Allowed algorithms (empty = every asymmetric one)"), "RS256, ES256");
    await user.selectOptions(jwt.getByLabelText("Mode"), "enforce");
    await user.click(jwt.getByRole("button", { name: /Save/ }));
    expect(await jwt.findByRole("alert")).toHaveTextContent("set a JWKS URL or a public key");
    expect(api.calls("PUT /api/services/1/jwt")[0]!.json).toMatchObject({ mode: "enforce", algorithms: ["RS256", "ES256"], prefixes: [] });

    const pol = form(d, "Request policy");
    await user.selectOptions(pol.getByLabelText("Preset"), "JSON API");
    expect(pol.getByLabelText("Allowed methods")).toHaveValue("GET POST PUT PATCH DELETE OPTIONS");
    await user.selectOptions(pol.getByLabelText("Mode"), "enforce");
    await user.click(pol.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() =>
      expect(api.calls("PUT /api/services/1/policy")[0]?.json).toEqual({
        mode: "enforce",
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        content_types: ["application/json"],
        max_body_kib: 1024,
      }),
    );
  });

  it("saves the MCP guard, and says when the spec can't be read", async () => {
    const api = mockApi({ ...base([svc()]), "GET /api/services/1/openapi": reply(500, {}), "PUT /api/services/1/mcp": reply(204) });
    const { user } = await renderRoute("/services");
    const d = await openEdit(user);
    await user.click(d.getByRole("tab", { name: "Requests" }));
    expect(await d.findByText("Couldn't load the OpenAPI spec.")).toHaveAttribute("role", "alert");
    const mcp = form(d, "MCP endpoint guard");
    await user.type(mcp.getByLabelText("Endpoint path (after the service prefix)"), "/mcp");
    await user.type(mcp.getByLabelText("Allowed methods, one per line"), "initialize\n\ntools/call");
    await user.selectOptions(mcp.getByLabelText("Mode"), "log");
    await user.click(mcp.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/services/1/mcp")[0]?.json).toEqual({ mode: "log", path: "/mcp", origins: [], methods: ["initialize", "tools/call"], tools: [] }));
  });

  it("approves script sources, warns about new ones and returns to report-only", async () => {
    const api = mockApi({
      ...base([
        svc({
          csp: {
            mode: "enforce",
            policy: "script-src 'self'",
            scripts: [
              { origin: "https://cdn.example.com", page: "/", first_seen: "2026-11-20T10:00:00Z" },
              { origin: "inline", page: "/checkout", first_seen: "2026-11-24T10:00:00Z" },
            ],
            approved: ["https://cdn.example.com"],
            recent: true,
          },
        }),
      ]),
      "PUT /api/services/1/csp": reply(204),
      "PUT /api/services/1/cookies": reply(204),
      "PUT /api/services/1/responses": reply(204),
    });
    const { user } = await renderRoute("/services");
    const d = await openEdit(user);
    await user.click(d.getByRole("tab", { name: "Responses" }));
    const csp = form(d, "Script inventory (CSP)");
    expect(csp.getByRole("alert")).toHaveTextContent(/last 7 days/);
    await user.selectOptions(csp.getByLabelText("Mode"), "report");
    expect(csp.queryByRole("alert")).toBeNull();
    await user.selectOptions(csp.getByLabelText("Mode"), "enforce");
    await user.click(csp.getByLabelText(/inline/));
    await user.click(csp.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() =>
      expect(api.calls("PUT /api/services/1/csp")[0]?.json).toEqual({ mode: "enforce", policy: "script-src 'self'", approved: ["https://cdn.example.com", "inline"] }),
    );
    await user.click(csp.getByRole("button", { name: "Return to report-only" }));
    await vi.waitFor(() => expect(api.calls("PUT /api/services/1/csp")[1]?.json).toMatchObject({ mode: "report" }));

    const ck = form(d, "Harden backend cookies");
    await user.type(ck.getByLabelText("Leave these cookies alone"), "csrftoken, theme");
    await user.selectOptions(ck.getByLabelText("Cookie hardening"), "on");
    await user.click(ck.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/services/1/cookies")[0]?.json).toEqual({ enabled: true, exempt: ["csrftoken", "theme"] }));

    const rs = form(d, "Inspect responses");
    await user.selectOptions(rs.getByLabelText("Mode"), "block");
    await user.click(rs.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/services/1/responses")[0]?.json).toEqual({ mode: "block" }));
  });

  it("shows viewers the checks read-only", async () => {
    asRole("viewer");
    mockApi({ ...base([svc({ csp: { mode: "enforce", policy: "", approved: [] } })]), "GET /api/services/1/openapi": pending });
    const { user } = await renderRoute("/services");
    const d = await openEdit(user);
    await user.click(d.getByRole("tab", { name: "Requests" }));
    expect(form(d, "JSON Schema").getByLabelText("JSON Schema")).toBeDisabled();
    expect(d.getByText("Loading…")).toBeInTheDocument();
    await user.click(d.getByRole("tab", { name: "Responses" }));
    expect(form(d, "Inspect responses").getByLabelText("Mode")).toBeDisabled();
    expect(d.queryByRole("button", { name: /Save|Return to report-only/ })).toBeNull();
  });
});
