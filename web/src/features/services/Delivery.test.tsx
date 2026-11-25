import { within } from "@testing-library/react";
import { mockApi, reply } from "@/test/api-mock";
import { asRole } from "@/test/boot";
import { renderRoute } from "@/test/render";
import { base, openEdit, page, svc } from "./fixtures";

type Scope = ReturnType<typeof within>;
const form = (d: Scope, title: string) => within(d.getByRole("heading", { name: title }).closest("form")!);

describe("services: cache and tls", () => {
  it("saves the cache tab and purges, with the server's errors", async () => {
    let fail = true;
    const api = mockApi({
      ...base([svc()]),
      "PUT /api/services/1/cache": () => (fail ? reply(400, { error: "invalid", message: "x", fields: { rules: `line 1: want "cache" or "bypass"` } }) : reply(204)),
      "POST /api/services/1/purge": reply(502, { error: "purge_failed", message: "Varnish didn't take the purge: connection refused" }),
    });
    const { user } = await renderRoute("/services");
    const d = await openEdit(user);
    await user.click(d.getByRole("tab", { name: "Cache" }));
    expect(d.getByText(/Varnish integration is off/)).toBeInTheDocument();
    await user.click(d.getByLabelText("Cache this service"));
    await user.click(d.getByLabelText("Cache by session"));
    await user.type(d.getByLabelText("Session cookie name"), "sid");
    await user.type(d.getByLabelText("TTL ceiling (s)"), "600");
    await user.type(d.getByLabelText("Path rules"), "keep /assets/");
    await user.click(d.getByLabelText("Compress responses"));
    await user.click(d.getByRole("button", { name: /Save/ }));
    expect(await d.findByText(`line 1: want "cache" or "bypass"`)).toBeInTheDocument();
    fail = false;
    await user.click(d.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/services/1/cache")).toHaveLength(2));
    expect(api.calls("PUT /api/services/1/cache")[1]!.json).toEqual({
      enabled: true,
      by_session: true,
      session_cookie: "sid",
      ttl_floor: 0,
      ttl_ceiling: 600,
      grace: 0,
      keep: 0,
      rules: "keep /assets/",
      compress: true,
    });

    await user.type(d.getByLabelText("Path prefix (empty = everything)"), "/blog/");
    await user.click(d.getByRole("button", { name: "Purge cached content" }));
    expect(await d.findByRole("alert")).toHaveTextContent("connection refused");
    expect(api.calls("POST /api/services/1/purge")[0]!.json).toEqual({ path: "/blog/" });
  });

  it("picks a pool certificate, asks for the ACME email, and saves HTTP/3 and mTLS", async () => {
    const api = mockApi({
      ...base([svc()]),
      "GET /api/services": { ...page([svc()]), certificates: [{ id: 4, name: "shop", domains: "blog.example.com" }] },
      "PUT /api/services/1/tls": reply(204),
      "PUT /api/services/1/http3": reply(204),
      "PUT /api/services/1/mtls": reply(400, { error: "invalid", message: "x", fields: { ca: "Paste the CA certificate(s) that issue your client certificates." } }),
    });
    const { user } = await renderRoute("/services");
    const d = await openEdit(user);
    await user.click(d.getByRole("tab", { name: "TLS" }));
    const cert = form(d, "Certificate");
    expect(cert.getByText(/server's default/)).toBeInTheDocument();
    await user.click(cert.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/services/1/tls")[0]?.json).toEqual({ mode: "pool", cert_id: 4 }));

    await user.click(cert.getByLabelText("Let's Encrypt"));
    await user.type(cert.getByLabelText("Let's Encrypt email"), "ops@example.com");
    await user.click(cert.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/services/1/tls")[1]?.json).toEqual({ mode: "auto", acme_email: "ops@example.com" }));

    const h3 = form(d, "HTTP/3 (QUIC)");
    expect(h3.getByText(/listener is off/)).toBeInTheDocument();
    await user.click(h3.getByLabelText("Offer HTTP/3"));
    await user.click(h3.getByRole("button", { name: /Save/ }));
    await vi.waitFor(() => expect(api.calls("PUT /api/services/1/http3")[0]?.json).toEqual({ enabled: true }));

    const mtls = form(d, "Client certificates (mTLS)");
    await user.click(mtls.getByLabelText(/Required/));
    await user.type(mtls.getByLabelText("Allowlist (optional, one per line)"), "svc-a\n\nsvc-b");
    await user.click(mtls.getByRole("button", { name: /Save/ }));
    expect(await mtls.findByText("Paste the CA certificate(s) that issue your client certificates.")).toBeInTheDocument();
    expect(api.calls("PUT /api/services/1/mtls")[0]!.json).toEqual({ mode: "required", ca: "", allow: ["svc-a", "svc-b"] });
  });

  it("hides TLS for a prefix service and shows viewers the tabs read-only", async () => {
    asRole("viewer");
    mockApi(base([svc({ tls: { ...svc().tls, mode: "custom", expires_at: "2027-01-01T00:00:00Z" } }), svc({ id: 2, name: "api", host: "", prefix: "/api" })]));
    const { user } = await renderRoute("/services");
    let d = await openEdit(user);
    await user.click(d.getByRole("tab", { name: "TLS" }));
    expect(d.getByText(/Serving an uploaded certificate/)).toBeInTheDocument();
    expect(d.getByLabelText("Offer HTTP/3")).toBeDisabled();
    await user.click(d.getByRole("tab", { name: "Cache" }));
    expect(d.getByLabelText("Cache this service")).toBeDisabled();
    expect(d.queryByRole("button", { name: /Save|Purge/ })).toBeNull();
    await user.keyboard("{Escape}");
    d = await openEdit(user, "api");
    expect(d.queryByRole("tab", { name: "TLS" })).toBeNull();
  });
});
