import { screen, within } from "@testing-library/react";
import { mockApi, pending, reply } from "@/test/api-mock";
import { asRole } from "@/test/boot";
import { renderRoute } from "@/test/render";
import { expiry, type CertsPage } from "./api";

const inDays = (n: number) => new Date(Date.now() + n * 86_400_000 + 3_600_000).toISOString();

const page: CertsPage = {
  certs: [
    { id: 1, name: "shop-origin", domains: ["shop.example", "*.shop.example"], expires_at: inDays(200), created_at: "", services: ["shop", "api"] },
    { id: 2, name: "old", domains: ["old.example"], expires_at: inDays(-3), created_at: "", services: [] },
  ],
  services: [
    { name: "shop", host: "shop.example", mode: "pool", cert: "shop-origin", expires_at: inDays(200) },
    { name: "blog", host: "blog.example", mode: "auto" },
    { name: "own", host: "own.example", mode: "custom", expires_at: inDays(10) },
    { name: "plain", host: "plain.example", mode: "none" },
  ],
  acme_email: false,
};

const base = { "GET /api/notifications": { unread: 0, blocks: [] }, "GET /api/certificates": page };

describe("certificates page", () => {
  it("lists the pool with domains, expiry and who serves each cert", async () => {
    mockApi(base);
    await renderRoute("/certificates");
    expect(await screen.findByText("shop-origin")).toBeInTheDocument();
    expect(within(screen.getByRole("list", { name: "Domains on shop-origin" })).getAllByRole("listitem")).toHaveLength(2);
    expect(screen.getByText("Serving shop, api")).toBeInTheDocument();
    expect(screen.getByText("Not assigned to a service")).toBeInTheDocument();
    expect(screen.getByText("Expired")).toBeInTheDocument();
    expect(screen.getByText("2 certs")).toBeInTheDocument();
    expect(screen.getByText("1 needs attention")).toBeInTheDocument();
    expect(screen.getByText("3 of 4 host services on TLS")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Every TLS identity in one place." })).toBeInTheDocument();
  });

  it("shows each service's TLS and asks for a Let's Encrypt email when one is missing", async () => {
    mockApi(base);
    await renderRoute("/certificates");
    expect(await screen.findByText("Pool · shop-origin")).toBeInTheDocument();
    expect(screen.getByText("Let's Encrypt")).toBeInTheDocument();
    expect(screen.getByText("Uploaded")).toBeInTheDocument();
    expect(screen.getByText("No TLS")).toBeInTheDocument();
    expect(screen.getByText("10 days left")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("contact email");
    expect(within(screen.getByRole("main")).getByRole("link", { name: "Services" })).toHaveAttribute("href", "/admin/app/services");
  });

  it("shows loading, empty and error states", async () => {
    mockApi({ ...base, "GET /api/certificates": pending });
    const r = await renderRoute("/certificates");
    expect(screen.getAllByText("Loading…")).toHaveLength(2);
    r.unmount();

    mockApi({ ...base, "GET /api/certificates": { certs: [], services: [], acme_email: true } });
    const r2 = await renderRoute("/certificates");
    expect(await screen.findByText("No certificates saved yet")).toBeInTheDocument();
    expect(screen.getByText(/No host-matched services yet/)).toBeInTheDocument();
    expect(screen.getByText("0 certs")).toBeInTheDocument();
    expect(screen.queryByRole("status")).toBeNull();
    r2.unmount();

    mockApi({ ...base, "GET /api/certificates": reply(500, {}) });
    await renderRoute("/certificates");
    expect(await screen.findAllByRole("alert")).toHaveLength(2);
    expect(screen.queryByText("No certificates saved yet")).toBeNull();
  });

  it("saves a pair from files, naming it after the certificate file, and shows field errors", async () => {
    let fail = true;
    const api = mockApi({
      ...base,
      "POST /api/certificates": () => (fail ? reply(400, { error: "invalid", message: "x", fields: { key_pem: "This key doesn't match the certificate." } }) : reply(201, { ...page.certs[1], name: "origin" })),
    });
    const { user } = await renderRoute("/certificates");
    await user.upload(await screen.findByLabelText("upload a .pem / .crt"), new File(["CERT"], "origin.crt"));
    await user.upload(screen.getByLabelText("upload a .pem / .key"), new File(["KEY"], "origin.key"));
    await vi.waitFor(() => expect(screen.getByLabelText("Private key (PEM)")).toHaveValue("KEY"));
    expect(screen.getByLabelText("Name")).toHaveValue("origin");
    expect(screen.getByLabelText("Certificate (PEM)")).toHaveValue("CERT");

    await user.click(screen.getByRole("button", { name: "Save certificate" }));
    expect(await screen.findByText("This key doesn't match the certificate.")).toBeInTheDocument();
    expect(screen.getByLabelText("Private key (PEM)")).toHaveAttribute("aria-invalid", "true");
    expect(api.calls("POST /api/certificates")[0]!.json).toEqual({ name: "origin", cert_pem: "CERT", key_pem: "KEY" });

    fail = false;
    await user.click(screen.getByRole("button", { name: "Save certificate" }));
    await vi.waitFor(() => expect(screen.getByLabelText("Name")).toHaveValue(""));
    expect(api.calls("GET /api/certificates").length).toBeGreaterThan(1);
  });

  it("keeps a typed name, takes a pasted PEM and shows an error no field carries", async () => {
    const api = mockApi({ ...base, "POST /api/certificates": reply(500, {}) });
    const { user } = await renderRoute("/certificates");
    await user.type(await screen.findByLabelText("Name"), "mine");
    await user.upload(screen.getByLabelText("upload a .pem / .crt"), new File(["CERT"], "cert.pem"));
    await vi.waitFor(() => expect(screen.getByLabelText("Certificate (PEM)")).toHaveValue("CERT"));
    await user.type(screen.getByLabelText("Private key (PEM)"), "KEY");
    await user.click(screen.getByRole("button", { name: "Save certificate" }));
    expect(await screen.findByText("Couldn't save. Try again.")).toBeInTheDocument();
    expect(api.calls("POST /api/certificates")[0]!.json).toEqual({ name: "mine", cert_pem: "CERT", key_pem: "KEY" });
  });

  it("deletes after a confirmation that names the services losing TLS", async () => {
    let answer: unknown = reply(500, { error: "internal", message: "Disk is full." });
    const api = mockApi({ ...base, "DELETE /api/certificates/1": () => answer, "DELETE /api/certificates/2": reply(204) });
    const { user } = await renderRoute("/certificates");
    await user.click(await screen.findByRole("button", { name: "Delete shop-origin" }));
    const dialog = await screen.findByRole("dialog", { name: "Delete shop-origin?" });
    expect(dialog).toHaveTextContent("shop, api will lose TLS");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await vi.waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await user.click(screen.getByRole("button", { name: "Delete shop-origin" }));
    await screen.findByRole("dialog");
    await user.keyboard("{Escape}");
    await vi.waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(api.calls("DELETE /api/certificates/1")).toHaveLength(0);

    await user.click(screen.getByRole("button", { name: "Delete shop-origin" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Disk is full.");

    answer = reply(204);
    await user.click(screen.getByRole("button", { name: "Delete old" }));
    expect(await screen.findByRole("dialog")).toHaveTextContent("No service uses it");
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Delete" }));
    await vi.waitFor(() => expect(api.calls("DELETE /api/certificates/2")).toHaveLength(1));
    expect(api.calls("DELETE /api/certificates/2")[0]!.headers.get("X-CSRF-Token")).toBeTruthy();
  });

  it("is read-only for viewers", async () => {
    asRole("viewer");
    mockApi(base);
    await renderRoute("/certificates");
    expect(await screen.findByText("shop-origin")).toBeInTheDocument();
    expect(screen.queryByText("Add Certificate")).toBeNull();
    expect(screen.queryByRole("button", { name: /Delete/ })).toBeNull();
  });
});

describe("expiry", () => {
  const now = Date.parse("2026-11-25T00:00:00Z");
  it.each([
    ["", "Expiry unknown"],
    ["2026-11-24T00:00:00Z", "Expired"],
    ["2026-11-26T12:00:00Z", "1 day left"],
    ["2026-12-20T00:00:00Z", "25 days left"],
    ["2027-11-25T00:00:00Z", "365 days left"],
  ])("%s → %s", (at, label) => expect(expiry(at, now).label).toBe(label));
});
