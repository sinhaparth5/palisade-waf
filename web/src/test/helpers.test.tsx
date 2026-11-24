// Tests for the test helpers themselves, so a broken helper can't make every
// other test pass for the wrong reason.
import { useQuery } from "@tanstack/react-query";
import { screen } from "@testing-library/react";
import { api } from "@/lib/api";
import { boot, can } from "@/lib/boot";
import { mockApi, pending } from "./api-mock";
import { asRole } from "./boot";
import { renderRoute, renderWithProviders } from "./render";

describe("mockApi", () => {
  it("fails on a route the test didn't declare", async () => {
    mockApi({});
    await expect(api("api/v1/unknown")).rejects.toThrow("mockApi: unexpected GET /api/v1/unknown");
  });

  it("matches with or without the query string", async () => {
    const mock = mockApi({ "GET /api/v1/logs": [] });
    await api("api/v1/logs?limit=5");
    expect(mock.calls("GET /api/v1/logs")).toHaveLength(1);
    expect(mock.calls()[0]!.path).toBe("/api/v1/logs?limit=5");
  });

  it("answers the same Response more than once", async () => {
    mockApi({ "GET /api/v1/x": { a: 1 } });
    await api("api/v1/x");
    await expect(api("api/v1/x")).resolves.toEqual({ a: 1 });
  });
});

describe("boot", () => {
  it("is reset between tests (1/2)", () => {
    asRole("viewer");
    expect(can("admin")).toBe(false);
  });
  it("is reset between tests (2/2)", () => {
    expect(boot.role).toBe("owner");
    expect(can("owner")).toBe(true);
  });
});

describe("renderWithProviders", () => {
  function Name() {
    const q = useQuery({ queryKey: ["name"], queryFn: () => api<{ name: string }>("api/v1/name") });
    return <p>{q.isPending ? "loading" : q.isError ? "failed" : q.data.name}</p>;
  }

  it("provides a query client", async () => {
    mockApi({ "GET /api/v1/name": { name: "palisade" } });
    renderWithProviders(<Name />);
    expect(await screen.findByText("palisade")).toBeInTheDocument();
  });

  it("shows loading with a pending request", () => {
    mockApi({ "GET /api/v1/name": pending });
    renderWithProviders(<Name />);
    expect(screen.getByText("loading")).toBeInTheDocument();
  });
});

describe("renderRoute", () => {
  it("renders a route under the admin base path", async () => {
    const { router } = await renderRoute("/");
    expect(router.state.location.pathname).toBe("/"); // relative to the base path
    expect(router.history.location.pathname).toBe("/admin/app/");
    expect(await screen.findByRole("heading", { level: 1, name: "Dashboard" })).toBeInTheDocument();
  });
});
