import { screen } from "@testing-library/react";
import { renderWithProviders, renderRoute } from "@/test/render";
import { ErrorScreen } from "./Fallback";

describe("fallback screens", () => {
  it("shows the Palisade 404 for an unknown path", async () => {
    await renderRoute("/no-such-page");
    expect(await screen.findByRole("heading", { name: /page not found/i })).toBeInTheDocument();
  });

  it("keeps the error message out of the page", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    renderWithProviders(<ErrorScreen error={new Error("db at /var/lib/secret")} />);
    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(screen.queryByText(/var\/lib\/secret/)).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /back to dashboard/i })).toHaveAttribute("href", "/admin/app/");
  });
});
