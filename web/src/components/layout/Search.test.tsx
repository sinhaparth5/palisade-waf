import { fireEvent, screen, waitFor } from "@testing-library/react";
import { mockApi, reply } from "@/test/api-mock";
import { renderWithProviders } from "@/test/render";
import { Search } from "./Search";

const groups = [
  { label: "Services", icon: "hgi-settings-01", hits: [{ title: "shop", detail: "shop.example.com", url: "/admin/services" }] },
  { label: "Pages", icon: "hgi-file-01", hits: [{ title: "Trusted IPs", detail: "Settings", url: "/admin/settings#find=Trusted%20IPs" }] },
];

describe("search", () => {
  it("opens with Ctrl+K, queries the server and goes to a hit", async () => {
    const api = mockApi({ "GET /search": groups });
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign });
    const { user } = renderWithProviders(<Search />);

    await user.keyboard("{Control>}k{/Control}");
    await user.type(screen.getByRole("combobox"), "shop");
    expect(await screen.findByText("shop.example.com")).toBeInTheDocument();
    expect(screen.getByText("Services")).toBeInTheDocument();
    expect(api.calls("GET /search").at(-1)!.path).toBe("/search?q=shop");
    expect(api.calls("GET /search").at(-1)!.headers.get("Accept")).toBe("application/json");

    await user.keyboard("{Enter}");
    expect(assign).toHaveBeenCalledWith("/admin/services");
    await user.click(screen.getByText("Trusted IPs"));
    expect(assign).toHaveBeenLastCalledWith("/admin/settings#find=Trusted%20IPs");
  });

  it("opens with / outside a text field, and from the button", async () => {
    mockApi({});
    const { user } = renderWithProviders(
      <>
        <input aria-label="other" />
        <Search />
      </>,
    );
    await user.type(screen.getByLabelText("other"), "/");
    const editor = document.body.appendChild(document.createElement("div"));
    Object.defineProperty(editor, "isContentEditable", { value: true }); // jsdom lacks it
    fireEvent.keyDown(editor, { key: "/" });
    editor.remove();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    fireEvent.keyDown(document.body, { key: "/" });
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    await user.keyboard("{Escape}");
    fireEvent.keyDown(document.body, { key: "k", metaKey: true }); // Cmd+K on a Mac
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    await user.keyboard("{Escape}");
    await user.click(screen.getByRole("button", { name: "Search" }));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
  });

  it("says when nothing matches, and asks nothing for blank input", async () => {
    const api = mockApi({ "GET /search": [] });
    const { user } = renderWithProviders(<Search />);
    await user.click(screen.getByRole("button", { name: "Search" }));
    await user.type(screen.getByRole("combobox"), "   ");
    await new Promise((r) => setTimeout(r, 200));
    expect(api.calls()).toHaveLength(0);
    await user.type(screen.getByRole("combobox"), "zzz");
    expect(await screen.findByText("No results for “zzz”.")).toBeInTheDocument();
  });

  it("shows a failed search as an error, not as no results", async () => {
    mockApi({ "GET /search": reply(500, { error: "db" }) });
    const { user } = renderWithProviders(<Search />);
    await user.click(screen.getByRole("button", { name: "Search" }));
    await user.type(screen.getByRole("combobox"), "x");
    expect(await screen.findByRole("alert")).toHaveTextContent("Search failed");
    await waitFor(() => expect(screen.queryByText(/No results/)).not.toBeInTheDocument());
  });
});
