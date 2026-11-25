import { act, screen, within } from "@testing-library/react";
import { asRole, setBoot } from "@/test/boot";
import { renderRoute } from "@/test/render";
import { clock, nav } from "./Shell";

describe("shell", () => {
  afterEach(() => {
    delete document.documentElement.dataset.theme;
    localStorage.clear();
  });

  it("links moved areas inside the app and the rest to their HTMX page", async () => {
    await renderRoute("/");
    const sidebar = screen.getByRole("navigation");
    const dash = within(sidebar).getByRole("link", { name: "Dashboard" });
    expect(dash).toHaveAttribute("href", "/admin/");
    expect(dash).toHaveAttribute("aria-current", "page");
    expect(within(sidebar).getByRole("link", { name: "Live Logs" })).toHaveAttribute("href", "/admin/logs");
    expect(within(sidebar).getAllByRole("link")).toHaveLength(nav.length);
    expect(document.title).toBe("Palisade · Dashboard");
  });

  it("shows the session: role, email, version, WAF state", async () => {
    setBoot({ waf: false });
    await renderRoute("/");
    expect(screen.getByText("owner@example.com")).toBeInTheDocument();
    expect(screen.getByText("Palisade v0.0.0-test")).toBeInTheDocument();
    expect(screen.getByText(/^Off/)).toBeInTheDocument();
    expect(screen.getByRole("contentinfo")).toHaveTextContent(/WAF off.*Signed in owner/i);
    expect(screen.queryByText("Read-only")).not.toBeInTheDocument();
  });

  it("marks a viewer read-only", async () => {
    asRole("viewer");
    await renderRoute("/");
    expect(screen.getByText("Read-only")).toBeInTheDocument();
  });

  it("signs out with a POST carrying the CSRF token", async () => {
    await renderRoute("/");
    const form = screen.getByRole("button", { name: "Sign out" }).closest("form")!;
    expect(form).toHaveAttribute("action", "/admin/logout");
    expect(form).toHaveAttribute("method", "post");
    expect(form.querySelector<HTMLInputElement>("input[name=_csrf]")?.value).toBe("test-csrf");
  });

  it("toggles and saves the theme the HTMX pages use", async () => {
    const { user } = await renderRoute("/");
    const btn = screen.getByRole("button", { name: "Dark mode" });
    await user.click(btn);
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(localStorage.getItem("cz-theme")).toBe("dark");
    expect(btn).toHaveAttribute("aria-pressed", "true");
    await user.click(btn);
    expect(document.documentElement.dataset.theme).toBeUndefined();
    expect(localStorage.getItem("cz-theme")).toBe("light");
  });

  it("still toggles when storage is off", async () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("denied");
    });
    const { user } = await renderRoute("/");
    await user.click(screen.getByRole("button", { name: "Dark mode" }));
    expect(document.documentElement.dataset.theme).toBe("dark");
  });

  it("opens the mobile drawer and closes it by button, backdrop, Escape and link", async () => {
    vi.stubGlobal("innerWidth", 500);
    const { user } = await renderRoute("/");
    const opener = screen.getByRole("button", { name: "Open navigation" });
    const drawer = screen.getByRole("complementary", { name: "Primary navigation" });
    const closed = () => expect(drawer).toHaveClass("-translate-x-full");

    await user.click(opener);
    expect(opener).toHaveAttribute("aria-expanded", "true");
    expect(drawer).toHaveClass("translate-x-0");
    await user.keyboard("{Escape}");
    closed();
    expect(opener).toHaveFocus();

    await user.click(opener);
    await user.click(within(drawer).getByRole("button", { name: "Close navigation" }));
    closed();

    await user.click(opener);
    await user.click(screen.getAllByRole("button", { name: "Close navigation" }).find((b) => !drawer.contains(b))!);
    closed();

    await user.click(opener);
    await user.click(within(drawer).getByRole("link", { name: "Dashboard" }));
    closed();
  });

  it("keeps the drawer state on a desktop link click", async () => {
    vi.stubGlobal("innerWidth", 1280);
    const { user } = await renderRoute("/");
    await user.click(screen.getByRole("button", { name: "Open navigation" }));
    await user.click(screen.getByRole("link", { name: "Dashboard" }));
    expect(screen.getByRole("complementary")).toHaveClass("translate-x-0");
  });

  it("ticks the clock every second", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    vi.setSystemTime(new Date(2026, 9, 28, 18, 24, 37));
    try {
      await renderRoute("/");
      expect(screen.getByText("28 OCT 2026")).toBeInTheDocument();
      act(() => vi.advanceTimersByTime(1000));
      expect(screen.getByText("· 18:24:38", { exact: false })).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it("formats the clock like the HTMX top bar", () => {
    expect(clock(new Date(2026, 0, 5, 7, 8, 9))).toEqual(["05 JAN 2026", " · 07:08:09"]);
  });
});
