import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { boot, can } from "@/lib/boot";
import { cn } from "@/lib/utils";
import { Notifications } from "./Notifications";
import { Search } from "./Search";

// The admin frame, the same as the HTMX base.html: dark sidebar, top bar with
// clock, page content, status footer. Areas not moved to this app yet link
// to their HTMX page; set `app` on an item once its route lives here.
export const nav = [
  { path: "/", icon: "hgi-dashboard-square-01", label: "Dashboard", app: true },
  { path: "/logs", icon: "hgi-activity-01", label: "Live Logs", app: true },
  { path: "/services", icon: "hgi-settings-01", label: "Services" },
  { path: "/certificates", icon: "hgi-certificate-01", label: "Certificates", app: true },
  { path: "/ip-rules", icon: "hgi-cancel-circle", label: "IP Rules", app: true },
  { path: "/geo-rules", icon: "hgi-earth", label: "Geo Rules", app: true },
  { path: "/waf-rules", icon: "hgi-security-block", label: "WAF Rules" },
  { path: "/threat-intel", icon: "hgi-database-01", label: "Threat Intel" },
  { path: "/settings", icon: "hgi-user-account", label: "Settings" },
];

const Icon = ({ name, className }: { name: string; className?: string }) => (
  <i aria-hidden className={cn("hgi hgi-stroke hgi-rounded", name, className)} />
);

const navItem =
  "flex min-h-10 items-center gap-3 rounded-md px-3 py-2 font-mono text-[13px] uppercase tracking-[.06em] no-underline transition-colors duration-150 text-side-ink hover:bg-white/[.06] aria-[current=page]:bg-side-active aria-[current=page]:text-side";
const sideButton =
  "flex h-11 w-11 cursor-pointer items-center justify-center rounded-sm border border-side-line text-side-ink transition-colors hover:bg-white/10 lg:h-9 lg:w-9";

export function Shell({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const opener = useRef<HTMLButtonElement>(null);
  const close = () => {
    setOpen(false);
    opener.current?.focus();
  };

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open]);

  return (
    <div className="min-h-dvh bg-canvas text-[14px] text-ink">
      {open && (
        <button type="button" tabIndex={-1} aria-label="Close navigation" onClick={close} className="fixed inset-0 z-40 bg-black/50 lg:hidden" />
      )}
      <Sidebar open={open} onClose={close} />
      <div className="flex min-h-dvh flex-col lg:ml-[264px]">
        <TopBar>
          <button
            ref={opener}
            type="button"
            aria-label="Open navigation"
            aria-controls="primary-nav"
            aria-expanded={open}
            onClick={() => setOpen(true)}
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-sm border border-edge text-ink lg:hidden"
          >
            <Icon name="hgi-menu-01" className="text-xl" />
          </button>
        </TopBar>
        <main id="main-content" className="min-w-0 flex-1 p-4 sm:p-6 lg:p-8">
          {children}
        </main>
        <footer className="flex flex-wrap items-center gap-x-6 gap-y-1 bg-side px-4 py-2 font-mono text-[11px] uppercase tracking-[.08em] text-side-muted sm:px-6 lg:px-8">
          <span>
            Database <span className="text-side-ink">sqlite</span>
          </span>
          <span>
            WAF <span className="text-side-ink">{boot.waf ? "on" : "off"}</span>
          </span>
          <span className="sm:ml-auto">
            Signed in <span className="text-side-ink">{boot.role}</span>
          </span>
        </footer>
      </div>
    </div>
  );
}

function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  // A link on a phone closes the drawer; on a desktop it stays put.
  const navigated = () => window.innerWidth < 1024 && onClose();
  return (
    <aside
      id="primary-nav"
      aria-label="Primary navigation"
      className={cn(
        "fixed top-0 bottom-0 left-0 z-50 flex w-[280px] flex-col border-r border-side-line bg-side text-side-ink transition-transform duration-200 lg:w-[264px] lg:translate-x-0",
        open ? "translate-x-0" : "-translate-x-full",
      )}
    >
      <div className="flex shrink-0 items-center gap-3 border-b border-side-line px-4 py-4">
        <div className="relative h-10 w-10 shrink-0 border border-side-line p-1">
          <img src={`${boot.admin}/static/imgs/logo.svg`} alt="Palisade logo" className="block h-full w-full" />
        </div>
        <div className="min-w-0 font-mono uppercase">
          <span className="block truncate text-[18px] leading-tight tracking-[.04em] text-side-active">Palisade</span>
          <span className="block text-[9px] leading-snug tracking-[.12em] text-side-muted">
            Web application
            <br />
            firewall
          </span>
        </div>
        <button type="button" aria-label="Close navigation" onClick={onClose} className="ml-auto flex h-11 w-11 items-center justify-center rounded-sm text-side-ink hover:bg-white/10 lg:hidden">
          <Icon name="hgi-cancel-01" className="text-lg" />
        </button>
      </div>

      <div className="mx-3 mt-3 shrink-0 border border-side-line px-3 py-2 font-mono text-[11px] uppercase tracking-[.08em]">
        <div className="flex items-center justify-between py-1">
          <span className="text-side-muted">WAF engine</span>
          <span className="flex items-center gap-2 text-side-ink">
            {boot.waf ? "On" : "Off"} <span className={cn("h-2 w-2 rounded-full", boot.waf ? "bg-success" : "bg-danger")} />
          </span>
        </div>
        <div className="flex items-center justify-between border-t border-side-line py-1">
          <span className="text-side-muted">Access</span>
          <span className="text-side-ink">{boot.role}</span>
        </div>
      </div>

      <p className="px-6 pt-4 pb-2 font-mono text-[10px] uppercase tracking-[.14em] text-side-muted">Navigation</p>
      <nav className="flex flex-1 flex-col gap-0.5 overflow-y-auto px-3">
        {nav.map(({ path, icon, label, app }) => {
          const inner = (
            <>
              <Icon name={icon} className="text-base" />
              {label}
            </>
          );
          return app ? (
            <Link key={path} to={path} activeOptions={{ exact: path === "/" }} onClick={navigated} className={navItem}>
              {inner}
            </Link>
          ) : (
            <a key={path} href={boot.admin + path} className={navItem}>
              {inner}
            </a>
          );
        })}
      </nav>

      <div className="flex shrink-0 items-center gap-2 border-t border-side-line px-4 py-4">
        <span className="min-w-0 flex-1" title={boot.email}>
          <span className="block truncate text-[13px] font-medium text-side-active">{boot.email}</span>
          <span className="block font-mono text-[10px] uppercase tracking-[.1em] text-side-muted">Palisade {boot.version}</span>
        </span>
        <ThemeToggle />
        <form action={`${boot.admin}/logout`} method="post" className="contents">
          <input type="hidden" name="_csrf" value={boot.csrf} />
          <button type="submit" title="Sign out" aria-label="Sign out" className={cn(sideButton, "hover:bg-danger/25")}>
            <Icon name="hgi-logout-02" className="text-[14px]" />
          </button>
        </form>
        <Notifications />
      </div>
    </aside>
  );
}

// ThemeToggle shares the HTMX pages' saved theme (static/js/src/theme.js
// applies it before first paint).
function ThemeToggle() {
  const root = document.documentElement;
  const [dark, setDark] = useState(root.dataset.theme === "dark");
  const toggle = () => {
    const next = !dark;
    if (next) root.dataset.theme = "dark";
    else delete root.dataset.theme;
    try {
      localStorage.setItem("cz-theme", next ? "dark" : "light");
    } catch {
      // Storage off (private mode): the theme still applies to this page.
    }
    setDark(next);
  };
  return (
    <button type="button" title="Toggle dark mode" aria-label="Dark mode" aria-pressed={dark} onClick={toggle} className={sideButton}>
      <Icon name={dark ? "hgi-sun-03" : "hgi-moon-02"} className="text-[14px]" />
    </button>
  );
}

// "28 OCT 2026 · 18:24:37", the browser's local time, like the HTMX top bar.
export function clock(now: Date) {
  const pad = (n: number) => String(n).padStart(2, "0");
  const date = `${pad(now.getDate())} ${now.toLocaleString("en", { month: "short" }).toUpperCase()} ${now.getFullYear()}`;
  return [date, ` · ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`] as const;
}

function TopBar({ children }: { children: ReactNode }) {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  const [date, time] = clock(now);
  return (
    <header className="sticky top-0 z-30 flex min-h-14 items-center gap-3 border-b border-edge bg-canvas px-4 sm:px-6 lg:px-8">
      {children}
      <p className="font-mono text-[13px] whitespace-nowrap uppercase tracking-[.06em] text-ink">
        {date}
        <span className="hidden sm:inline">{time}</span>
      </p>
      {!can("admin") && (
        <span
          title="Your role can read every page but not change settings"
          className="inline-flex shrink-0 items-center gap-1.5 rounded-xs border border-edge px-2 py-0.5 font-mono text-[11px] font-medium uppercase tracking-[.06em] whitespace-nowrap text-ink"
        >
          <span className="h-2 w-2 rounded-full bg-slate-400" />
          Read-only
        </span>
      )}
      <div className="ml-auto flex items-center gap-2 py-2 sm:gap-3">
        <Search />
      </div>
    </header>
  );
}
