import { createFileRoute } from "@tanstack/react-router";
import { LogsPage } from "@/features/logs/LogsPage";
import type { LogSearch } from "@/features/logs/api";

const text = (v: unknown) => (typeof v === "string" && v ? v : undefined);

export const Route = createFileRoute("/logs")({
  // Same parameters as the HTMX page, so its links and bookmarks still work.
  validateSearch: (s: Record<string, unknown>): LogSearch => {
    const page = Number(s.page);
    return {
      from: text(s.from),
      to: text(s.to),
      app: text(s.app),
      status: text(s.status),
      page: Number.isInteger(page) && page > 1 ? page : undefined,
      mode: s.mode === "history" ? "history" : undefined,
    };
  },
  component: function Logs() {
    return <LogsPage search={Route.useSearch()} />;
  },
});
