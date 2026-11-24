import { createFileRoute } from "@tanstack/react-router";
import { IPRulesPage } from "@/features/rules/IPRulesPage";

export const Route = createFileRoute("/ip-rules")({
  // ?page= as the HTMX page had it.
  validateSearch: (s: Record<string, unknown>): { page?: number } => {
    const page = Number(s.page);
    return { page: Number.isInteger(page) && page > 1 ? page : undefined };
  },
  component: function IPRules() {
    return <IPRulesPage page={Route.useSearch().page ?? 1} />;
  },
});
