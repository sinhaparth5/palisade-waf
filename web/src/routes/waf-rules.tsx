import { createFileRoute } from "@tanstack/react-router";
import { WAFRulesPage } from "@/features/waf-rules/WAFRulesPage";

export const Route = createFileRoute("/waf-rules")({ component: WAFRulesPage });
