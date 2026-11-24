import { createFileRoute } from "@tanstack/react-router";
import { GeoRulesPage } from "@/features/rules/GeoRulesPage";

export const Route = createFileRoute("/geo-rules")({ component: GeoRulesPage });
