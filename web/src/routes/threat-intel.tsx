import { createFileRoute } from "@tanstack/react-router";
import { ThreatIntelPage } from "@/features/threat-intel/ThreatIntelPage";

export const Route = createFileRoute("/threat-intel")({ component: ThreatIntelPage });
