import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { LogRow } from "@/lib/format";

// GET {admin}/api/dashboard (internal/ui/dashboard.go): the whole page in one request.
export type CountryCount = { code: string; name?: string; count: number };

export type Dashboard = {
  requests_today: number;
  blocked_today: number;
  blocked_all: number;
  block_rate: number;
  challenged: number;
  passed: number;
  visitors: number;
  glance: { label: string; value: string; trend: string }[];
  traffic: { labels: string[]; allowed: number[]; blocked: number[] };
  countries: CountryCount[];
  threats: CountryCount[];
  enforcement: { label: string; icon: string; count: number }[];
  services: { name: string; route: string; tls: string; healthy: boolean; known: boolean; cache: boolean }[];
  recent: LogRow[];
  blocked: LogRow[];
  changes: { ID: number; TS: string; Actor: string; Action: string }[];
};

export const useDashboard = () => useQuery({ queryKey: ["dashboard"], queryFn: () => api<Dashboard>("/api/dashboard") });
