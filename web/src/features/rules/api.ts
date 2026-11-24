import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

// IP and Geo Rules (issue #351). Every write answers 2xx with no data the
// page needs, so a write just invalidates its list.

export type RuleType = "block" | "allow";

export type IPRule = {
  id: number;
  app_name: string;
  ip: string;
  rule_type: RuleType;
  note: string;
  auto: boolean;
  score: number; // 0 = no recorded threat score
  created_at: string;
};

export type IPRulesPage = {
  rules: IPRule[];
  page: number;
  total_pages: number;
  total: number;
  block_count: number;
  allow_count: number;
};

// Shared with /api/v1, which has no json tags on this type.
export type GeoRule = { ID: number; AppName: string; CountryCode: string; RuleType: RuleType; CreatedAt: string };

export type Autoban = { enabled: boolean; threshold: number; window: number; ban_hours: number; bad_status: boolean; bad_codes: string; bad_points: number };
export type Adaptive = { enabled: boolean; high_threshold: number; low_threshold: number; high_scale: number; low_scale: number; force_challenge: number };
export type IPSettings = { autoban: Autoban; adaptive: Adaptive; honeypot_paths: string[] };

export const useIPRules = (page: number) =>
  useQuery({ queryKey: ["ip-rules", page], queryFn: () => api<IPRulesPage>(`/api/ip-rules?page=${page}`), placeholderData: keepPreviousData });

export const useIPSettings = () => useQuery({ queryKey: ["ip-rules-settings"], queryFn: () => api<IPSettings>("/api/ip-rules/settings") });

export const useGeoRules = () => useQuery({ queryKey: ["geo-rules"], queryFn: () => api<GeoRule[]>("/api/geo-rules") });

const post = (path: string, body: unknown, method = "POST") => api<{ added?: number }>(path, { method, body: JSON.stringify(body) });

// useWrite sends body to path and refreshes the list under key.
export function useWrite<T>(key: string, path: string, method = "POST") {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: T) => post(path, body, method),
    onSettled: () => qc.invalidateQueries({ queryKey: [key] }),
  });
}

// useRemove deletes rules by id. The geo list drops them at once (it is one
// unpaged list) and puts them back if the server refuses; the paged IP list
// waits for the server, since a page refills from the next one.
export function useRemove(key: "ip-rules" | "geo-rules") {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (ids: number[]) => post(`/api/${key}/remove`, { ids }),
    onMutate: async (ids) => {
      if (key !== "geo-rules") return;
      await qc.cancelQueries({ queryKey: [key] });
      const before = qc.getQueryData<GeoRule[]>([key]);
      qc.setQueryData<GeoRule[]>([key], (rules) => rules?.filter((r) => !ids.includes(r.ID)));
      return { before };
    },
    onError: (_e, _ids, ctx) => ctx?.before && qc.setQueryData([key], ctx.before),
    onSettled: () => qc.invalidateQueries({ queryKey: [key] }),
  });
}
