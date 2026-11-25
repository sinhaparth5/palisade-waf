import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

// GET {admin}/api/waf-rules (internal/ui/wafrules.go). Times are RFC 3339.

export type VPatch = { cve: string; product: string; reference: string; added: string; rule_id: number; hits: number; global_off: boolean; off_for: string[] };

// An exception switches a rule off globally (service "") or for one
// service; id is the row in its own table, so delete goes by both.
export type Exception = { id: number; rule_id: number; service: string; reason: string; created_at: string };
export type Suggestion = { rule_id: number; service: string; false_positives: number; last_marked: string };
export type TopRule = { rule_id: number; hits: number; last_seen: string; disabled: boolean };
export type CustomRule = { id: number; service: string; rule: string; note: string; enabled: boolean; created_at: string };
export type Feedback = { threshold: number; window_days: number };

export type WAFPage = {
  vpatches: VPatch[];
  suggestions: Suggestion[];
  feedback: Feedback;
  top_rules: TopRule[];
  custom: CustomRule[];
  exceptions: Exception[];
  services: string[];
  waf_enabled: boolean;
};

export type NewException = { rule_id: number; service: string; reason: string };
export type CustomDraft = { id?: number; rule: string; service: string; note: string };
export type Verdict = { blocked: boolean; rule_id: number };
export type DryRun = { replayed: number; hits: { id: number; app: string; method: string; host: string; target: string; before: Verdict; after: Verdict }[] };

const key = ["waf-rules"];
const json = (method: string, body: unknown) => ({ method, body: JSON.stringify(body) });

export const useWAF = () => useQuery({ queryKey: key, queryFn: () => api<WAFPage>("/api/waf-rules") });

function useWrite<T>(fn: (v: T) => Promise<unknown>) {
  const qc = useQueryClient();
  return useMutation({ mutationFn: fn, onSettled: () => qc.invalidateQueries({ queryKey: key }) });
}

export const useAddException = () => useWrite((e: NewException) => api<null>("/api/waf-rules/exceptions", json("POST", e)));
export const useRemoveException = () => useWrite((e: Exception) => api<null>(`/api/waf-rules/exceptions/${e.service ? "services" : "global"}/${e.id}`, { method: "DELETE" }));
export const useSetFeedback = () => useWrite((f: Feedback) => api<null>("/api/waf-rules/feedback", json("PUT", f)));
export const useSaveCustom = () =>
  useWrite(({ id, ...r }: CustomDraft) => (id ? api<null>(`/api/waf-rules/custom/${id}`, json("PUT", r)) : api<null>("/api/waf-rules/custom", json("POST", r))));
export const useDeleteCustom = () => useWrite((id: number) => api<null>(`/api/waf-rules/custom/${id}`, { method: "DELETE" }));
export const useDryRun = () => useMutation({ mutationFn: (r: { rule: string; limit: number }) => api<DryRun>("/api/waf-rules/dry-run", json("POST", r)) });

// Turning a custom rule on or off shows at once; a failure puts it back.
export function useSetCustomEnabled() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => api<null>(`/api/waf-rules/custom/${id}/enabled`, json("PUT", { enabled })),
    onMutate: async ({ id, enabled }) => {
      await qc.cancelQueries({ queryKey: key });
      const before = qc.getQueryData<WAFPage>(key);
      qc.setQueryData<WAFPage>(key, (p) => p && { ...p, custom: p.custom.map((r) => (r.id === id ? { ...r, enabled } : r)) });
      return { before };
    },
    onError: (_e, _v, ctx) => ctx?.before && qc.setQueryData(key, ctx.before),
    onSettled: () => qc.invalidateQueries({ queryKey: key }),
  });
}
