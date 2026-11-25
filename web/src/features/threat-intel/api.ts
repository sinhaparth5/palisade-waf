import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

// GET {admin}/api/threat-intel (internal/ui/threatintel.go): every source
// with its sync state, and the quick-add presets. A CrowdSec source's keys
// never come back; push says whether autobans are sent to its LAPI.

export type Source = {
  id: number;
  label: string;
  kind: "feed" | "crowdsec";
  url: string;
  interval_hours: number;
  enabled: boolean;
  last_synced_at: string; // "" = never
  last_error: string;
  ips: number;
  ranges: number;
  push: boolean;
};

export type Preset = { label: string; url: string; interval_hours: number };
export type IntelPage = { sources: Source[]; presets: Preset[] };
export type NewFeed = Preset;
export type NewCrowdSec = { label: string; url: string; api_key: string; machine_login: string; machine_password: string };

const key = ["threat-intel"];

export const useIntel = () => useQuery({ queryKey: key, queryFn: () => api<IntelPage>("/api/threat-intel") });

function useWrite<T>(fn: (v: T) => Promise<unknown>) {
  const qc = useQueryClient();
  return useMutation({ mutationFn: fn, onSettled: () => qc.invalidateQueries({ queryKey: key }) });
}

const post = (path: string, body: unknown) => api<null>(path, { method: "POST", body: JSON.stringify(body) });

export const useAddFeed = () => useWrite((f: NewFeed) => post("/api/threat-intel", f));
export const useAddCrowdSec = () => useWrite((c: NewCrowdSec) => post("/api/threat-intel/crowdsec", c));
export const useDeleteSource = () => useWrite((id: number) => api<null>(`/api/threat-intel/${id}`, { method: "DELETE" }));

// Pausing is safe to show at once: the server only flips a flag, and a
// failure puts the old list back.
export function useSetEnabled() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => api<null>(`/api/threat-intel/${id}`, { method: "PUT", body: JSON.stringify({ enabled }) }),
    onMutate: async ({ id, enabled }) => {
      await qc.cancelQueries({ queryKey: key });
      const before = qc.getQueryData<IntelPage>(key);
      qc.setQueryData<IntelPage>(key, (p) => p && { ...p, sources: p.sources.map((s) => (s.id === id ? { ...s, enabled } : s)) });
      return { before };
    },
    onError: (_e, _v, ctx) => ctx?.before && qc.setQueryData(key, ctx.before),
    onSettled: () => qc.invalidateQueries({ queryKey: key }),
  });
}

// Sync now runs the fetch in the request and answers with the source's new
// state, which replaces the old row.
export function useSync() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api<Source>(`/api/threat-intel/${id}/sync`, { method: "POST" }),
    onSuccess: (s) => qc.setQueryData<IntelPage>(key, (p) => p && { ...p, sources: p.sources.map((o) => (o.id === s.id ? s : o)) }),
  });
}

// since says how long ago a sync ran, coarse on purpose.
export function since(at: string, now = Date.now()) {
  if (!at) return "Never synced";
  const min = Math.max(0, Math.floor((now - Date.parse(at)) / 60_000));
  if (min < 1) return "Synced just now";
  if (min < 60) return `Synced ${min} min ago`;
  const h = Math.floor(min / 60);
  if (h < 48) return `Synced ${h} h ago`;
  return `Synced ${Math.floor(h / 24)} days ago`;
}
