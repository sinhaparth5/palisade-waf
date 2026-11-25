import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

// GET {admin}/api/certificates (internal/ui/certificates.go): the shared
// pool, every host-matched service's TLS, and whether Let's Encrypt has a
// contact email.

export type Cert = { id: number; name: string; domains: string[]; expires_at: string; created_at: string; services: string[] };

// mode: auto = Let's Encrypt, pool = a pool cert (named in cert), custom =
// the service's own upload, none = plain HTTP.
export type ServiceTLS = { name: string; host: string; mode: "auto" | "pool" | "custom" | "none"; cert?: string; expires_at?: string };

export type CertsPage = { certs: Cert[]; services: ServiceTLS[]; acme_email: boolean };

export type NewCert = { name: string; cert_pem: string; key_pem: string };

const key = ["certificates"];

export const useCerts = () => useQuery({ queryKey: key, queryFn: () => api<CertsPage>("/api/certificates") });

export function useAddCert() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (c: NewCert) => api<Cert>("/api/certificates", { method: "POST", body: JSON.stringify(c) }),
    onSettled: () => qc.invalidateQueries({ queryKey: key }),
  });
}

export function useDeleteCert() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api<null>(`/api/certificates/${id}`, { method: "DELETE" }),
    onSettled: () => qc.invalidateQueries({ queryKey: key }),
  });
}

const DAY = 86_400_000;

// expiry says how long a certificate has left: expired, within 30 days
// (renew soon), or fine. An unknown date says so rather than guessing.
export function expiry(at: string | undefined, now = Date.now()) {
  if (!at) return { label: "Expiry unknown", tone: "text-slate-500", dot: "bg-slate-300" };
  const days = Math.floor((Date.parse(at) - now) / DAY);
  if (days < 0) return { label: "Expired", tone: "text-red-600", dot: "bg-danger" };
  if (days <= 30) return { label: days === 1 ? "1 day left" : `${days} days left`, tone: "text-amber-700", dot: "bg-warning" };
  return { label: `${days} days left`, tone: "text-green-700", dot: "bg-success" };
}

export const fmtDate = (at: string) => new Date(at).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
