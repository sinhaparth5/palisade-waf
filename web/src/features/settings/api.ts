import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

// The Settings page (internal/ui/account.go and friends). Each section has
// its own read, so a role sees only what it may.

export type Passkey = { id: number; name: string; created_at: string; last_used_at: string };
export type Device = { id: string; device: string; ip: string; location: string; flag: string; first_seen: string; last_seen: string; current: boolean; live: boolean };
export type Account = { email: string; totp: boolean; secure_context: boolean; passkeys: Passkey[]; devices: Device[] };
export type Credentials = { current_password: string; new_email: string; new_password: string; confirm_password: string };

export const json = (method: string, body: unknown = {}) => ({ method, body: JSON.stringify(body) });

export function useWrite<V, R = null>(key: string, fn: (v: V) => Promise<R>) {
  const qc = useQueryClient();
  return useMutation({ mutationFn: fn, onSettled: () => qc.invalidateQueries({ queryKey: [key] }) });
}

export const useAccount = () => useQuery({ queryKey: ["account"], queryFn: () => api<Account>("/api/settings/account") });

export const useSetCredentials = () => useMutation({ mutationFn: (c: Credentials) => api<null>("/api/settings/credentials", json("PUT", c)) });
export const useStartTOTP = () => useMutation({ mutationFn: () => api<{ qr: string; key: string }>("/api/settings/2fa/start", json("POST")) });
export const useConfirmTOTP = () => useWrite("account", (code: string) => api<{ backup_codes: string[] }>("/api/settings/2fa/confirm", json("POST", { code })));
export const useDisableTOTP = () => useWrite("account", (code: string) => api<null>("/api/settings/2fa/disable", json("POST", { code })));
export const useRemovePasskey = () => useWrite("account", (id: number) => api<null>(`/api/settings/passkeys/${id}`, { method: "DELETE" }));
export const useSignOutDevice = () => useWrite("account", (id: string) => api<null>(`/api/settings/devices/${encodeURIComponent(id)}`, { method: "DELETE" }));
export const useSignOutOthers = () => useWrite("account", () => api<null>("/api/settings/devices/sign-out-others", json("POST")));

// Registering a passkey runs the browser's WebAuthn ceremony between the
// begin and finish requests. The server speaks base64url for every buffer.
const fromB64 = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const toB64 = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

type CreationJSON = { publicKey: Omit<PublicKeyCredentialCreationOptions, "challenge" | "user" | "excludeCredentials"> & {
  challenge: string;
  user: Omit<PublicKeyCredentialUserEntity, "id"> & { id: string };
  excludeCredentials?: (Omit<PublicKeyCredentialDescriptor, "id"> & { id: string })[];
} };

export async function registerPasskey(name: string) {
  const { publicKey: o } = await api<CreationJSON>("/api/settings/passkeys/begin", json("POST", { name }));
  const cred = (await navigator.credentials.create({
    publicKey: { ...o, challenge: fromB64(o.challenge), user: { ...o.user, id: fromB64(o.user.id) }, excludeCredentials: o.excludeCredentials?.map((c) => ({ ...c, id: fromB64(c.id) })) },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No passkey was created.");
  const r = cred.response as AuthenticatorAttestationResponse;
  await api<null>(
    "/api/settings/passkeys/finish",
    json("POST", { id: cred.id, rawId: toB64(cred.rawId), type: cred.type, response: { attestationObject: toB64(r.attestationObject), clientDataJSON: toB64(r.clientDataJSON) } }),
  );
}

export function useAddPasskey() {
  const qc = useQueryClient();
  return useMutation({ mutationFn: registerPasskey, onSettled: () => qc.invalidateQueries({ queryKey: ["account"] }) });
}
