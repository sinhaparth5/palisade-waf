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

// Owner only: GET {admin}/api/settings/team (internal/ui/team.go).
export type Role = "viewer" | "admin" | "owner";
export type User = { id: number; email: string; role: Role; disabled: boolean; totp: boolean; sso: boolean; invited: boolean; created_at: string; you: boolean };
export type SSOInvite = { id: number; email: string; role: Role; expires_at: string; expired: boolean };
export type APIKey = { id: number; name: string; prefix: string; read_only: boolean; created_at: string; last_used_at: string };
export type SSO = { issuer: string; client_id: string; secret_set: boolean; group: string; callback_url: string };
export type Team = { users: User[]; invites: SSOInvite[]; api_keys: APIKey[]; sso: SSO };
export type Invite = { email: string; role: Role };
// The invite email's outcome: when it wasn't sent, link is shown once.
export type InviteSent = { email: string; sent: boolean; link?: string; send_error?: string };

export const useTeam = () => useQuery({ queryKey: ["team"], queryFn: () => api<Team>("/api/settings/team") });
export const useAddUser = () => useWrite("team", (i: Invite) => api<InviteSent>("/api/settings/users", json("POST", i)));
export const useResendInvite = () => useWrite("team", (id: number) => api<InviteSent>(`/api/settings/users/${id}/invite`, json("POST")));
export const useUpdateUser = () => useWrite("team", ({ id, ...v }: { id: number; role?: Role; disabled?: boolean }) => api<null>(`/api/settings/users/${id}`, json("PUT", v)));
export const useResetUser2FA = () => useWrite("team", (id: number) => api<null>(`/api/settings/users/${id}/reset-2fa`, json("POST")));
export const useRemoveUser = () => useWrite("team", (id: number) => api<null>(`/api/settings/users/${id}`, { method: "DELETE" }));
export const useAddSSOInvite = () => useWrite("team", (i: Invite) => api<null>("/api/settings/sso-invites", json("POST", i)));
export const useRenewSSOInvite = () => useWrite("team", (id: number) => api<null>(`/api/settings/sso-invites/${id}/renew`, json("POST")));
export const useRemoveSSOInvite = () => useWrite("team", (id: number) => api<null>(`/api/settings/sso-invites/${id}`, { method: "DELETE" }));
export const useSetSSO = () =>
  useWrite("team", (s: { issuer: string; client_id: string; client_secret: string; group: string }) => api<null>("/api/settings/sso", json("PUT", s)));
export const useAddAPIKey = () => useWrite("team", (k: { name: string; read_only: boolean }) => api<{ key: string }>("/api/settings/api-keys", json("POST", k)));
export const useRemoveAPIKey = () => useWrite("team", (id: number) => api<null>(`/api/settings/api-keys/${id}`, { method: "DELETE" }));
