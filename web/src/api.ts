// Admin API client. Session cookie auth; every non-GET carries the CSRF token
// the Go server puts on <body data-csrf>.
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly fields?: Record<string, string>,
  ) {
    super(message);
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body && !(init.body instanceof FormData)) headers.set("Content-Type", "application/json");
  if (init.method && init.method !== "GET") headers.set("X-CSRF-Token", document.body.dataset.csrf ?? "");

  const res = await fetch(new URL(`../api/${path.replace(/^\//, "")}`, document.baseURI), {
    ...init,
    headers,
    credentials: "same-origin",
  });
  if (res.status === 401) {
    window.location.assign(new URL("../login", document.baseURI));
    throw new ApiError(401, "unauthenticated", "Session expired");
  }
  const body = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) {
    throw new ApiError(res.status, body?.error ?? "error", body?.message ?? res.statusText, body?.fields);
  }
  return body as T;
}
