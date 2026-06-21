// Minimal fetch wrapper for the Setup Wizard's backend endpoints
// (backend/internal/setup) plus the one URL the OIDC login flow
// (backend/internal/auth) needs. Deliberately not TanStack Query - this
// page only ever makes one-shot POSTs in a fixed sequence, not the
// cached/revalidated GETs that library is for; it gets introduced once the
// rest of the dashboard (spec section 6.4) starts needing it.

const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";

// Must match bootstrap.HeaderName in the Go backend exactly.
const BOOTSTRAP_HEADER = "X-ModuLab-Bootstrap-Token";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(
  path: string,
  options: RequestInit & { bootstrapToken?: string } = {},
): Promise<T> {
  const { bootstrapToken, headers, ...rest } = options;
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...rest,
    headers: {
      "Content-Type": "application/json",
      ...(bootstrapToken ? { [BOOTSTRAP_HEADER]: bootstrapToken } : {}),
      ...headers,
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new ApiError(res.status, text || res.statusText);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

// The backend no longer generates or returns a master key here (it must
// come from MODULAB_MASTER_KEY in the backend's own environment - see
// wizard.go's InitHandler doc comment) - Ready just confirms the bootstrap
// token round-tripped through bootstrapMgr.Middleware successfully.
export interface InitResponse {
  ready: boolean;
}

export function setupInit(bootstrapToken: string): Promise<InitResponse> {
  return request<InitResponse>("/v1/setup/init", { method: "POST", bootstrapToken });
}

export interface OIDCStatus {
  configured: boolean;
  issuer_url?: string;
  client_id?: string;
}

export function configureOIDC(
  bootstrapToken: string,
  body: { issuer_url: string; client_id: string; client_secret: string },
): Promise<OIDCStatus> {
  return request<OIDCStatus>("/v1/setup/oidc/configure", {
    method: "POST",
    bootstrapToken,
    body: JSON.stringify(body),
  });
}

export interface DNSChallengeStatus {
  configured: boolean;
  provider?: string;
}

export function configureDNSChallenge(
  bootstrapToken: string,
  body: { provider: string; credentials: string },
): Promise<DNSChallengeStatus> {
  return request<DNSChallengeStatus>("/v1/setup/dns-challenge/configure", {
    method: "POST",
    bootstrapToken,
    body: JSON.stringify(body),
  });
}

export interface GroupPrefixStatus {
  configured: boolean;
  prefix?: string;
  groups?: string[];
}

export function configureGroupPrefix(
  bootstrapToken: string,
  prefix: string,
): Promise<GroupPrefixStatus> {
  return request<GroupPrefixStatus>("/v1/setup/group-prefix/configure", {
    method: "POST",
    bootstrapToken,
    body: JSON.stringify({ prefix }),
  });
}

export interface CompleteResponse {
  completed: boolean;
  missing?: string[];
}

export function completeSetup(bootstrapToken: string): Promise<CompleteResponse> {
  return request<CompleteResponse>("/v1/setup/complete", { method: "POST", bootstrapToken });
}

// Not a fetch() call - this is a full-page navigation target. The backend
// redirects the browser to the IdP from here, so it can't go through
// request() above.
export function loginRedirectUrl(): string {
  return `${API_BASE_URL}/v1/auth/login`;
}

export interface HealthResponse {
  status: string;
  version: string;
  postgres_reachable: boolean;
  valkey_reachable: boolean;
  master_key_present: boolean;
  setup_completed: boolean;
}

// /healthz needs no bootstrap token - it's exempt from that gate in main.go
// - which is exactly why the footer uses it to read the running version
// rather than a dedicated authenticated endpoint.
export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/healthz");
}
