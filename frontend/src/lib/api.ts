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
  uptime_seconds: number;
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

// Mirrors backend/internal/auth.MeResponse's JSON shape exactly (the
// embedded Session's UserID/Email/EmailVerified/Name/PreferredUsername/
// Picture/Role/Locked fields plus the sibling AccountSettingsURL, all with
// those exact json tags) - keep both in sync. Name, PreferredUsername, and
// Picture come from the OIDC "profile" claims at login time and are
// optional by nature (PocketID or any other IdP may have any subset unset)
// - callers must treat "" as "not available", never as an error.
// user_id is the OIDC "sub" claim - stable for a given IdP account even if
// every other field above changes, which is exactly why ProfilePage shows
// it as a separate, more technical row rather than folding it into the
// display name. AccountSettingsURL is computed fresh per-request by the
// backend (not stored on the session) and is "" if OIDC's issuer URL could
// not be resolved - same "not available" treatment applies. locked is only
// ever present (and true) alongside role === "pending" - it distinguishes
// "an admin revoked your access" from the far more common "never approved
// yet" case; absent (undefined) for every other session.
export interface Session {
  user_id: string;
  email: string;
  email_verified: boolean;
  name: string;
  preferred_username: string;
  picture: string;
  role: string;
  account_settings_url?: string;
  locked?: boolean;
}

function bearerHeaders(token: string): HeadersInit {
  return { Authorization: `Bearer ${token}` };
}

// GET /v1/auth/me - the one endpoint every page that needs to know "who is
// this and what role do they have" calls, whether that's to render a
// dashboard or just to decide whether to bounce to /pending or /login.
export function getMe(token: string): Promise<Session> {
  return request<Session>("/v1/auth/me", { headers: bearerHeaders(token) });
}

// eventsUrl builds the GET /v1/events URL (backend/internal/auth/
// events.go) for token. Not a fetch()-based call like everything else in
// this file - the caller opens this directly as `new EventSource(...)`
// (see lib/useEvents.ts) - which is also why token travels as a query
// parameter instead of going through bearerHeaders() below: EventSource
// cannot set custom request headers at all.
export function eventsUrl(token: string): string {
  return `${API_BASE_URL}/v1/events?token=${encodeURIComponent(token)}`;
}

// POST /v1/auth/logout - invalidates the token server-side immediately.
// Callers should clear the locally stored token (lib/session.ts) regardless
// of whether this call succeeds; a token that is already invalid (expired,
// already logged out elsewhere) still needs to fail closed on the client.
export function logoutRequest(token: string): Promise<void> {
  return request<void>("/v1/auth/logout", { method: "POST", headers: bearerHeaders(token) });
}

// DELETE /v1/auth/me - lets the signed-in user remove their own account
// entirely, the self-service counterpart to deleteUser below (which is
// admin-only and explicitly refuses to act on the caller's own account -
// see backend/internal/auth/admin.go's guardAgainstSelfOrLastSuperAdmin).
// The backend still refuses this for the last remaining super-admin (400,
// surfaced here as an ApiError with that message in .message) - someone
// has to be left who can manage the instance. Callers should clear the
// locally stored token (lib/session.ts) and navigate away on success, same
// as logoutRequest above.
export function deleteSelf(token: string): Promise<void> {
  return request<void>("/v1/auth/me", { method: "DELETE", headers: bearerHeaders(token) });
}

// Mirrors backend/internal/auth.UserResponse's JSON shape exactly. One
// entry per user row, covering all three states an admin can act on:
// Approved === false -> "Pending" (Approve button); Approved && Locked ->
// "Locked" (Unlock + Delete); Approved && !Locked -> "Active" (Lock +
// Delete). Role reflects what they're already correctly a member of in
// the IdP, not anything approval/lock/delete would change.
export interface AdminUser {
  subject: string;
  email: string;
  name: string;
  role: string;
  approved: boolean;
  locked: boolean;
  created_at: string;
  last_login_at: string;
}

// GET /v1/admin/users - every user, org-admin/super-admin only (enforced
// server-side by requireAdmin in backend/internal/auth/admin.go; a
// non-admin caller gets a 403, surfaced here as an ApiError).
export function listUsers(token: string): Promise<AdminUser[]> {
  return request<AdminUser[]>("/v1/admin/users", { headers: bearerHeaders(token) });
}

// POST /v1/admin/users/{subject}/approve - flips that user's approved flag
// to true. Takes effect on their *next* login, not retroactively - see
// ApproveUserHandler's doc comment in admin.go for why.
export function approveUser(token: string, subject: string): Promise<void> {
  return request<void>(`/v1/admin/users/${encodeURIComponent(subject)}/approve`, {
    method: "POST",
    headers: bearerHeaders(token),
  });
}

// POST /v1/admin/users/{subject}/lock - revokes an already-approved user's
// access without forgetting who they are. The backend refuses this for
// your own account or the last remaining super-admin (400) - surfaced here
// as an ApiError with that message in .message.
export function lockUser(token: string, subject: string): Promise<void> {
  return request<void>(`/v1/admin/users/${encodeURIComponent(subject)}/lock`, {
    method: "POST",
    headers: bearerHeaders(token),
  });
}

// POST /v1/admin/users/{subject}/unlock - restores access for a locked
// user. No self/last-super-admin restriction (unlocking can't strand the
// instance the way locking or deleting could).
export function unlockUser(token: string, subject: string): Promise<void> {
  return request<void>(`/v1/admin/users/${encodeURIComponent(subject)}/unlock`, {
    method: "POST",
    headers: bearerHeaders(token),
  });
}

// DELETE /v1/admin/users/{subject} - forgets the user row entirely. Same
// self/last-super-admin guard as lockUser. If this person logs in again
// later, they are JIT-provisioned as a brand-new pending user, exactly as
// if they had never logged in before.
export function deleteUser(token: string, subject: string): Promise<void> {
  return request<void>(`/v1/admin/users/${encodeURIComponent(subject)}`, {
    method: "DELETE",
    headers: bearerHeaders(token),
  });
}

// Mirrors backend/internal/setup.SMTPStatusResponse's JSON shape exactly.
// password is never part of this type at all (mirroring how
// OIDCStatusResponse never carries the OIDC client secret either) - there
// is no "show the current password" affordance anywhere in the admin UI,
// only "set a new one".
export interface SMTPStatus {
  configured: boolean;
  host?: string;
  port?: number;
  username?: string;
  from_address?: string;
  // One of "none" | "starttls" | "tls" - mirrors
  // backend/internal/setup.SMTPEncryptionNone/STARTTLS/TLS exactly.
  encryption?: string;
}

// Body of POST /v1/admin/smtp/configure - mirrors
// backend/internal/setup.SMTPConfigRequest. password may be sent empty to
// mean "unauthenticated relay", same as the backend's own treatment (see
// that struct's doc comment) - it is never "leave the existing password
// unchanged", since the backend has no way to tell those two cases apart
// once a password is already encrypted at rest.
export interface SMTPConfigRequest {
  host: string;
  port: number;
  username: string;
  password: string;
  from_address: string;
  // One of "none" | "starttls" | "tls" - empty defaults server-side to
  // "starttls" (see SMTPConfigRequest's Go doc comment).
  encryption: string;
}

// GET /v1/admin/smtp/status - super-admin only (enforced server-side by
// auth.RequireSuperAdminMiddleware; an org-admin or below gets a 403,
// surfaced here as an ApiError).
export function smtpStatus(token: string): Promise<SMTPStatus> {
  return request<SMTPStatus>("/v1/admin/smtp/status", { headers: bearerHeaders(token) });
}

// POST /v1/admin/smtp/configure - super-admin only, same gate as
// smtpStatus above.
export function configureSmtp(token: string, body: SMTPConfigRequest): Promise<SMTPStatus> {
  return request<SMTPStatus>("/v1/admin/smtp/configure", {
    method: "POST",
    headers: bearerHeaders(token),
    body: JSON.stringify(body),
  });
}

// DELETE /v1/admin/smtp - clears the configuration entirely (all fields,
// including the encrypted password), returning the instance to "not
// configured" - same gate as smtpStatus/configureSmtp above. Distinct
// from configureSmtp with empty fields: that would still write an empty
// host/from_address and get rejected as invalid, this actually removes
// the underlying settings rows.
export function deleteSmtpConfig(token: string): Promise<void> {
  return request<void>("/v1/admin/smtp", { method: "DELETE", headers: bearerHeaders(token) });
}
