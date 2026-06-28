// Minimal fetch wrapper for the Setup Wizard's backend endpoints
// (backend/internal/setup) plus the one URL the OIDC login flow
// (backend/internal/auth) needs. Deliberately not TanStack Query - this
// page only ever makes one-shot POSTs in a fixed sequence, not the
// cached/revalidated GETs that library is for; it gets introduced once the
// rest of the dashboard (spec section 6.4) starts needing it.

// Empty string = relative to the current origin. In dev, Vite proxies /v1/*
// and /healthz to the Go backend (see vite.config.ts), so the browser never
// needs to know the backend's address directly. VITE_API_BASE_URL can still
// override this for production builds served from a different origin.
const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? "";

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
  searxng_configured: boolean;
  // Only present when searxng_configured is true.
  searxng_reachable?: boolean;
  // Absent when the NTP UDP check timed out or was blocked by the firewall.
  // true = clock within 30 s of pool.ntp.org; false = dangerous drift.
  ntp_drift_ok?: boolean;
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

// --- News feeds ----------------------------------------------------------
// Mirrors backend/internal/news.FeedResponse exactly.

export interface Feed {
  id: number;
  url: string;
  label: string;
  /** Only present on user-facing GET /v1/feeds, not on admin list. */
  enabled?: boolean;
  created_at: string;
}

// Mirrors backend/internal/news.Article exactly.
export interface NewsArticle {
  title: string;
  url: string;
  source: string;
  published_at: string; // RFC3339
  image_url?: string;
}

// GET /v1/admin/feeds — org-admin/super-admin only.
export function adminListFeeds(token: string): Promise<Feed[]> {
  return request<Feed[]>("/v1/admin/feeds", { headers: bearerHeaders(token) });
}

// POST /v1/admin/feeds
export function adminCreateFeed(token: string, body: { url: string; label: string }): Promise<Feed> {
  return request<Feed>("/v1/admin/feeds", {
    method: "POST",
    headers: bearerHeaders(token),
    body: JSON.stringify(body),
  });
}

// PATCH /v1/admin/feeds/{id}
export function adminUpdateFeed(
  token: string,
  id: number,
  body: { url: string; label: string },
): Promise<void> {
  return request<void>(`/v1/admin/feeds/${id}`, {
    method: "PATCH",
    headers: bearerHeaders(token),
    body: JSON.stringify(body),
  });
}

// DELETE /v1/admin/feeds/{id}
export function adminDeleteFeed(token: string, id: number): Promise<void> {
  return request<void>(`/v1/admin/feeds/${id}`, {
    method: "DELETE",
    headers: bearerHeaders(token),
  });
}

// GET /v1/feeds — all approved users; returns feeds with enabled flag.
export function listFeeds(token: string): Promise<Feed[]> {
  return request<Feed[]>("/v1/feeds", { headers: bearerHeaders(token) });
}

// PATCH /v1/feeds/{id}/subscription
export function setFeedSubscription(
  token: string,
  id: number,
  enabled: boolean,
): Promise<void> {
  return request<void>(`/v1/feeds/${id}/subscription`, {
    method: "PATCH",
    headers: bearerHeaders(token),
    body: JSON.stringify({ enabled }),
  });
}

// GET /v1/news — aggregated articles from user's enabled feeds.
export function getNews(token: string): Promise<NewsArticle[]> {
  return request<NewsArticle[]>("/v1/news", { headers: bearerHeaders(token) });
}

// Admin-controlled display config returned by GET /v1/news/config.
export interface NewsConfig {
  home_count: number;
  show_images: boolean;
}

// GET /v1/news/config — returns global display settings for authenticated users.
export function getNewsConfig(token: string): Promise<NewsConfig> {
  return request<NewsConfig>("/v1/news/config", { headers: bearerHeaders(token) });
}

// Admin news settings (GET/PATCH /v1/admin/news/settings).
export interface AdminNewsSettings {
  max_articles: number;
  home_count: number;
  show_images: boolean;
}

// GET /v1/admin/news/settings
export function adminGetNewsSettings(token: string): Promise<AdminNewsSettings> {
  return request<AdminNewsSettings>("/v1/admin/news/settings", {
    headers: bearerHeaders(token),
  });
}

// PATCH /v1/admin/news/settings — partial update.
export function adminUpdateNewsSettings(
  token: string,
  body: Partial<AdminNewsSettings>,
): Promise<AdminNewsSettings> {
  return request<AdminNewsSettings>("/v1/admin/news/settings", {
    method: "PATCH",
    headers: bearerHeaders(token),
    body: JSON.stringify(body),
  });
}

// --- Widget: Weather -----------------------------------------------------
// Mirrors backend/internal/weather.Response exactly.

export interface WeatherCurrent {
  temperature: number;
  apparent_temperature: number;
  humidity: number;
  wind_speed: number;
  weather_code: number;
}

export interface WeatherHourly {
  time: string; // "2026-06-23T14:00"
  temperature: number;
  weather_code: number;
  precip_probability: number;
}

export interface WeatherDaily {
  time: string; // "2026-06-23"
  weather_code: number;
  temp_max: number;
  temp_min: number;
  precip_prob_max: number;
  sunrise: string;
  sunset: string;
}

export interface WeatherResponse {
  current: WeatherCurrent;
  hourly: WeatherHourly[];
  daily: WeatherDaily[];
  timezone: string;
}

// GET /v1/widgets/weather — no auth required (see weather.go's doc comment).
// lat and lon come from navigator.geolocation.getCurrentPosition().
export function getWeather(lat: number, lon: number): Promise<WeatherResponse> {
  return request<WeatherResponse>(
    `/v1/widgets/weather?lat=${lat.toFixed(4)}&lon=${lon.toFixed(4)}`,
  );
}

// --- SearXNG web search --------------------------------------------------
// Mirrors backend/internal/searxng's JSON shapes exactly.

export interface SearXNGStatus {
  configured: boolean;
  url?: string;
  // Both fields are always present (backend fills defaults when unset).
  max_results: number;
  fetch_pages: number;
}

// GET /v1/admin/searxng/status — super-admin only.
export function searxngStatus(token: string): Promise<SearXNGStatus> {
  return request<SearXNGStatus>("/v1/admin/searxng/status", {
    headers: bearerHeaders(token),
  });
}

// POST /v1/admin/searxng/configure — super-admin only.
export function configureSearxng(
  token: string,
  body: { url: string; max_results: number; fetch_pages: number },
): Promise<SearXNGStatus> {
  return request<SearXNGStatus>("/v1/admin/searxng/configure", {
    method: "POST",
    headers: bearerHeaders(token),
    body: JSON.stringify(body),
  });
}

// DELETE /v1/admin/searxng — super-admin only.
export function deleteSearxngConfig(token: string): Promise<void> {
  return request<void>("/v1/admin/searxng", {
    method: "DELETE",
    headers: bearerHeaders(token),
  });
}

// One search result returned by GET /v1/search/web.
// thumbnail and img_src are only populated for category=images results.
export interface WebResult {
  title: string;
  url: string;
  snippet: string;
  thumbnail?: string;
  img_src?: string;
}

// Search category — "general" for web results, "images" for image search.
export type SearchCategory = "general" | "images";

// Time range filter — "" means any time.
export type SearchTimeRange = "" | "day" | "week" | "month" | "year";

// GET /v1/search/web?q=<query>&category=<category>&time_range=<range>
// Any approved session. Returns 503 when SearXNG is not configured.
export function searchWeb(
  token: string,
  query: string,
  category: SearchCategory = "general",
  timeRange: SearchTimeRange = "",
): Promise<WebResult[]> {
  const params = new URLSearchParams({ q: query, category });
  if (timeRange) params.set("time_range", timeRange);
  return request<WebResult[]>(
    `/v1/search/web?${params.toString()}`,
    { headers: bearerHeaders(token) },
  );
}

// --- Search preferences (per-user) ----------------------------------------
// Mirrors backend/internal/db.SearchPrefs exactly.

export interface SearchPrefs {
  // 0 = off, 1 = moderate, 2 = strict
  safesearch: number;
  // "all", "de", "en", "fr", "es", "it", "nl", "pl", "pt", "ru", "zh"
  language: string;
}

// GET /v1/user/search-prefs — any approved session.
export function getSearchPrefs(token: string): Promise<SearchPrefs> {
  return request<SearchPrefs>("/v1/user/search-prefs", {
    headers: bearerHeaders(token),
  });
}

// POST /v1/user/search-prefs — any approved session.
export function updateSearchPrefs(
  token: string,
  body: Partial<SearchPrefs>,
): Promise<SearchPrefs> {
  return request<SearchPrefs>("/v1/user/search-prefs", {
    method: "POST",
    headers: bearerHeaders(token),
    body: JSON.stringify(body),
  });
}

// --- AI providers -----------------------------------------------------------
// Mirrors backend/internal/ai's JSON shapes exactly.

// Admin view: full provider details.
export interface AIProvider {
  id: string;
  type: string;
  name: string;
  base_url?: string;
  has_admin_key: boolean;
  default_model: string;
  user_can_override: boolean;
  enabled: boolean;
  sort_order: number;
}

// User view: availability info without key material.
export interface AIUserProvider {
  id: string;
  name: string;
  type: string;
  default_model: string;   // admin-set model; fixed when using admin key
  preferred_model: string; // user's model choice; only active when has_user_key
  available: boolean;
  enabled: boolean;
  has_user_key: boolean;
  has_admin_key: boolean;
  can_override: boolean;
}

// GET /v1/admin/ai/providers — super-admin only.
export function adminListAIProviders(token: string): Promise<AIProvider[]> {
  return request<AIProvider[]>("/v1/admin/ai/providers", {
    headers: bearerHeaders(token),
  });
}

// POST /v1/admin/ai/providers — super-admin only.
export function adminCreateAIProvider(
  token: string,
  body: {
    id: string;
    type: string;
    name: string;
    base_url?: string;
    admin_key?: string;
    default_model: string;
    user_can_override: boolean;
    enabled: boolean;
    sort_order: number;
  },
): Promise<AIProvider> {
  return request<AIProvider>("/v1/admin/ai/providers", {
    method: "POST",
    headers: bearerHeaders(token),
    body: JSON.stringify(body),
  });
}

// PATCH /v1/admin/ai/providers/{id} — super-admin only.
export function adminPatchAIProvider(
  token: string,
  id: string,
  body: Partial<{
    name: string;
    base_url: string;
    admin_key: string;
    default_model: string;
    user_can_override: boolean;
    enabled: boolean;
    sort_order: number;
  }>,
): Promise<AIProvider> {
  return request<AIProvider>(`/v1/admin/ai/providers/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: bearerHeaders(token),
    body: JSON.stringify(body),
  });
}

// DELETE /v1/admin/ai/providers/{id} — super-admin only.
export function adminDeleteAIProvider(token: string, id: string): Promise<void> {
  return request<void>(`/v1/admin/ai/providers/${encodeURIComponent(id)}`, {
    method: "DELETE",
    headers: bearerHeaders(token),
  });
}

// DELETE /v1/admin/ai/providers/{id}/key — clears admin key only.
export function adminClearAIProviderKey(token: string, id: string): Promise<void> {
  return request<void>(`/v1/admin/ai/providers/${encodeURIComponent(id)}/key`, {
    method: "DELETE",
    headers: bearerHeaders(token),
  });
}

// GET /v1/admin/ai/providers/{id}/models — fetches available models from the provider API.
export async function adminFetchAIProviderModels(token: string, id: string): Promise<string[]> {
  const result = await request<{ models: string[] }>(
    `/v1/admin/ai/providers/${encodeURIComponent(id)}/models`,
    { headers: bearerHeaders(token) },
  );
  return result.models ?? [];
}

export interface AISettings {
  chat_rpm_limit: number;
  max_body_bytes: number;
}

// GET /v1/admin/ai/settings — super-admin only.
export function adminGetAISettings(token: string): Promise<AISettings> {
  return request<AISettings>("/v1/admin/ai/settings", {
    headers: bearerHeaders(token),
  });
}

// PATCH /v1/admin/ai/settings — super-admin only.
export function adminPatchAISettings(token: string, settings: Partial<AISettings>): Promise<AISettings> {
  return request<AISettings>("/v1/admin/ai/settings", {
    method: "PATCH",
    headers: bearerHeaders(token),
    body: JSON.stringify(settings),
  });
}

// GET /v1/ai/providers — any approved session.
export function listAIProviders(token: string): Promise<AIUserProvider[]> {
  return request<AIUserProvider[]>("/v1/ai/providers", {
    headers: bearerHeaders(token),
  });
}

// PUT /v1/ai/keys/{id} — set own API key for a provider.
export function setAIUserKey(token: string, providerId: string, key: string): Promise<void> {
  return request<void>(`/v1/ai/keys/${encodeURIComponent(providerId)}`, {
    method: "PUT",
    headers: bearerHeaders(token),
    body: JSON.stringify({ key }),
  });
}

// DELETE /v1/ai/keys/{id} — remove own API key (fall back to admin key).
export function deleteAIUserKey(token: string, providerId: string): Promise<void> {
  return request<void>(`/v1/ai/keys/${encodeURIComponent(providerId)}`, {
    method: "DELETE",
    headers: bearerHeaders(token),
  });
}

// PATCH /v1/ai/keys/{id}/model — save preferred model for own key.
export function setAIUserPreferredModel(token: string, providerId: string, model: string): Promise<void> {
  return request<void>(`/v1/ai/keys/${encodeURIComponent(providerId)}/model`, {
    method: "PATCH",
    headers: bearerHeaders(token),
    body: JSON.stringify({ model }),
  });
}

// GET /v1/ai/keys/{id}/models — fetch available models using the user's own key.
export async function fetchUserAIProviderModels(token: string, providerId: string): Promise<string[]> {
  const result = await request<{ models: string[] }>(
    `/v1/ai/keys/${encodeURIComponent(providerId)}/models`,
    { headers: bearerHeaders(token) },
  );
  return result.models ?? [];
}

// Chat message shape mirroring backend/internal/ai.chatMessage.
export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

// streamAIChat opens a POST /v1/ai/chat SSE stream and calls onDelta for each
// text chunk received. Returns a Promise that resolves when [DONE] is received
// or rejects on error. The caller is responsible for aborting via the signal.
export function streamAIChat(
  token: string,
  providerId: string,
  model: string,
  messages: ChatMessage[],
  onDelta: (text: string) => void,
  signal?: AbortSignal,
): Promise<void> {
  return fetch(`${API_BASE_URL}/v1/ai/chat`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ provider_id: providerId, model, messages }),
    signal,
  }).then(async (res) => {
    if (!res.ok) {
      const text = await res.text();
      throw new ApiError(res.status, text || res.statusText);
    }
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split("\n");
      buf = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        const data = line.slice(6);
        if (data === "[DONE]") return;
        try {
          const parsed = JSON.parse(data) as { delta?: string; error?: string };
          if (parsed.error) throw new Error(parsed.error);
          if (parsed.delta) onDelta(parsed.delta);
        } catch {
          // malformed chunk — skip
        }
      }
    }
  });
}

// ---- Admin system status -------------------------------------------------------

export interface OIDCStatus {
  configured: boolean;
  issuer_url?: string;
  client_id?: string;
}

export interface DNSChallengeStatus {
  configured: boolean;
  provider?: string;
}

export interface SystemStatus {
  oidc: OIDCStatus;
  dns_challenge: DNSChallengeStatus;
  group_prefix: string;
}

// GET /v1/admin/system — OIDC config, DNS-challenge, group prefix (read-only).
export function getSystemStatus(token: string): Promise<SystemStatus> {
  return request<SystemStatus>("/v1/admin/system", {
    headers: bearerHeaders(token),
  });
}

// PATCH /v1/admin/oidc — update OIDC configuration. client_secret is optional;
// omit or pass "" to keep the existing secret.
export function updateOIDC(
  token: string,
  body: { issuer_url: string; client_id: string; client_secret?: string },
): Promise<OIDCStatus> {
  return request<OIDCStatus>("/v1/admin/oidc", {
    method: "PATCH",
    headers: bearerHeaders(token),
    body: JSON.stringify(body),
  });
}

// PATCH /v1/admin/dns-challenge — update DNS-challenge configuration.
// credentials is optional; omit or pass "" to keep existing credentials.
export function updateDNSChallenge(
  token: string,
  body: { provider: string; credentials?: string },
): Promise<DNSChallengeStatus> {
  return request<DNSChallengeStatus>("/v1/admin/dns-challenge", {
    method: "PATCH",
    headers: bearerHeaders(token),
    body: JSON.stringify(body),
  });
}

// ---- Audit log ----------------------------------------------------------------

export interface AuditEntry {
  id: number;
  created_at: string;    // ISO-8601 timestamp
  event_type: string;
  actor_id: string;
  actor_email: string;
  target_id: string;
  target_email: string;
  details: string;       // JSON string, "" if none
  prev_hash: string;
  hash: string;
}

// GET /v1/audit-log — paginated, newest first.
// event_type: filter to one event type; before: cursor (id < before); limit: page size.
export function getAuditLog(
  token: string,
  opts?: { event_type?: string; before?: number; limit?: number },
): Promise<AuditEntry[]> {
  const params = new URLSearchParams();
  if (opts?.event_type) params.set("event_type", opts.event_type);
  if (opts?.before) params.set("before", String(opts.before));
  if (opts?.limit) params.set("limit", String(opts.limit));
  const qs = params.toString();
  return request<AuditEntry[]>(`/v1/audit-log${qs ? `?${qs}` : ""}`, {
    headers: bearerHeaders(token),
  });
}

// ---- User preferences -------------------------------------------------------

export interface UserPrefs {
  ui_language: string; // "en" | "de" | "" (browser default)
}

// GET /v1/user/preferences — returns the calling user's stored UI language.
export function getUserPrefs(token: string): Promise<UserPrefs> {
  return request<UserPrefs>("/v1/user/preferences", {
    headers: bearerHeaders(token),
  });
}

// PATCH /v1/user/preferences — saves the UI language preference.
export function updateUserPrefs(token: string, prefs: Partial<UserPrefs>): Promise<void> {
  return request<void>("/v1/user/preferences", {
    method: "PATCH",
    headers: bearerHeaders(token),
    body: JSON.stringify(prefs),
  });
}

// ---- DSGVO / data export ----------------------------------------------------

// GET /v1/auth/me/export — triggers a JSON file download of all personal data.
// Returns the raw Response so the caller can blob it and create an object URL.
export async function exportMyData(token: string): Promise<Blob> {
  const res = await fetch(`${API_BASE_URL}/v1/auth/me/export`, {
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new ApiError(res.status, text || res.statusText);
  }
  return res.blob();
}
