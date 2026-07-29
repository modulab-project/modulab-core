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

// csrfToken mirrors backend/internal/auth.Session.CSRFToken - see that
// field's doc comment for the full reasoning
// (feedback_modulab_cookie_same_origin_risk). Held only as an in-memory
// module-level variable, never in localStorage/sessionStorage: the whole
// point is that an installed module's UI bundle, which runs in the same
// window/JS realm as this SPA, has no route to this value unless it goes
// out of its way to intercept getMe()'s own fetch response - a plain
// same-origin fetch() from module code cannot read it just by existing,
// the way it can the ambient session cookie. Populated by getMe() below
// (GET /v1/auth/me is the only endpoint that ever returns it) and attached
// to every mutating request by csrfHeaders(). null until the first
// successful getMe() call - request() below simply omits the header in
// that window, which the backend correctly treats as a missing/invalid
// token (403) for any admin route, same as an expired session's stale copy
// would.
let csrfToken: string | null = null;

// Must match backend/internal/auth/admin.go's csrfHeaderName exactly.
const CSRF_HEADER = "X-CSRF-Token";

// csrfHeaders returns the X-CSRF-Token header for state-changing methods
// only (matching backend/internal/auth/admin.go's csrfProtectedMethod) -
// GET/HEAD requests never need it, and the backend ignores it either way
// since only requireAdmin/RequireAdminSession-gated routes ever check it.
// Attaching it unconditionally on every mutating request (not just ones
// aimed at /v1/admin/*) is deliberate: several admin-gated routes don't
// live under that path prefix (e.g. POST /v1/modules/install-manual,
// /v1/store/sync), and there's no cost to sending a header the backend
// simply won't look at on a non-admin route.
function csrfHeaders(method?: string): Record<string, string> {
  const m = (method ?? "GET").toUpperCase();
  if (m === "GET" || m === "HEAD" || !csrfToken) {
    return {};
  }
  return { [CSRF_HEADER]: csrfToken };
}

// Exported so no second HTTP wrapper has to exist anywhere in the app.
// lib/quicklinks.ts used to hand-roll its own fetch() calls, which meant it
// silently missed csrfHeaders() below - and once the admin guards started
// enforcing CSRF (2026-07-27) every admin quick-link create/update/delete
// began returning 403 with nothing in the UI explaining why. Anything that
// talks to Core should go through here; the three raw fetch() calls left in
// this file (adminParseOPML and installModuleManual send FormData, streamAIChat
// needs the unconsumed response stream) are the documented exceptions, and all
// three attach csrfHeaders() by hand.
export async function request<T>(
  path: string,
  options: RequestInit & { bootstrapToken?: string } = {},
): Promise<T> {
  const { bootstrapToken, headers, ...rest } = options;
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...rest,
    // Every session-authenticated endpoint now relies on the browser
    // sending the httpOnly __Host-modulab_session cookie automatically (see
    // backend/internal/auth/handlers.go's setSessionCookie) instead of a
    // caller-supplied Authorization header - `credentials: "include"` is
    // what makes the browser actually attach it, same-origin or not
    // (needed even same-origin once VITE_API_BASE_URL points at a
    // different origin for some deployments).
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(bootstrapToken ? { [BOOTSTRAP_HEADER]: bootstrapToken } : {}),
      ...csrfHeaders(rest.method),
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
//
// options.reauth/returnPath are for the "step-up" flow (backend's
// LoginHandler ?reauth=1&return=... - see its doc comment): a destructive
// admin action that was refused for needing a more recent login
// (requireRecentLogin) uses these so the resulting IdP round-trip actually
// forces fresh authentication (not a silently-reused IdP SSO session) and
// lands the user back on the page they were on, instead of the ordinary
// post-login destination. Omitted entirely for a normal login - the
// backend treats their absence exactly like a plain login redirect.
export function loginRedirectUrl(options?: { reauth?: boolean; returnPath?: string }): string {
  const params = new URLSearchParams();
  if (options?.reauth) {
    params.set("reauth", "1");
  }
  if (options?.returnPath) {
    params.set("return", options.returnPath);
  }
  const query = params.toString();
  return `${API_BASE_URL}/v1/auth/login${query ? `?${query}` : ""}`;
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
  // Counts across every row in installed_modules, by status. degraded is
  // the status a Deno worker gets flipped to when it exits unexpectedly
  // (WorkerPool.SetCrashHandler) - surfaced here so the System Status panel
  // can show it without a separate trip to the Modules admin page.
  modules_active: number;
  modules_degraded: number;
  modules_failed: number;
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
// csrf_token (added alongside feedback_modulab_cookie_same_origin_risk's
// fix) is deliberately NOT surfaced as a field consumers of this interface
// ever read directly - getMe() below pulls it out into the module-private
// csrfToken variable and every other caller only ever sees the rest of the
// session. Kept optional here (rather than a separate response type) since
// it really is just another field of backend/internal/auth.MeResponse's
// embedded Session.
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
  csrf_token?: string;
}

// GET /v1/auth/me - the one endpoint every page that needs to know "who is
// this and what role do they have" calls, whether that's to render a
// dashboard or just to decide whether to bounce to /pending or /login. No
// token parameter: the browser attaches the httpOnly __Host-modulab_session cookie
// automatically (see request()'s credentials: "include").
//
// Also the one and only place csrfToken gets (re-)populated - every tab
// calls this on mount and every POLL_INTERVAL_MS afterward
// (useSession.ts), so the in-memory token is refreshed automatically
// alongside the rest of the session state, with no separate plumbing
// needed for the login round-trip vs. an already-open tab.
export async function getMe(): Promise<Session> {
  const session = await request<Session>("/v1/auth/me");
  if (session.csrf_token) {
    csrfToken = session.csrf_token;
  }
  return session;
}

// eventsUrl builds the GET /v1/events URL (backend/internal/auth/
// events.go). Not a fetch()-based call like everything else in this file -
// the caller opens this directly as `new EventSource(...)` (see
// lib/useEvents.ts). No token/query parameter needed: EventSource sends
// cookies automatically for a same-origin URL, same as any other
// browser-initiated request - this used to need a ?token=... query
// parameter instead, back when the session lived in a header-only bearer
// token EventSource had no way to attach.
export function eventsUrl(): string {
  return `${API_BASE_URL}/v1/events`;
}

// POST /v1/auth/logout - invalidates the token server-side immediately and
// clears the __Host-modulab_session cookie (see backend's LogoutHandler). No
// token parameter to pass or locally-stored token to clear afterward - the
// cookie is httpOnly, so there is nothing for the frontend to hold in the
// first place.
export function logoutRequest(): Promise<void> {
  return request<void>("/v1/auth/logout", { method: "POST" });
}

// DELETE /v1/auth/me - lets the signed-in user remove their own account
// entirely, the self-service counterpart to deleteUser below (which is
// admin-only and explicitly refuses to act on the caller's own account -
// see backend/internal/auth/admin.go's guardAgainstSelfOrLastAdmin).
// The backend still refuses this for the last remaining admin (400,
// surfaced here as an ApiError with that message in .message).
export function deleteSelf(): Promise<void> {
  return request<void>("/v1/auth/me", { method: "DELETE" });
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

// GET /v1/admin/users - every user, admin only (enforced
// server-side by requireAdmin in backend/internal/auth/admin.go; a
// non-admin caller gets a 403, surfaced here as an ApiError).
export function listUsers(): Promise<AdminUser[]> {
  return request<AdminUser[]>("/v1/admin/users");
}

// POST /v1/admin/users/{subject}/approve - flips that user's approved flag
// to true. Takes effect on their *next* login, not retroactively - see
// ApproveUserHandler's doc comment in admin.go for why.
export function approveUser(subject: string): Promise<void> {
  return request<void>(`/v1/admin/users/${encodeURIComponent(subject)}/approve`, {
    method: "POST",
  });
}

// POST /v1/admin/users/{subject}/lock - revokes an already-approved user's
// access without forgetting who they are. The backend refuses this for
// your own account or the last remaining admin (400) - surfaced here
// as an ApiError with that message in .message.
export function lockUser(subject: string): Promise<void> {
  return request<void>(`/v1/admin/users/${encodeURIComponent(subject)}/lock`, {
    method: "POST",
  });
}

// POST /v1/admin/users/{subject}/unlock - restores access for a locked
// user. No self/last-admin restriction (unlocking can't strand the
// instance the way locking or deleting could).
export function unlockUser(subject: string): Promise<void> {
  return request<void>(`/v1/admin/users/${encodeURIComponent(subject)}/unlock`, {
    method: "POST",
  });
}

// DELETE /v1/admin/users/{subject} - forgets the user row entirely. Same
// self/last-admin guard as lockUser. If this person logs in again
// later, they are JIT-provisioned as a brand-new pending user, exactly as
// if they had never logged in before.
export function deleteUser(subject: string): Promise<void> {
  return request<void>(`/v1/admin/users/${encodeURIComponent(subject)}`, {
    method: "DELETE",
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

// GET /v1/admin/smtp/status - admin only (enforced server-side by
// auth.RequireAdminMiddleware; a non-admin gets a 403, surfaced here as
// an ApiError).
export function smtpStatus(): Promise<SMTPStatus> {
  return request<SMTPStatus>("/v1/admin/smtp/status");
}

// POST /v1/admin/smtp/configure - admin only, same gate as
// smtpStatus above.
export function configureSmtp(body: SMTPConfigRequest): Promise<SMTPStatus> {
  return request<SMTPStatus>("/v1/admin/smtp/configure", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

// DELETE /v1/admin/smtp - clears the configuration entirely (all fields,
// including the encrypted password), returning the instance to "not
// configured" - same gate as smtpStatus/configureSmtp above. Distinct
// from configureSmtp with empty fields: that would still write an empty
// host/from_address and get rejected as invalid, this actually removes
// the underlying settings rows.
export function deleteSmtpConfig(): Promise<void> {
  return request<void>("/v1/admin/smtp", { method: "DELETE" });
}

// Body of POST /v1/admin/smtp/test — same fields as SMTPConfigRequest plus
// a "to" address. The configuration is NOT persisted; the backend just dials
// out immediately so the operator can verify connectivity before saving.
export interface SMTPTestRequest extends SMTPConfigRequest {
  to: string;
}

// POST /v1/admin/smtp/test — admin only. Sends a single test message
// using the supplied configuration. Returns {ok: true} on success; throws
// ApiError (502) if the SMTP connection or delivery failed.
export function testSmtp(body: SMTPTestRequest): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>("/v1/admin/smtp/test", {
    method: "POST",
    body: JSON.stringify(body),
  });
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

// GET /v1/admin/feeds — admin only.
export interface FeedImportResult {
  url: string;
  label: string;
  skipped: boolean;
  error?: string;
}

// One entry parsed from an OPML file — returned by adminParseOPML.
export interface OPMLEntry {
  url: string;
  label: string;
  already_exists: boolean;
  /** false when the feed could not be fetched/parsed during the parse step */
  reachable: boolean;
  /** short error string when reachable is false */
  reach_error?: string;
}

// POST /v1/admin/feeds/opml-parse — parses an OPML file and returns the
// list of feeds it contains (with already_exists flag) WITHOUT importing.
export async function adminParseOPML(file: File): Promise<OPMLEntry[]> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${API_BASE_URL}/v1/admin/feeds/opml-parse`, {
    method: "POST",
    credentials: "include",
    headers: csrfHeaders("POST"),
    body: form,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new ApiError(res.status, text || res.statusText);
  }
  return res.json();
}

// POST /v1/admin/feeds/import — imports a user-selected list of feeds (JSON body).
export function adminImportFeeds(feeds: OPMLEntry[]): Promise<FeedImportResult[]> {
  return request<FeedImportResult[]>("/v1/admin/feeds/import", {
    method: "POST",
    body: JSON.stringify({ feeds }),
  });
}

// GET /v1/admin/feeds/catalog — without lang: returns {languages: string[]}.
// With ?lang=DE: returns []OPMLEntry with reachable + already_exists populated
// (reachability check runs server-side, takes a few seconds).
export function adminFetchCatalogLanguages(): Promise<{ languages: string[] }> {
  return request<{ languages: string[] }>("/v1/admin/feeds/catalog");
}

export function adminFetchCatalogByLang(lang: string): Promise<OPMLEntry[]> {
  return request<OPMLEntry[]>(`/v1/admin/feeds/catalog?lang=${encodeURIComponent(lang)}`);
}

export interface FeedCheckResult {
  reachable: boolean;
  article_count: number;
  has_images: boolean;
  error?: string;
}

// POST /v1/admin/feeds/check — checks reachability and image support without saving.
export function adminCheckFeed(url: string): Promise<FeedCheckResult> {
  return request<FeedCheckResult>("/v1/admin/feeds/check", {
    method: "POST",
    body: JSON.stringify({ url }),
  });
}

export function adminListFeeds(): Promise<Feed[]> {
  return request<Feed[]>("/v1/admin/feeds");
}

// POST /v1/admin/feeds
export function adminCreateFeed(body: { url: string; label: string }): Promise<Feed> {
  return request<Feed>("/v1/admin/feeds", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

// PATCH /v1/admin/feeds/{id}
export function adminUpdateFeed(
  id: number,
  body: { url: string; label: string },
): Promise<void> {
  return request<void>(`/v1/admin/feeds/${id}`, {
    method: "PATCH",
    body: JSON.stringify(body),
  });
}

// DELETE /v1/admin/feeds/{id}
export function adminDeleteFeed(id: number): Promise<void> {
  return request<void>(`/v1/admin/feeds/${id}`, { method: "DELETE" });
}

// GET /v1/feeds — all approved users; returns feeds with enabled flag.
export function listFeeds(): Promise<Feed[]> {
  return request<Feed[]>("/v1/feeds");
}

// PATCH /v1/feeds/{id}/subscription
export function setFeedSubscription(id: number, enabled: boolean): Promise<void> {
  return request<void>(`/v1/feeds/${id}/subscription`, {
    method: "PATCH",
    body: JSON.stringify({ enabled }),
  });
}

// GET /v1/news — aggregated articles from user's enabled feeds.
export function getNews(): Promise<NewsArticle[]> {
  return request<NewsArticle[]>("/v1/news");
}

// Admin-controlled display config returned by GET /v1/news/config.
export interface NewsConfig {
  home_count: number;
  show_images: boolean;
}

// GET /v1/news/config — returns global display settings for authenticated users.
export function getNewsConfig(): Promise<NewsConfig> {
  return request<NewsConfig>("/v1/news/config");
}

// Admin news settings (GET/PATCH /v1/admin/news/settings).
export interface AdminNewsSettings {
  max_articles: number;
  home_count: number;
  show_images: boolean;
}

// GET /v1/admin/news/settings
export function adminGetNewsSettings(): Promise<AdminNewsSettings> {
  return request<AdminNewsSettings>("/v1/admin/news/settings");
}

// PATCH /v1/admin/news/settings — partial update.
export function adminUpdateNewsSettings(
  body: Partial<AdminNewsSettings>,
): Promise<AdminNewsSettings> {
  return request<AdminNewsSettings>("/v1/admin/news/settings", {
    method: "PATCH",
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

export interface WeatherLocation {
  city: string; // e.g. "Frankfurt am Main" — for tight inline spots
  label: string; // e.g. "Frankfurt am Main, Deutschland" — for the detail panel
}

// GET /v1/widgets/weather/location — reverse-geocodes the same lat/lon into
// a short place name via Nominatim. Same trust model as getWeather above
// (no auth). Called alongside getWeather, not merged into its response,
// since the two have very different cache lifetimes on the backend (15min
// vs 24h) and a failure here should not take the temperature/forecast down
// with it.
export function getWeatherLocation(lat: number, lon: number): Promise<WeatherLocation> {
  return request<WeatherLocation>(
    `/v1/widgets/weather/location?lat=${lat.toFixed(4)}&lon=${lon.toFixed(4)}`,
  );
}

// GET /v1/widgets/weather/geo-config — admin-configurable timeout (ms) for
// the browser's navigator.geolocation.getCurrentPosition() call (see
// AdminLimitsHandler's geo_timeout_ms field). Same trust model as getWeather
// above (no auth) - Home.tsx needs this *before* it can even request a
// position fix, so it can't ride along with getWeather/getWeatherLocation.
export interface WeatherGeoConfig {
  geo_timeout_ms: number;
}

export function getWeatherGeoConfig(): Promise<WeatherGeoConfig> {
  return request<WeatherGeoConfig>("/v1/widgets/weather/geo-config");
}

// --- Web search providers --------------------------------------------------
// Mirrors backend/internal/search's JSON shapes. Web search can be backed by
// more than one provider now (SearXNG, Serper.dev, ...) - see that
// package's doc comment. Replaces the old single-provider SearXNG-only API
// (searxngStatus/configureSearxng/deleteSearxngConfig).

// Admin view: full provider details.
export interface SearchProvider {
  id: string;
  type: string;
  name: string;
  base_url?: string;
  has_admin_key: boolean;
  max_results: number;
  fetch_pages: number;
  user_can_override: boolean;
  enabled: boolean;
  sort_order: number;
}

// GET /v1/admin/search/providers — admin only.
export function adminListSearchProviders(): Promise<SearchProvider[]> {
  return request<SearchProvider[]>("/v1/admin/search/providers");
}

// PATCH /v1/admin/search/providers/{id} — admin only. Only send
// admin_key when the admin actually typed a new one - omitting it (or
// sending "") leaves the stored key untouched, matching UpdateSearchProvider's
// COALESCE-on-conflict behavior on the backend.
export function adminPatchSearchProvider(
  id: string,
  patch: Partial<{
    base_url: string;
    admin_key: string;
    max_results: number;
    fetch_pages: number;
    user_can_override: boolean;
    enabled: boolean;
    sort_order: number;
  }>,
): Promise<SearchProvider> {
  return request<SearchProvider>(`/v1/admin/search/providers/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

// DELETE /v1/admin/search/providers/{id}/key — admin only. Clears the
// admin key without touching the rest of the provider row.
export function adminClearSearchProviderKey(id: string): Promise<void> {
  return request<void>(`/v1/admin/search/providers/${encodeURIComponent(id)}/key`, {
    method: "DELETE",
  });
}

// Which provider is primary/fallback, and the two shared search timeouts.
export interface SearchSettings {
  primary_provider_id: string;
  fallback_provider_id: string;
  timeout_seconds: number;
  fallback_timeout_seconds: number;
}

// GET /v1/admin/search/settings — admin only.
export function adminGetSearchSettings(): Promise<SearchSettings> {
  return request<SearchSettings>("/v1/admin/search/settings");
}

// PATCH /v1/admin/search/settings — admin only.
export function adminPatchSearchSettings(settings: SearchSettings): Promise<SearchSettings> {
  return request<SearchSettings>("/v1/admin/search/settings", {
    method: "PATCH",
    body: JSON.stringify(settings),
  });
}

// User view: whether a provider is usable, and whether the user has their
// own key stored for it — no secret material ever included.
export interface UserSearchProvider {
  id: string;
  name: string;
  type: string;
  enabled: boolean;
  available: boolean;
  has_user_key: boolean;
  has_admin_key: boolean;
  can_override: boolean;
}

// GET /v1/search/providers — any approved session.
export function listSearchProvidersForUser(): Promise<UserSearchProvider[]> {
  return request<UserSearchProvider[]>("/v1/search/providers");
}

// PUT /v1/user/search/keys/{id} — any approved session. Only allowed for
// providers with can_override = true (e.g. Serper, not SearXNG).
export function setUserSearchKey(providerId: string, key: string): Promise<void> {
  return request<void>(`/v1/user/search/keys/${encodeURIComponent(providerId)}`, {
    method: "PUT",
    body: JSON.stringify({ key }),
  });
}

// DELETE /v1/user/search/keys/{id} — any approved session.
export function deleteUserSearchKey(providerId: string): Promise<void> {
  return request<void>(`/v1/user/search/keys/${encodeURIComponent(providerId)}`, {
    method: "DELETE",
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
  query: string,
  category: SearchCategory = "general",
  timeRange: SearchTimeRange = "",
): Promise<WebResult[]> {
  const params = new URLSearchParams({ q: query, category });
  if (timeRange) params.set("time_range", timeRange);
  return request<WebResult[]>(`/v1/search/web?${params.toString()}`);
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
export function getSearchPrefs(): Promise<SearchPrefs> {
  return request<SearchPrefs>("/v1/user/search-prefs");
}

// POST /v1/user/search-prefs — any approved session.
export function updateSearchPrefs(body: Partial<SearchPrefs>): Promise<SearchPrefs> {
  return request<SearchPrefs>("/v1/user/search-prefs", {
    method: "POST",
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

// GET /v1/admin/ai/providers — admin only.
export function adminListAIProviders(): Promise<AIProvider[]> {
  return request<AIProvider[]>("/v1/admin/ai/providers");
}

// POST /v1/admin/ai/providers — admin only.
export function adminCreateAIProvider(body: {
  id: string;
  type: string;
  name: string;
  base_url?: string;
  admin_key?: string;
  default_model: string;
  user_can_override: boolean;
  enabled: boolean;
  sort_order: number;
}): Promise<AIProvider> {
  return request<AIProvider>("/v1/admin/ai/providers", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

// PATCH /v1/admin/ai/providers/{id} — admin only.
export function adminPatchAIProvider(
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
    body: JSON.stringify(body),
  });
}

// DELETE /v1/admin/ai/providers/{id} — admin only.
export function adminDeleteAIProvider(id: string): Promise<void> {
  return request<void>(`/v1/admin/ai/providers/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

// DELETE /v1/admin/ai/providers/{id}/key — clears admin key only.
export function adminClearAIProviderKey(id: string): Promise<void> {
  return request<void>(`/v1/admin/ai/providers/${encodeURIComponent(id)}/key`, {
    method: "DELETE",
  });
}

// GET /v1/admin/ai/providers/{id}/models — fetches available models from the provider API.
export async function adminFetchAIProviderModels(id: string): Promise<string[]> {
  const result = await request<{ models: string[] }>(
    `/v1/admin/ai/providers/${encodeURIComponent(id)}/models`,
  );
  return result.models ?? [];
}

export interface AIBalanceResult {
  supported: boolean;
  currency?: string;
  amount?: number;
  error?: string;
}

export async function adminFetchAIProviderBalance(id: string): Promise<AIBalanceResult> {
  return request<AIBalanceResult>(`/v1/admin/ai/providers/${encodeURIComponent(id)}/balance`);
}

// LimitsSettings mirrors backend/internal/adminapi/limits.go's
// LimitsSettings — the cross-cutting operational limits (upload/body size
// caps, rate limits, Deno worker pool size) that used to be hardcoded Go
// constants scattered across several packages. See that file's doc comment
// for the incident (module photo uploads silently capped at ~1 MB) that
// led to consolidating them behind one endpoint.
//
// deno_conn_pool_size is the only field here that needs a module
// restart/update to take effect — every other field applies immediately.
export interface LimitsSettings {
  max_body_bytes: number;
  max_upload_body_bytes: number;
  max_module_zip_bytes: number;
  max_opml_upload_bytes: number;
  auth_rate_limit_max: number;
  ai_chat_ip_rate_limit_max: number;
  global_rate_limit_max: number;
  deno_conn_pool_size: number;
  geo_timeout_ms: number;
  ai_provider_timeout_seconds: number;
  search_timeout_seconds: number;
  search_fallback_timeout_seconds: number;
  news_fetch_timeout_seconds: number;
  store_sync_interval_seconds: number;
  store_github_api_timeout_seconds: number;
  modules_install_download_timeout_seconds: number;
  chat_rpm_limit: number;
  // core_update_check_weekdays: comma-separated weekday integers
  // (0=Sunday..6=Saturday, matching JS Date.getDay()/backend time.Weekday)
  // naming which days coreupdate.RunScheduler checks GitHub for a newer
  // modulab-core release. Default "0,1,2,3,4,5,6" (every day).
  core_update_check_weekdays: string;
  // core_update_check_time: "HH:MM" (24h) time of day the check above runs.
  // Default "03:00".
  core_update_check_time: string;
}

// GET /v1/admin/system/limits — admin only.
export function adminGetLimitsSettings(): Promise<LimitsSettings> {
  return request<LimitsSettings>("/v1/admin/system/limits");
}

// PATCH /v1/admin/system/limits — admin only. Always sends the full
// object (unlike adminPatchAISettings' Partial<>) since the backend
// validates and rewrites every field on each PATCH — see
// AdminLimitsHandler's doc comment.
export function adminPatchLimitsSettings(settings: LimitsSettings): Promise<LimitsSettings> {
  return request<LimitsSettings>("/v1/admin/system/limits", {
    method: "PATCH",
    body: JSON.stringify(settings),
  });
}

// POST /v1/admin/system/core-update-check — admin only. Manually
// triggers coreupdate.CheckNow instead of waiting for the next scheduled
// (core_update_check_weekdays/_time) tick — used by the "check now" button
// on both AdminSystemLimitsPage (next to the schedule fields) and
// AdminSystemInfoPage (next to the update-available banner).
export interface CoreUpdateCheckResult {
  latest_core_version?: string;
  core_update_available: boolean;
}
export function adminCheckCoreUpdateNow(): Promise<CoreUpdateCheckResult> {
  return request<CoreUpdateCheckResult>("/v1/admin/system/core-update-check", { method: "POST" });
}

export interface AIUserProvidersResponse {
  providers: AIUserProvider[];
  preferred_provider_id: string;
}

// GET /v1/ai/providers — any approved session.
export function listAIProviders(): Promise<AIUserProvidersResponse> {
  return request<AIUserProvidersResponse>("/v1/ai/providers");
}

// PATCH /v1/ai/preference — persist the user's preferred provider cross-device.
export function setAIPreferredProvider(providerId: string): Promise<void> {
  return request<void>("/v1/ai/preference", {
    method: "PATCH",
    body: JSON.stringify({ provider_id: providerId }),
  });
}

// PUT /v1/ai/keys/{id} — set own API key for a provider.
export function setAIUserKey(providerId: string, key: string): Promise<void> {
  return request<void>(`/v1/ai/keys/${encodeURIComponent(providerId)}`, {
    method: "PUT",
    body: JSON.stringify({ key }),
  });
}

// DELETE /v1/ai/keys/{id} — remove own API key (fall back to admin key).
export function deleteAIUserKey(providerId: string): Promise<void> {
  return request<void>(`/v1/ai/keys/${encodeURIComponent(providerId)}`, {
    method: "DELETE",
  });
}

// PATCH /v1/ai/keys/{id}/model — save preferred model for own key.
export function setAIUserPreferredModel(providerId: string, model: string): Promise<void> {
  return request<void>(`/v1/ai/keys/${encodeURIComponent(providerId)}/model`, {
    method: "PATCH",
    body: JSON.stringify({ model }),
  });
}

// GET /v1/ai/keys/{id}/models — fetch available models using the user's own key.
export async function fetchUserAIProviderModels(providerId: string): Promise<string[]> {
  const result = await request<{ models: string[] }>(
    `/v1/ai/keys/${encodeURIComponent(providerId)}/models`,
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
// No token parameter: raw fetch() with credentials: "include" so the
// browser attaches the __Host-modulab_session cookie, same as request() above.
// Cannot go through request() itself because that consumes the whole body as
// JSON, while this needs the raw stream - so csrfHeaders() has to be attached
// by hand here. That is easy to forget: POST /v1/ai/chat is CSRF-checked as
// of 2026-07-28 (auth.RequireActiveSession now applies the check to every
// session-guarded mutation, not just admin ones), so without this header the
// whole chat feature 403s.
export function streamAIChat(
  providerId: string,
  model: string,
  messages: ChatMessage[],
  onDelta: (text: string) => void,
  signal?: AbortSignal,
): Promise<void> {
  return fetch(`${API_BASE_URL}/v1/ai/chat`, {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...csrfHeaders("POST"),
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

export interface SystemStatus {
  oidc: OIDCStatus;
  group_prefix: string;
}

// GET /v1/admin/system — OIDC config, group prefix (read-only).
export function getSystemStatus(): Promise<SystemStatus> {
  return request<SystemStatus>("/v1/admin/system");
}

// ---- Admin system info (read-only diagnostics page) ---------------------------

export interface SystemInfoTimer {
  last_run_at?: string;
  next_run_at?: string;
  interval_seconds: number;
}

export interface SystemInfoModule {
  name: string;
  version: string;
  available_version?: string;
  status: string;
  source: string;
  pinned: boolean;
  // 1 | 2 | 3 (not plain number) so an out-of-range tier from the API is a
  // type error at the call site instead of silently flowing into TierBadge's
  // colors[tier] ?? colors[1] fallback (see ModulesPage.tsx's TierBadge).
  tier: 1 | 2 | 3;
  // cosign_verified (added 2026-07-05): whether the Cosign signature check
  // actually passed for the currently-installed version - false for
  // "direct" installs (no registry signature to check at all) and for any
  // official/community install made before this field existed.
  cosign_verified: boolean;
}

export interface ActiveSession {
  id: string;
  name?: string;
  email?: string;
  role: string;
  created_at?: string;
  ip?: string;
  // Reverse-DNS (PTR) name for ip, resolved and cached server-side
  // (resolveHostname in backend/internal/auth/session.go). Absent whenever
  // ip has no PTR record, is empty, or the lookup failed/timed out - same
  // "just omit it" treatment as country below.
  hostname?: string;
  user_agent?: string;
  // Cloudflare's CF-IPCountry header, captured once at login - absent for
  // sessions created before this field existed, or for logins that never
  // passed through Cloudflare (e.g. local/direct access).
  country?: string;
  last_active_seconds_ago?: number;
  expires_in_seconds?: number;
  current?: boolean;
}

// One active fixed-window rate-limit counter in Valkey (key
// "ratelimit:<label>:<identifier>"). Surfaced in System Info so an admin can
// see, without SSH-ing into Valkey, whether a given IP (or user, for the
// "chat" label) is currently rate-limited and when it will clear on its own.
export interface SystemInfoRateLimit {
  key: string;
  label: string;
  identifier: string;
  display_name?: string;
  count: number;
  max?: number;
  reset_in_seconds: number;
}

export interface SystemInfo {
  version: string;
  uptime_seconds: number;
  postgres_reachable: boolean;
  valkey_reachable: boolean;
  searxng_configured: boolean;
  searxng_reachable?: boolean;
  ntp_drift_ok?: boolean;
  registry_sync: SystemInfoTimer;
  modules: SystemInfoModule[];
  // cosign_available (added 2026-07-05): whether the cosign binary itself
  // is reachable on this instance. If false, every module's
  // cosign_verified is false too regardless of whether a signature
  // exists - shown separately so that doesn't read as "signature check
  // failed" when it actually means "the check couldn't run at all".
  cosign_available: boolean;
  latest_core_version?: string;
  core_update_available: boolean;
  active_sessions?: ActiveSession[];
  rate_limits?: SystemInfoRateLimit[];
  tls_cert_expires_at?: string;
  tls_cert_days_left?: number;
}

// GET /v1/admin/system/info — version/uptime, dependency reachability, and
// countdowns until the next background module-update check / registry sync.
export function getSystemInfo(): Promise<SystemInfo> {
  return request<SystemInfo>("/v1/admin/system/info");
}

// DELETE /v1/admin/sessions/{id} — ends exactly one active session (System
// Info page's per-row "end session" button). id is ActiveSession.id (a
// one-way hash), never the session's bearer token itself.
export function revokeSession(id: string): Promise<void> {
  return request<void>(`/v1/admin/sessions/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

// GET /v1/auth/sessions — self-service counterpart to getSystemInfo's
// active_sessions: every currently-active session belonging to the calling
// user only (backend's ListActiveSessionsForUser), for the Profile page's
// "my devices" section. Any approved session can call this, not just an
// admin.
export function listMySessions(): Promise<ActiveSession[]> {
  return request<ActiveSession[]>("/v1/auth/sessions");
}

// DELETE /v1/auth/sessions/{id} — self-service counterpart to revokeSession
// above: ends one of the caller's own sessions (e.g. a lost phone), not
// any other user's. 404 if id doesn't resolve to one of the caller's own
// sessions - see backend's RevokeOwnSessionByID doc comment for why that
// case is indistinguishable from "no such session" rather than a 403.
export function revokeMySession(id: string): Promise<void> {
  return request<void>(`/v1/auth/sessions/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

// DELETE /v1/admin/system/rate-limits — manually clears one rate-limit
// counter (System Info page's per-row "reset" button). key is
// SystemInfoRateLimit.key, the raw Valkey key ("ratelimit:<label>:<id>"),
// sent in the request body since it contains characters not safe for a path
// segment (colons).
export function resetRateLimit(key: string): Promise<void> {
  return request<void>("/v1/admin/system/rate-limits", {
    method: "DELETE",
    body: JSON.stringify({ key }),
  });
}

// PATCH /v1/admin/oidc — update OIDC configuration. client_secret is optional;
// omit or pass "" to keep the existing secret.
export function updateOIDC(body: {
  issuer_url: string;
  client_id: string;
  client_secret?: string;
}): Promise<OIDCStatus> {
  return request<OIDCStatus>("/v1/admin/oidc", {
    method: "PATCH",
    body: JSON.stringify(body),
  });
}

export function deleteOIDCConfig(): Promise<OIDCStatus> {
  return request<OIDCStatus>("/v1/admin/oidc", { method: "DELETE" });
}

// ---- Audit log ----------------------------------------------------------------

export interface AuditEntry {
  id: number;
  created_at: string;    // ISO-8601 timestamp
  event_type: string;
  actor_id: string;
  actor_email: string;
  // actor_name/target_name (added 2026-07-05) resolve to the account's
  // current name where the subject still matches a users row - prefer
  // these over *_email when present (see AdminAuditPage's rendering).
  actor_name?: string;
  target_id: string;
  target_email: string;
  target_name?: string;
  details: string;       // JSON string, "" if none
  prev_hash: string;
  hash: string;
}

// GET /v1/audit-log — paginated, newest first.
// event_type: filter to one event type; actor_id: filter to one actor (see
// getAuditActors); since/until: YYYY-MM-DD date range (both inclusive);
// search: case-insensitive substring match across all decrypted text fields
// (see backend AuditLogHandler's doc comment for how this is scanned);
// before: cursor (id < before); limit: page size.
export function getAuditLog(opts?: {
  event_type?: string;
  actor_id?: string;
  since?: string;
  until?: string;
  search?: string;
  before?: number;
  limit?: number;
}): Promise<AuditEntry[]> {
  const params = new URLSearchParams();
  if (opts?.event_type) params.set("event_type", opts.event_type);
  if (opts?.actor_id) params.set("actor_id", opts.actor_id);
  if (opts?.since) params.set("since", opts.since);
  if (opts?.until) params.set("until", opts.until);
  if (opts?.search) params.set("search", opts.search);
  if (opts?.before) params.set("before", String(opts.before));
  if (opts?.limit) params.set("limit", String(opts.limit));
  const qs = params.toString();
  return request<AuditEntry[]>(`/v1/audit-log${qs ? `?${qs}` : ""}`);
}

export interface AuditActor {
  id: string;
  name?: string; // "" / absent if this actor never matched a users row (e.g. an IP-keyed rate-limit entry) or no longer does
}

// GET /v1/audit-log/actors — every distinct actor that has produced an audit
// entry, for the audit page's actor filter dropdown.
export function getAuditActors(): Promise<AuditActor[]> {
  return request<AuditActor[]>("/v1/audit-log/actors");
}

export interface AuditVerifyResult {
  ok: boolean;
  entries_checked: number;
  broken_at_id?: number;
}

// GET /v1/audit-log/verify — walks the whole HMAC hash chain server-side and
// reports whether it's intact. On-demand only (not called on page load) -
// see the handler's doc comment for why.
export function verifyAuditLog(): Promise<AuditVerifyResult> {
  return request<AuditVerifyResult>("/v1/audit-log/verify");
}

// ---- User preferences -------------------------------------------------------

export interface UserPrefs {
  ui_language: string; // "en" | "de" | "" (browser default)
  theme: string; // "light" | "dark" | "system" | "" (client default, see AppShell.tsx)
}

// GET /v1/user/preferences — returns the calling user's stored UI language
// and theme preferences.
export function getUserPrefs(): Promise<UserPrefs> {
  return request<UserPrefs>("/v1/user/preferences");
}

// PATCH /v1/user/preferences — saves a partial set of preferences (e.g. just
// { theme: "dark" }). Only the keys present in `prefs` are sent, so the
// backend only touches the fields it received — see UserPrefsHandler's PATCH
// branch for why that matters (pointer fields, partial-update safe).
export function updateUserPrefs(prefs: Partial<UserPrefs>): Promise<void> {
  return request<void>("/v1/user/preferences", {
    method: "PATCH",
    body: JSON.stringify(prefs),
  });
}

// ---- Module Store -----------------------------------------------------------

// Mirrors store.Entry in backend/internal/store/registry.go.
export interface StoreEntry {
  name: string;
  source: "official" | "community" | "custom";
  source_repo: string;
  release_asset: string;
  category: string;
  latest_version: string;
  // Map of language code → short blurb, e.g. {"en": "...", "de": "..."} -
  // same shape as an installed module's manifest.display_name. Resolve with
  // an en-fallback lookup for the user's UI language (see StorePage.tsx).
  description?: Record<string, string>;
  // Map of language code → human-readable module name, same shape as
  // description - falls back to `name` (the raw module identifier) when
  // absent.
  display_name?: Record<string, string>;
  // Absolute URL to the module's logo image, or empty/absent when the
  // module ships none - render the ModuLab mark as fallback in that case
  // (see StorePage.tsx's ModuleLogo).
  logo_url?: string;
  // "View on GitHub" link target. For official modules this points at the
  // module's own subdirectory in the monorepo; absent for community
  // modules, where source_repo itself is already the right link.
  browse_url?: string;
  // Only ever set for source="custom" - the admin-entered Cosign public key
  // for that repo (see AddCustomSourceHandler). Presence here just means
  // "this source can verify"; the actual pass/fail is only known after
  // install (installed_modules.cosign_verified) - see StorePage.tsx's
  // UnverifiedBadge for how this is surfaced pre-install.
  cosign_pubkey?: string;
  manifest?: Record<string, unknown>;
  synced_at: string;
}

export interface StoreListResponse {
  entries: StoreEntry[];
  total_count: number;
  last_synced_at?: string;
}

// Mirrors db.InstalledModuleRow (with json tags) in backend/internal/db/db.go.
export interface InstalledModule {
  name: string;
  version: string;
  // 1 | 2 | 3 (not plain number) - see SystemInfoModule.tier's comment above.
  tier: 1 | 2 | 3;
  source: string;
  release_url: string;
  sha256: string;
  manifest?: Record<string, unknown>;
  status: "installing" | "active" | "degraded" | "failed" | "isolated";
  pinned: boolean;
  cached_zip_path?: string;
  available_version?: string;
  last_update_check?: string;
  logo_url?: string;
  installed_at: string;
  updated_at: string;
}

export interface ModuleUpdateInfo {
  name: string;
  installed_version: string;
  available_version: string;
  source: string;
  last_checked: string;
}

// GET /v1/store — any active session; optional ?source= and ?category= filters.
export function listStore(source?: string, category?: string): Promise<StoreListResponse> {
  const params = new URLSearchParams();
  if (source) params.set("source", source);
  if (category) params.set("category", category);
  const qs = params.toString();
  return request<StoreListResponse>(`/v1/store${qs ? `?${qs}` : ""}`);
}

// POST /v1/store/sync — admin only; triggers registry refresh.
export function syncStore(): Promise<{ ok: boolean; error?: string }> {
  return request<{ ok: boolean; error?: string }>("/v1/store/sync", { method: "POST" });
}

// ---- Custom Module Sources ---------------------------------------------------
// Admin-only "HACS-style" custom repositories on top of official/community —
// mirrors store.CustomSourceResponse in backend/internal/store/custom_sources_handlers.go.

export interface CustomSource {
  id: string;
  repo_url: string;
  name: string;
  // PEM text, or empty when the source was added without a signing key (the
  // resulting module installs as unsigned/unverified — see StorePage.tsx's
  // unverified badge).
  pubkey?: string;
  // Whether a GitHub PAT is on file for this source (for a private repo) —
  // the token itself is never sent back once saved, see
  // store.CustomSourceResponse's has_token on the backend.
  has_token: boolean;
  added_by: string;
  added_at: string;
}

// GET /v1/admin/store/custom-sources — admin only (elevated from a lower
// bar to admin-exclusive on 2026-07-22, back when a separate org-admin
// tier still existed).
export function listCustomSources(): Promise<CustomSource[]> {
  return request<CustomSource[]>("/v1/admin/store/custom-sources");
}

// POST /v1/admin/store/custom-sources — admin only, reauth-free (the
// "anlegen" case - see main.go's route registration comment).
// pubkey and token are both optional; leave pubkey empty for an
// unsigned/unverified custom source, and token empty for a public repo.
export function addCustomSource(
  repoUrl: string,
  name: string,
  pubkey: string,
  token: string,
): Promise<CustomSource> {
  return request<CustomSource>("/v1/admin/store/custom-sources", {
    method: "POST",
    body: JSON.stringify({ repo_url: repoUrl, name, pubkey, token }),
  });
}

// PATCH /v1/admin/store/custom-sources/{id} — admin only, step-up
// reauth-gated. token is omitted entirely (not sent as "") when the admin
// left it blank in the edit form - that means "keep the existing token",
// matching the SMTP/OIDC secret-field convention; sending an empty string
// would instead explicitly clear it back to a public/unauthenticated repo.
export function updateCustomSource(
  id: string,
  name: string,
  pubkey: string,
  token?: string,
): Promise<CustomSource> {
  return request<CustomSource>(`/v1/admin/store/custom-sources/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify({ name, pubkey, ...(token !== undefined ? { token } : {}) }),
  });
}

// DELETE /v1/admin/store/custom-sources/{id} — admin only, step-up
// reauth-gated (2026-07-22 - same reasoning as locking a user or deleting
// an AI provider's key).
export function deleteCustomSource(id: string): Promise<void> {
  return request<void>(`/v1/admin/store/custom-sources/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

// GET /v1/modules — any active session.
export function listInstalledModules(): Promise<InstalledModule[]> {
  return request<InstalledModule[]>("/v1/modules");
}

// GET /v1/modules/updates — admin only; runs a fresh update check.
export function checkModuleUpdates(): Promise<{ updates: ModuleUpdateInfo[]; count: number }> {
  return request<{ updates: ModuleUpdateInfo[]; count: number }>("/v1/modules/updates");
}

// POST /v1/modules/install — admin only.
export function installModule(name: string): Promise<InstalledModule> {
  return request<InstalledModule>("/v1/modules/install", {
    method: "POST",
    body: JSON.stringify({ name }),
  });
}

// POST /v1/modules/install-manual — admin only. Multipart
// upload of a module ZIP with no registry entry behind it (see
// modules.InstallManualHandler in the backend) — installs it fresh, or
// updates it in place if a module with the same name (read from the ZIP's
// own manifest.yaml) is already installed. Unlike installModule/
// updateModule, there is no signature/checksum verification against a
// registry-published one — the resulting module's source is "manual" and
// cosign_verified is always false, see StorePage.tsx's badge for this case.
export async function installManualModule(file: File): Promise<InstalledModule> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${API_BASE_URL}/v1/modules/install-manual`, {
    method: "POST",
    credentials: "include",
    headers: csrfHeaders("POST"),
    body: form,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new ApiError(res.status, text || res.statusText);
  }
  return res.json();
}

// DELETE /v1/modules/{name} — admin only.
export function uninstallModule(name: string): Promise<void> {
  return request<void>(`/v1/modules/${encodeURIComponent(name)}`, { method: "DELETE" });
}

// POST /v1/modules/{name}/update — admin only.
export function updateModule(name: string): Promise<InstalledModule> {
  return request<InstalledModule>(`/v1/modules/${encodeURIComponent(name)}/update`, {
    method: "POST",
  });
}

// POST /v1/modules/{name}/restart — admin only. Restarts the
// Deno worker from the currently-installed manifest (no version/registry
// change). Exists so a "degraded" module (crashed worker, see
// WorkerPool.SetCrashHandler in deno.go) can be recovered without an
// available update to trigger updateModule with - previously the only way
// back to "active" for a module already on its latest release was a manual
// DB update.
export function restartModule(name: string): Promise<InstalledModule> {
  return request<InstalledModule>(`/v1/modules/${encodeURIComponent(name)}/restart`, {
    method: "POST",
  });
}

// POST /v1/modules/{name}/pin — admin only.
export function pinModule(name: string): Promise<{ name: string; pinned: boolean }> {
  return request<{ name: string; pinned: boolean }>(`/v1/modules/${encodeURIComponent(name)}/pin`, {
    method: "POST",
  });
}

// DELETE /v1/modules/{name}/pin — admin only.
export function unpinModule(name: string): Promise<{ name: string; pinned: boolean }> {
  return request<{ name: string; pinned: boolean }>(`/v1/modules/${encodeURIComponent(name)}/pin`, {
    method: "DELETE",
  });
}

// ---- DSGVO / data export ----------------------------------------------------

// ---- Module API proxy -------------------------------------------------------

// moduleApiUrl returns the base URL for a module's Deno API.
// Callers append their own path, e.g. moduleApiUrl("rezepte") + "/recipes".
export function moduleApiUrl(moduleName: string): string {
  return `${API_BASE_URL}/v1/modules/${encodeURIComponent(moduleName)}/api`;
}

// Response body of GET /v1/modules/{name}/token (mirrors
// backend/internal/modules.ModuleTokenHandler's anonymous struct).
export interface ModuleTokenResponse {
  token: string;
  expires_in: number;
}

// fetchModuleToken mints a short-lived, module-scoped token
// (backend/internal/auth/moduletoken.go) for the caller's own session -
// call this once a module is confirmed active, then hand the returned
// token (never the full session) to the module's own UI bundle via
// ModuleComponentProps.token. No session token parameter needed here: the
// caller's session is identified by its httpOnly cookie, same as every
// other request() call in this file - only the module-scoped token this
// returns is ever handed to JS/module code (see moduleApiFetch below).
export function fetchModuleToken(moduleName: string): Promise<ModuleTokenResponse> {
  return request<ModuleTokenResponse>(`/v1/modules/${encodeURIComponent(moduleName)}/token`);
}

// moduleApiFetch sends an authenticated request to a module's Deno API,
// using the module-scoped token (NOT the caller's session, which stays in
// the httpOnly cookie and is never exposed to module code) - see
// moduletoken.go's package doc comment for why modules only ever get this
// narrower credential. Unlike every session-authenticated function above,
// this one still takes an explicit token parameter and attaches it via
// Authorization header, matching exactly how each installed module's own
// UI bundle (recipes/unifi-network/my-place's App.tsx `useApi`) does it.
export async function moduleApiFetch<T = unknown>(
  token: string,
  moduleName: string,
  path: string,
  init?: RequestInit,
): Promise<T> {
  const url = moduleApiUrl(moduleName) + path;
  const res = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
      Authorization: `Bearer ${token}`,
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new ApiError(res.status, text || res.statusText);
  }
  if (res.status === 204) return undefined as unknown as T;
  return res.json() as Promise<T>;
}

// GET /v1/auth/me/export — triggers a JSON file download of all personal data.
// Returns the raw Response so the caller can blob it and create an object URL.
export async function exportMyData(): Promise<Blob> {
  const res = await fetch(`${API_BASE_URL}/v1/auth/me/export`, {
    credentials: "include",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new ApiError(res.status, text || res.statusText);
  }
  return res.blob();
}
