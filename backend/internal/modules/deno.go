package modules

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// WorkerPool manages one Deno subprocess per installed Tier 2/3 module.
// Each worker communicates with Core over a Unix-domain socket using a simple
// JSON-RPC-style protocol (one request object per line → one response object
// per line).
//
// The WorkerPool is created once in main.go and passed into modules.Deps.
// All public methods are safe for concurrent use.
type WorkerPool struct {
	dataDir string // /var/lib/modulab/modules — used to resolve socket paths
	dbURL   string // postgres:// URL passed to Deno workers for DB access
	// dbHost is the host:port parsed out of dbURL once at construction time.
	// Every worker's --allow-net always includes this, on top of whatever
	// the module's own manifest egress_allowlist grants: the DB connection
	// is Core-managed infrastructure (schema-isolated per module via
	// search_path, see startLocked below — that's the real access boundary
	// for the database, not the OS-level network permission), not a module
	// choosing an external destination, so it doesn't belong in the
	// module-authored egress allowlist. Without this, npm:postgres's own
	// DNS resolution of the DB hostname is blocked by the Deno sandbox
	// (getaddrinfo EPERM) even though the worker never leaves the network
	// path Core itself set up for it — hit on the first real deploy with a
	// module that had an empty egress_allowlist (2026-07-02).
	dbHost string

	// dnsResolver is the host:port every worker's --allow-net also always
	// includes, on top of dbHost and the manifest/runtime egress hosts.
	// Deno's --allow-net is a TCP-connect allowlist, but resolving *any*
	// hostname (including ones already on the allowlist, like a gateway's
	// FQDN) requires Deno's internal DNS client to reach a resolver over the
	// network first — that lookup is a separate connection the sandbox does
	// not implicitly grant just because the final destination is allowed.
	// In this Docker deployment the resolver is the embedded Docker DNS at
	// 127.0.0.11:53. Without this, Deno.resolveDns() (and any implicit
	// hostname lookup npm:postgres or fetch() performs) fails with
	// NotCapable, which unifi-network's isPrivateHost() then treats as "DNS
	// resolution failed" and fails closed (PrivateHostViolationError) even
	// though the destination itself was correctly allowlisted — hit on the
	// first deploy where all three egress hosts were already in --allow-net
	// (2026-07-02).
	dnsResolver string

	mu      sync.RWMutex
	workers map[string]*denoWorker

	// onCrash, if set, is called (in its own goroutine, never holding p.mu)
	// whenever a worker's Deno process exits on its own rather than via an
	// intentional Stop/StopAll/restart. Wired up once in main.go to mark the
	// module ModuleStatusDegraded and publish an admin notification — see
	// SetCrashHandler's doc comment for why this is deliberately "detect and
	// surface", not "detect and auto-respawn".
	onCrash func(name string)
}

// SetCrashHandler registers fn to run whenever a worker crashes (its Deno
// process exits without Stop/StopAll/a restart having been requested first).
// Must be called once, right after NewWorkerPool, before any Start.
//
// This intentionally does not attempt automatic respawning with backoff.
// Before this existed, a crashed worker just silently stayed dead until
// Core's own next restart, with installed_modules.status still reading
// "active" and nothing in the admin UI or logs pointing at it (the exit was
// only ever logged as "modules: deno worker %q exited" — indistinguishable
// from a normal Stop). A blind auto-restart loop would hide that same
// problem behind a busy-loop instead of surfacing it (e.g. a bad manifest
// change or a crashing handler would just restart forever, burning CPU,
// while still reporting "active"). Marking the module degraded and
// notifying admins puts a human in the loop to decide whether to fix and
// restart it — the safer default for a homelab instance nobody is actively
// paging on.
func (p *WorkerPool) SetCrashHandler(fn func(name string)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onCrash = fn
}

// NewWorkerPool creates an empty WorkerPool. Call Start for each installed
// Tier 2/3 module at startup. dbURL is the PostgreSQL connection string that
// will be passed to each Deno worker so modules can query the database.
func NewWorkerPool(dataDir, dbURL string) *WorkerPool {
	dbHost := ""
	if u, err := url.Parse(dbURL); err == nil {
		dbHost = u.Host // includes port, e.g. "postgres:5432" — exactly what --allow-net expects
	} else {
		log.Printf("modules: NewWorkerPool: could not parse dbURL to extract host for worker --allow-net grants: %v", err)
	}
	return &WorkerPool{
		dataDir:     dataDir,
		dbURL:       dbURL,
		dbHost:      dbHost,
		dnsResolver: "127.0.0.11:53", // Docker's embedded DNS resolver — see field doc comment
		workers:     make(map[string]*denoWorker),
	}
}

// WorkerOptions carries the module-scoped permission grant for a Deno worker.
// It is derived from the module's manifest.yaml (EgressAllowlist) and passed
// to Start so each worker gets exactly the access its manifest declares —
// never more. There is deliberately no "allow everything" sentinel here:
// modules that need a runtime-determined destination (e.g. unifi-network,
// whose gateway URLs are entered by the admin after install) must instead
// call ReloadEgress with the concrete hosts once they are known, and the
// worker is restarted with a scoped --allow-net for exactly those hosts.
// See ReloadEgress and WorkerResponse.RestartHosts.
type WorkerOptions struct {
	// EgressHosts lists the hostnames (no scheme/port) the worker's
	// --allow-net flag is scoped to. Empty = no outbound network access at
	// all for this worker.
	EgressHosts []string
	// Jobs maps job name (from manifest.yaml's jobs: list) to the absolute
	// filesystem path of that job's .ts entrypoint. Loaded once at worker
	// startup alongside the HTTP handler; JobRunner (jobs.go) dispatches to
	// these by name on its own schedule, independent of HTTP traffic.
	Jobs map[string]string
	// SkipTLSVerify, when true, scopes
	// --unsafely-ignore-certificate-errors to exactly this worker's
	// EgressHosts. For modules whose runtime destinations are private IPs
	// with no CA-issued certificate (unifi-network's gateways — see
	// unifi-client.ts). Manifest-declared per module (manifest.yaml's
	// tls_skip_verify: true), NOT a global default: most modules talk to
	// public APIs (e.g. recipes' openfoodfacts.org) where cert validation
	// must stay on.
	SkipTLSVerify bool
}

// Start spawns a Deno worker for the given module. entrypoint is the absolute
// path to the module's handler file (e.g. /var/lib/modulab/modules/rezepte/handlers/index.ts).
// The worker socket is placed at {dataDir}/{name}/worker.sock.
//
// opts scopes the worker's OS-level permissions (network egress) to what the
// module's manifest actually declares. Callers should always pass the
// manifest-derived WorkerOptions; only ReloadEgress (unifi-network's runtime
// host discovery) overrides EgressHosts after the fact.
//
// If a worker for this module is already running, it is stopped first.
func (p *WorkerPool) Start(name, entrypoint string, opts WorkerOptions) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.startLocked(name, entrypoint, opts)
}

// startLocked does the actual spawn. Caller must hold p.mu.
func (p *WorkerPool) startLocked(name, entrypoint string, opts WorkerOptions) error {
	if existing, ok := p.workers[name]; ok {
		existing.stop()
		delete(p.workers, name)
	}

	sockPath := filepath.Join(p.dataDir, name, "worker.sock")
	// Remove stale socket file from a previous crash.
	_ = os.Remove(sockPath)

	// Build a module-scoped DB URL with search_path set to the module's schema
	// first, then public. This means unqualified table names like "settings"
	// resolve to "module_vacation_spots.settings" without the handler needing to
	// schema-qualify every query.
	//
	// IMPORTANT: use the same identifier transformation as moduleIdentifiers()
	// in migrations.go (hyphens → underscores) so the schema name matches what
	// was actually created during installation.
	// Also use & instead of ? when the base URL already carries query parameters.
	moduleSchema := "module_" + strings.ReplaceAll(strings.ToLower(name), "-", "_")
	sep := "?"
	if strings.Contains(p.dbURL, "?") {
		sep = "&"
	}
	dbURL := p.dbURL + sep + "search_path=" + moduleSchema + ",public"

	jobs := opts.Jobs
	if jobs == nil {
		jobs = map[string]string{}
	}
	egressHosts := p.effectiveEgressHosts(opts.EgressHosts)
	w := &denoWorker{
		name:       name,
		entrypoint: entrypoint,
		sockPath:   sockPath,
		dbURL:      dbURL,
		// moduleRoot is {dataDir}/{name} — the common parent of both the
		// handler code (moduleRoot/handlers/...) and the worker's Unix
		// socket (moduleRoot/worker.sock, see sockPath above). Used as the
		// --allow-read/--allow-write scope instead of separately reasoning
		// about which exact sub-paths Deno.listen()'s Unix-socket bind and
		// Deno.removeSync() touch — still confined to this one module's own
		// directory, not the rest of the host.
		moduleRoot: filepath.Dir(sockPath),
		egressHosts: egressHosts,
		// moduleEgressHosts is opts.EgressHosts as passed in, WITHOUT dbHost/
		// dnsResolver mixed in — i.e. exactly the hosts a module itself
		// declared or requested via ReloadEgress. Kept separately from
		// egressHosts (the effective, infra-included list actually passed to
		// --allow-net) so callers that need to preserve "what the module
		// asked for" across an unrelated restart (see CurrentModuleEgressHosts
		// and its use in handlers.go's update-restart path) don't have to
		// guess which entries were infra vs. module-declared.
		moduleEgressHosts: append([]string(nil), opts.EgressHosts...),
		skipTLSVerify:     opts.SkipTLSVerify,
		jobEntrypoints:    jobs,
		onCrash:           p.onCrash,
	}
	if err := w.start(); err != nil {
		return fmt.Errorf("worker %q: start: %w", name, err)
	}

	p.workers[name] = w
	log.Printf("modules: deno worker %q started (pid %d, socket %s, egress=%v)",
		name, w.cmd.Process.Pid, sockPath, egressHosts)
	return nil
}

// effectiveEgressHosts prepends dbHost (if known) to manifestHosts and
// dedupes. Every worker gets the DB host regardless of what its manifest
// declares — see the dbHost field doc comment on WorkerPool for why the DB
// connection is Core infrastructure, not module-chosen egress.
func (p *WorkerPool) effectiveEgressHosts(manifestHosts []string) []string {
	seen := make(map[string]bool, len(manifestHosts)+1)
	var out []string
	add := func(h string) {
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	add(p.dbHost)
	add(p.dnsResolver)
	for _, h := range manifestHosts {
		add(h)
	}
	return out
}

// CurrentModuleEgressHosts returns the module-declared egress hosts the
// running worker for name currently has — i.e. what the manifest's
// egress_allowlist said at last start, PLUS whatever a later ReloadEgress
// call added at runtime (e.g. unifi-network gateway IPs), but WITHOUT the
// infra hosts (DB, DNS resolver) that startLocked always adds on top.
//
// Exists so a module-code update (UpdateModuleHandler in handlers.go) can
// restart the worker without silently discarding runtime-discovered egress
// hosts that aren't in the manifest at all. Before this, an update reset
// the worker to exactly mf.EgressAllowlist from the manifest — for
// unifi-network (manifest egress_allowlist: [] by design, real hosts only
// ever added via ReloadEgress) that meant every module update wiped the
// worker back to zero network access with no error or warning, and
// gateways silently stopped being pollable until an admin happened to
// re-save one (hit in production, 2026-07-02/03 — a routine module update
// to 0.3.4 pausd all three gateways overnight with no log output at all,
// since the connection attempts failed inside the sandbox before the
// handler's own error logging could run).
//
// Returns false if no worker is currently running for name.
func (p *WorkerPool) CurrentModuleEgressHosts(name string) ([]string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	w, ok := p.workers[name]
	if !ok {
		return nil, false
	}
	return append([]string(nil), w.moduleEgressHosts...), true
}

// ReloadEgress restarts the worker for name with an updated egress host list,
// keeping the same entrypoint. Used by modules whose outbound targets are
// only known at runtime (e.g. unifi-network gateway base URLs entered by an
// admin after install) — see WorkerResponse.RestartHosts. No-op if the
// worker is not currently running.
func (p *WorkerPool) ReloadEgress(name string, hosts []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	existing, ok := p.workers[name]
	if !ok {
		return ErrWorkerNotFound
	}
	entrypoint := existing.entrypoint
	// SkipTLSVerify must be carried over from the existing worker — it is
	// manifest-derived, not something ReloadEgress's caller (a module
	// handler reacting to a gateway create/update) passes in. Losing it on
	// reload would silently re-enable cert validation for the same private
	// IPs on every gateway save, breaking exactly the case this option
	// exists for.
	opts := WorkerOptions{EgressHosts: hosts, Jobs: existing.jobEntrypoints, SkipTLSVerify: existing.skipTLSVerify}
	if err := p.startLocked(name, entrypoint, opts); err != nil {
		return fmt.Errorf("reload egress for %q: %w", name, err)
	}
	log.Printf("modules: deno worker %q reloaded with egress=%v", name, hosts)
	return nil
}

// Stop gracefully shuts down the worker for the given module.
// Returns nil if no worker is running for that module.
func (p *WorkerPool) Stop(name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	w, ok := p.workers[name]
	if !ok {
		return nil
	}
	w.stop()
	delete(p.workers, name)
	log.Printf("modules: deno worker %q stopped", name)
	return nil
}

// StopAll shuts down every running worker. Called on Core shutdown.
func (p *WorkerPool) StopAll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for name, w := range p.workers {
		w.stop()
		log.Printf("modules: deno worker %q stopped (shutdown)", name)
	}
	p.workers = make(map[string]*denoWorker)
}

// Dispatch sends a HandlerRequest to the worker for name and returns the
// HandlerResponse. Returns ErrWorkerNotFound when no worker is registered.
func (p *WorkerPool) Dispatch(ctx context.Context, name string, req WorkerRequest) (WorkerResponse, error) {
	p.mu.RLock()
	w, ok := p.workers[name]
	p.mu.RUnlock()

	if !ok {
		return WorkerResponse{}, ErrWorkerNotFound
	}
	return w.dispatch(ctx, req)
}

// egressHostsQueryTimeout bounds how long QueryEgressHosts waits for a
// module's EgressHostsHandler to compute its current hosts. This is a pure
// DB read (e.g. unifi-network's computeEgressHosts() selects from its own
// gateways table) — no outbound network call, so it does not need the full
// jobTimeout scheduled jobs get.
const egressHostsQueryTimeout = 10 * time.Second

// QueryEgressHosts dispatches the reserved "__compute_egress_hosts__" job
// (see ResolveJobEntrypoints/egressHostsJobName in jobs.go) to the running
// worker for name and parses its response body as a []string. Returns
// (nil, false) if the worker has no such job registered (module doesn't set
// EgressHostsHandler in its manifest, or isn't running at all) rather than
// an error — callers should treat that as "nothing to do here", not a
// failure.
//
// This exists to solve the gap CurrentModuleEgressHosts/DynamicEgress left
// open: that mechanism preserves a RUNNING worker's egress across a code
// update by asking the worker itself, but there is no running worker to ask
// immediately after Core's own process starts. QueryEgressHosts instead asks
// the module to recompute its hosts from its own persisted state (its DB
// schema), which works the same whether Core just started, a module was
// just updated, or anything else — there's no "previous worker" dependency
// at all.
func (p *WorkerPool) QueryEgressHosts(ctx context.Context, name string) ([]string, bool) {
	queryCtx, cancel := context.WithTimeout(ctx, egressHostsQueryTimeout)
	defer cancel()

	resp, err := p.Dispatch(queryCtx, name, WorkerRequest{Job: egressHostsJobName})
	if err != nil {
		// ErrWorkerNotFound or a transport error — nothing to reload with.
		return nil, false
	}
	if resp.Status == http.StatusNotFound {
		// Worker has no egressHostsJobName entry — module doesn't set
		// EgressHostsHandler. Not an error, just "this module doesn't use
		// this feature".
		return nil, false
	}
	if resp.Status >= 400 {
		log.Printf("modules: %q: egress hosts query failed (status %d): %s", name, resp.Status, string(resp.Body))
		return nil, false
	}
	var hosts []string
	if err := json.Unmarshal(resp.Body, &hosts); err != nil {
		log.Printf("modules: %q: egress hosts query returned unparseable body: %v", name, err)
		return nil, false
	}
	return hosts, true
}

// Running reports whether a worker is currently registered for the module.
func (p *WorkerPool) Running(name string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.workers[name]
	return ok
}

// ErrWorkerNotFound is returned when Dispatch is called for a module with no
// running worker.
var ErrWorkerNotFound = errors.New("modules: no running worker for this module")

// ── WorkerRequest / WorkerResponse ───────────────────────────────────────────

// WorkerRequest is the JSON object sent to the Deno worker on each request.
// It mirrors the HandlerRequest interface in the module SDK.
//
// Two shapes travel over the same socket protocol:
//   - HTTP requests: Method/Path/Body/Auth set, Job empty. Dispatched to the
//     module's default HTTP handler (unchanged from before).
//   - Job invocations: Job set to the job name from manifest.yaml (e.g.
//     "poll_gateways"), everything else empty. Dispatched to
//     jobs/{handler-path-from-manifest}.ts's default export, called with a
//     JobContext ({ db }) instead of a HandlerRequest. See JobRunner in
//     jobs.go for the Go-side scheduler that sends these.
type WorkerRequest struct {
	Method      string            `json:"method,omitempty"`
	Path        string            `json:"path,omitempty"`
	Body        json.RawMessage   `json:"body,omitempty"`
	Auth        WorkerAuth        `json:"auth"`
	Credentials map[string]string `json:"credentials,omitempty"`
	// Job, when set, identifies this as a scheduled-job invocation rather
	// than an HTTP request. Value is the job's manifest name.
	Job string `json:"job,omitempty"`
}

// WorkerAuth carries the already-verified session context to the handler.
type WorkerAuth struct {
	UserID    string   `json:"userId"`
	UserEmail string   `json:"userEmail"`
	UserName  string   `json:"userName"`
	Roles     []string `json:"roles"`
	Scopes    []string `json:"scopes"`
}

// WorkerResponse is what the Deno worker sends back.
type WorkerResponse struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
	// RestartHosts, when non-nil, asks Core to restart this worker with the
	// given egress host list. Set by module handlers (via the SDK's
	// requestEgressReload() helper) after writing a new runtime destination
	// to the database — e.g. unifi-network's createGateway/updateGateway
	// call this so the freshly-added gateway host is actually reachable
	// on the next request. An empty (non-nil) slice restart the worker
	// with no network access at all.
	RestartHosts []string `json:"restartHosts,omitempty"`
	// Notifications, when non-empty, asks Core to publish each one to
	// notify.AdminChannel() so every connected admin session's SSE stream
	// (auth/events.go) picks it up live — the same delivery path used for
	// "user.pending" and "module.updates_available". Added for
	// asynchronous, job-triggered events a module discovers with no admin
	// currently watching (e.g. unifi-network's poll_gateways cron
	// auto-adopting a device, or a gateway flipping to paused) — unlike an
	// HTTP-handler-triggered change (e.g. approving a device), which the
	// requesting admin already sees synchronously in that request's own
	// response and does not need a separate notification for. See
	// ModuleNotification's doc comment for why the payload carries
	// pre-rendered text rather than a type+data pair Core would interpret.
	Notifications []ModuleNotification `json:"notifications,omitempty"`
	// AuditEvents, when non-empty, asks Core to append one entry per event
	// to the central audit_log (internal/audit) — e.g. a RADIUS module
	// recording "account_created"/"account_deleted" for its own accounts.
	// This is the Core-side half of the module audit bridge; no module SDK
	// helper calls this yet (module code is out of scope here), but the
	// wire format and Core-side enforcement are in place so a module only
	// needs to add AuditEvents to the JSON it already returns. See
	// ModuleAuditEvent's doc comment for the trust boundary: neither the
	// event-type prefix nor the actor identity is taken from the module.
	AuditEvents []ModuleAuditEvent `json:"auditEvents,omitempty"`
}

// ModuleAuditEvent is a single audit_log entry a module handler wants Core
// to record on its behalf, carried in WorkerResponse.AuditEvents.
//
// Trust boundary — deliberately asymmetric between fields:
//
//   - EventType is NOT used verbatim. ModuleProxyHandler (router.go) always
//     rewrites it to "module.<moduleName>.<EventType>" before writing, and
//     rejects the event entirely if EventType contains anything outside
//     [a-z0-9_.] (see moduleAuditEventSuffix in router.go). This makes it
//     impossible for a module — compromised, buggy, or malicious — to write
//     an entry into Core's own event-type namespace (e.g. "user.approved",
//     "config.smtp"); the "module.<name>." prefix is structural, not a
//     convention the module could opt out of.
//   - ActorID/ActorEmail are NOT read from this struct at all. Core already
//     knows who made the request (the session ModuleProxyHandler validated
//     before ever reaching Deno), so the actor of a module audit event is
//     always the calling user. A module has no field through which it could
//     attribute its action to a different user.
//   - TargetID/TargetEmail/Details ARE module-supplied, since only the
//     module knows what its own action affected (e.g. which RADIUS account
//     was created). Details is truncated to a fixed cap before writing
//     (see maxModuleAuditDetailsLen, router.go) since audit_log is
//     append-only and never pruned.
type ModuleAuditEvent struct {
	EventType   string `json:"eventType"`
	TargetID    string `json:"targetId,omitempty"`
	TargetEmail string `json:"targetEmail,omitempty"`
	Details     string `json:"details,omitempty"`
}

// ModuleNotification is a single event a module's job or handler wants
// surfaced to every connected admin, dispatched via WorkerResponse.
// Notifications.
//
// Message carries the FULLY RENDERED text in every language ModuLab's UI
// supports ({"de": "...", "en": "..."}), not a type key + raw data for Core
// to translate — deliberately, so that adding module notifications never
// requires a Core change. An earlier version of this feature had Core's own
// de.json/en.json hardcode per-module, per-event translation strings (e.g.
// "unifi-network.gateway_paused": "Gateway {{gatewayName}} paused..."),
// which directly violated the module system's core promise: a module
// should be independently developable without ever touching Core. The
// module already has its own locales/de.json + en.json (see
// GetEncKey/getGatewayName-style helpers) — it renders its own strings
// using its own translations and just hands Core the finished text to
// display. Core does not parse, template, or otherwise interpret Message;
// it only picks the entry matching the viewing admin's UI language client-
// side (falling back to "en" if the admin's language isn't present).
type ModuleNotification struct {
	Message map[string]string `json:"message"`
	// ActionPath, when set, is where Core navigates to if the admin clicks
	// this notification's action button (e.g. "/modules/unifi-network" or
	// "/modules/unifi-network?view=pending"). Same reasoning as Message:
	// Core has no route table for modules, so it cannot derive a sensible
	// destination itself — it previously hardcoded every module
	// notification's click target to "/admin/modules/installed" (the
	// installed-modules list), which is rarely where an admin actually
	// needs to go to act on the notification (reported 2026-07-04: clicking
	// "review" on a device-approval notification landed on the module list,
	// not the module's own pending-devices view). The module knows its own
	// routes, so it supplies the path; Core just navigates there without
	// interpreting it. Falls back to "/admin/modules/installed" if empty,
	// for notifications that genuinely have no more specific destination
	// (e.g. "module.updates_available", still built by Core itself).
	ActionPath string `json:"actionPath,omitempty"`
}

// ── denoWorker (internal) ─────────────────────────────────────────────────────

// denoWorker manages a single Deno subprocess.
type denoWorker struct {
	name       string
	entrypoint string
	sockPath   string
	dbURL      string
	// moduleRoot is {dataDir}/{name} — the --allow-read/--allow-write scope.
	// Covers both the handler code under moduleRoot/handlers/... and the
	// worker's own Unix socket at moduleRoot/worker.sock.
	moduleRoot string
	egressHosts    []string // hostnames granted via --allow-net (includes dbHost/dnsResolver); empty = no network
	// moduleEgressHosts is egressHosts minus the infra hosts (dbHost,
	// dnsResolver) — see the field doc comment where this is set in
	// startLocked.
	moduleEgressHosts []string
	skipTLSVerify     bool              // manifest tls_skip_verify: true — see WorkerOptions.SkipTLSVerify
	jobEntrypoints    map[string]string // job name -> absolute .ts path, from manifest.yaml jobs:

	cmd    *exec.Cmd
	cancel context.CancelFunc

	// onCrash is copied from the owning WorkerPool at construction time (see
	// startLocked) so the Wait goroutine in start() can call it without
	// needing a back-reference to the pool itself.
	onCrash func(name string)

	// mu protects conn (the reusable Unix socket connection) and stopping.
	mu       sync.Mutex
	conn     net.Conn
	stopping bool // set by stop() before cancel(); distinguishes an intentional stop from a crash
}

// workerBootstrapScript is the small Deno bootstrap that wraps the module's
// default export and listens on a Unix domain socket. Each line on the socket
// is a JSON WorkerRequest; the worker responds with a JSON WorkerResponse.
//
// The bootstrap keeps a single persistent connection open; Core reconnects if
// the connection drops. A real IPC bus with multiplexing (e.g. JSON-RPC 2.0
// with id fields) would be the next step, but this synchronous line-protocol
// is simple and correct for a single-instance homelab.
const workerBootstrapScript = `
import handler from "%s";
import postgres from "npm:postgres@3";

const enc = new TextEncoder();
const dec = new TextDecoder();

// DB client — shared across all requests in this worker process.
const sql = postgres(Deno.env.get("MODULAB_DB_URL") ?? "");

// ModuleDbClient adapter that wraps the postgres.js client.
//
// Note on sql.unsafe(): despite the name, sql.unsafe(sqlStr, params) still
// sends params as real bind parameters over the wire protocol — it does not
// concatenate them into the query string. "Unsafe" refers to sqlStr itself
// being a plain string instead of a tagged template, which is required here
// because module handlers build sqlStr dynamically (e.g. optional WHERE
// clauses). The actual injection risk would only appear if a handler
// concatenated user input directly into sqlStr — module code was audited
// and does not do this (params are always passed via the array). Passing
// { prepare: true } additionally opts back into prepared statements, which
// sql.unsafe disables by default.
const db = {
  async query(sqlStr: string, params: unknown[] = []): Promise<unknown[]> {
    const rows = await sql.unsafe(sqlStr, params as never[], { prepare: true });
    return rows as unknown[];
  },
};

// Job handlers this module declares in manifest.yaml's jobs: list, keyed by
// job name. Populated by Go (see denoWorker.start) as a JSON object literal
// mapping job name -> absolute path to the job's .ts entrypoint. Empty ({})
// for modules with no jobs. Loaded once at worker startup, same as the HTTP
// handler — job code runs under the exact same --allow-* grant as the HTTP
// handler, since it is the same Deno process (no separate --allow-net scope
// per job; a job that needs network access relies on the same egress hosts
// the HTTP handler was granted).
const jobEntrypoints: Record<string, string> = %s;
const jobHandlers: Record<string, (ctx: { db: typeof db }) => Promise<unknown>> = {};
for (const [jobName, path] of Object.entries(jobEntrypoints)) {
  const mod = await import(path);
  jobHandlers[jobName] = mod.default;
}

// Remove stale socket file from a previous (crashed) worker before binding.
try { Deno.removeSync("%s"); } catch { /* doesn't exist, that's fine */ }

const listener = Deno.listen({ path: "%s", transport: "unix" });
console.log("[modulab-worker] listening on %s");

// Accept loop using explicit accept() — avoids Deno 2.x for-await regression
// on UnixListener (os error 22 when iterating the listener as async iterable).
async function acceptLoop() {
  while (true) {
    let conn: Deno.Conn;
    try {
      conn = await listener.accept();
    } catch {
      break; // listener closed
    }
    handleConn(conn);
  }
}

acceptLoop();

async function handleConn(conn: Deno.Conn) {
  let partial = "";
  const chunk = new Uint8Array(4096);
  try {
    while (true) {
      const n = await conn.read(chunk);
      if (n === null) break;
      partial += dec.decode(chunk.subarray(0, n));
      const lines = partial.split("\n");
      partial = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.trim()) continue;
        let resp: { status: number; body: unknown; notifications?: unknown };
        try {
          const req = JSON.parse(line);
          if (req.job) {
            // Job invocation (see JobRunner in Go's jobs.go): no HTTP
            // envelope, just { db } as the JobContext. Scheduled jobs
            // (manifest.yaml's jobs: list) return void — success is "didn't
            // throw" and we report a fixed 200/{ok:true}.
            //
            // System jobs (job names starting with "__", not declared in
            // manifest.yaml's jobs: list, dispatched by Core itself rather
            // than JobRunner's cron scheduler — e.g. "__compute_egress_hosts__",
            // see WorkerPool.QueryEgressHosts in deno.go) MAY return a value;
            // if the handler returns anything other than undefined, that
            // value becomes the response body instead of the fixed
            // {ok:true}. This keeps every existing scheduled job (which
            // returns nothing) working identically, while letting a module
            // opt into a request/response job by simply returning a value.
            //
            // Separately, ANY job (scheduled or system) can surface async
            // notifications (see WorkerResponse.Notifications in deno.go)
            // by returning an object with a "__notifications" array
            // property — pulled out here onto resp.notifications (top-level
            // JSON key, matching restartHosts' own top-level placement) so
            // Go's WorkerResponse can bind it without it also becoming part
            // of the response body. Chosen as a double-underscore-prefixed
            // property rather than reusing the whole return value, so a
            // scheduled job can both return void (the common case) AND
            // separately report notifications without also having to
            // invent a body — e.g. unifi-network's poll_gateways still
            // returns void for its normal 200/{ok:true}, but can attach
            // { __notifications: [...] } alongside that.
            const jobFn = jobHandlers[req.job];
            if (!jobFn) {
              resp = { status: 404, body: { error: "unknown job: " + req.job } };
            } else {
              const result = await jobFn({ db });
              let notifications: unknown;
              let body: unknown = result;
              if (result && typeof result === "object" && "__notifications" in result) {
                const r = result as { __notifications: unknown; [k: string]: unknown };
                notifications = r.__notifications;
                const { __notifications, ...rest } = r;
                body = Object.keys(rest).length > 0 ? rest : undefined;
              }
              resp = {
                status: 200,
                body: body === undefined ? { ok: true } : body,
                ...(notifications !== undefined ? { notifications } : {}),
              };
            }
          } else {
            resp = await handler({ ...req, db });
          }
        } catch (e) {
          resp = { status: 500, body: { error: String(e) } };
        }
        await conn.write(enc.encode(JSON.stringify(resp) + "\n"));
      }
    }
  } catch { /* connection reset / closed */ } finally {
    try { conn.close(); } catch { /* already closed */ }
  }
}
`

// start launches the Deno subprocess using the bootstrap script.
func (w *denoWorker) start() error {
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel

	// Write the bootstrap script to a temp file so we can pass it to deno run.
	jobEntrypointsJSON, err := json.Marshal(w.jobEntrypoints)
	if err != nil {
		cancel()
		return fmt.Errorf("marshal job entrypoints: %w", err)
	}
	bootstrap := fmt.Sprintf(workerBootstrapScript,
		w.entrypoint, string(jobEntrypointsJSON), w.sockPath, w.sockPath, w.sockPath)
	tmpScript, err := os.CreateTemp("", "modulab-worker-"+w.name+"-*.ts")
	if err != nil {
		cancel()
		return fmt.Errorf("create bootstrap script: %w", err)
	}
	if _, err := tmpScript.WriteString(bootstrap); err != nil {
		cancel()
		return fmt.Errorf("write bootstrap script: %w", err)
	}
	tmpScript.Close()

	// Permission scoping (replaces the previous --allow-all):
	//   --allow-read  scoped to moduleRoot ({dataDir}/{name}), covering both
	//                 the handler code (moduleRoot/handlers/...) and the
	//                 worker's own Unix socket (moduleRoot/worker.sock) — so
	//                 a handler cannot read arbitrary files on the host, but
	//                 the bootstrap script's own Deno.listen({ path:
	//                 sockPath, transport: "unix" }) call (which needs read
	//                 access to bind the socket) still works.
	//   --allow-write also scoped to moduleRoot — needed for the same
	//                 Deno.listen() call above (binding a Unix socket
	//                 creates the file) and for the bootstrap's
	//                 Deno.removeSync(sockPath) cleanup of a stale socket
	//                 left behind by a crashed previous instance. No module
	//                 code (my-place, recipes, unifi-network) itself writes
	//                 files — uploads go through Core's own
	//                 ModuleStorageHandler (router.go), which writes to disk
	//                 as Core, not as the Deno worker — but the grant is
	//                 kept at directory scope (rather than the single
	//                 worker.sock path) since Unix-socket binding needs
	//                 write access to the containing directory, not just the
	//                 not-yet-existing socket file itself. Still confined to
	//                 this one module's own directory, not the rest of the
	//                 host. Missing this caused every worker to crash with
	//                 NotCapable on Deno.listen at first deploy (2026-07-02).
	//   --allow-net   always includes "unix:" + sockPath (the worker's own
	//                 Unix socket, see sockPath above), plus the hostnames
	//                 from the module's manifest egress_allowlist
	//                 (opts.EgressHosts). No egress-host entry = no outbound
	//                 TCP for this worker at all, but the socket grant is
	//                 unconditional. There is no wildcard/"allow everything"
	//                 host — modules whose destination is only known at
	//                 runtime must call ReloadEgress once the destination is
	//                 known (see WorkerResponse.RestartHosts).
	//                 The unix-socket grant became necessary after the Deno
	//                 2.9.0 upgrade (was 2.3.6): Deno.listen({transport:
	//                 "unix"}) now also gates on --allow-net for the exact
	//                 socket path ("unix:<path>"), on top of the
	//                 --allow-read/--allow-write above, which used to be
	//                 sufficient on their own. Without this every worker
	//                 failed at Deno.listen with "NotCapable: Requires net
	//                 access to \"unix:.../worker.sock\"" regardless of
	//                 whether the module had any egress hosts at all.
	//   --allow-env   limited to MODULAB_DB_URL/MODULAB_ENCRYPTION_KEY (what
	//                 a module could plausibly need) plus a "PG*" prefix
	//                 wildcard. The PG* grant isn't for the module's own
	//                 code — it's because npm:postgres (the DB client
	//                 every worker imports, see workerBootstrapScript)
	//                 unconditionally probes PGHOST, PGPORT, PGDATABASE,
	//                 PGUSER(NAME), PGPASSWORD, PGAPPNAME,
	//                 PGTARGETSESSIONATTRS, and one PG<option> variable per
	//                 connection default (PGMAX, PGIDLE_TIMEOUT,
	//                 PGCONNECT_TIMEOUT, PGMAX_LIFETIME, PGMAX_PIPELINE,
	//                 PGBACKOFF, PGKEEP_ALIVE, PGPREPARE, PGDEBUG,
	//                 PGFETCH_TYPES, PGPUBLICATIONS — see parseOptions in
	//                 postgres.js's src/index.js) while parsing connection
	//                 options, regardless of whether MODULAB_DB_URL already
	//                 specifies everything. Deno's env permission check
	//                 fires on the *read attempt*, not on whether the
	//                 variable is actually set, so every worker crashed on
	//                 startup with NotCapable for PGMAX before this was
	//                 added (2026-07-02, first real deploy of the sandbox).
	//                 None of these PG* variables are ever set in Core's own
	//                 environment, so this is "may ask for values that don't
	//                 exist", not an actual credential leak — the real
	//                 secrets (DB root password, SMTP, OIDC client secret)
	//                 are still excluded, same as before.
	args := []string{
		"run",
		"--no-prompt",
		"--allow-read=" + w.moduleRoot,
		"--allow-write=" + w.moduleRoot,
		"--allow-env=MODULAB_DB_URL,MODULAB_ENCRYPTION_KEY,PG*",
	}
	netGrants := append([]string{"unix:" + w.sockPath}, w.egressHosts...)
	args = append(args, "--allow-net="+strings.Join(netGrants, ","))
	// unifi-network's gateways are addressed by private IP (2026-07-02
	// decision — see unifi-client.ts's unifiFetch comment): a controller
	// reachable only on a private IP has no public FQDN to hold a CA-issued
	// certificate against, so its self-signed/private-CA cert can never pass
	// Deno's default TLS validation. Rather than disabling cert validation
	// process-wide, scope --unsafely-ignore-certificate-errors to exactly
	// the same host list as --allow-net: a compromised module handler still
	// cannot use this to talk to (or spoof) hosts outside its own egress
	// grant, it can only skip cert-chain validation for hosts it was already
	// allowed to reach. dbHost/dnsResolver are deliberately included too —
	// harmless (neither serves TLS), simpler than excluding them.
	if len(w.egressHosts) > 0 && w.skipTLSVerify {
		args = append(args, "--unsafely-ignore-certificate-errors="+strings.Join(w.egressHosts, ","))
	}
	args = append(args, tmpScript.Name())

	w.cmd = exec.CommandContext(ctx, "deno", args...)
	// Deliberately not os.Environ(): the worker only receives the handful of
	// variables it was granted via --allow-env above, plus its own scoped DB
	// URL. Everything else Core has in its environment (DB root credentials
	// if different from the module role, SMTP secrets, OIDC client secret,
	// etc.) stays invisible to module code even if a future --allow-env
	// grant were widened by mistake, since it was never in w.cmd.Env to
	// begin with.
	moduleEnv := []string{"MODULAB_DB_URL=" + w.dbURL}
	if encKey := os.Getenv("MODULAB_ENCRYPTION_KEY"); encKey != "" {
		moduleEnv = append(moduleEnv, "MODULAB_ENCRYPTION_KEY="+encKey)
	}
	w.cmd.Env = moduleEnv
	w.cmd.Stdout = &prefixWriter{prefix: "[" + w.name + "] ", w: os.Stdout}
	w.cmd.Stderr = &prefixWriter{prefix: "[" + w.name + "] ", w: os.Stderr}

	if err := w.cmd.Start(); err != nil {
		cancel()
		_ = os.Remove(tmpScript.Name())
		return fmt.Errorf("exec deno: %w", err)
	}

	// Clean up the temp script file after the process exits, and - if this
	// wasn't an intentional stop - report the crash so it doesn't pass
	// silently as an indistinguishable "exited" log line (see SetCrashHandler's
	// doc comment for why this notifies rather than auto-restarting).
	go func() {
		_ = w.cmd.Wait()
		_ = os.Remove(tmpScript.Name())
		log.Printf("modules: deno worker %q exited", w.name)

		w.mu.Lock()
		crashed := !w.stopping
		w.mu.Unlock()
		if crashed && w.onCrash != nil {
			w.onCrash(w.name)
		}
	}()

	// Wait for the socket to appear (up to 10 s).
	if err := w.waitForSocket(10 * time.Second); err != nil {
		w.stop()
		return fmt.Errorf("socket did not appear: %w", err)
	}

	return nil
}

// stop kills the Deno subprocess and closes the connection.
func (w *denoWorker) stop() {
	w.mu.Lock()
	w.stopping = true
	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
	}
	w.mu.Unlock()

	if w.cancel != nil {
		w.cancel()
	}
	_ = os.Remove(w.sockPath)
}

// dispatch sends a request and reads the response over the Unix socket.
// It reconnects automatically if the connection was dropped.
func (w *denoWorker) dispatch(ctx context.Context, req WorkerRequest) (WorkerResponse, error) {
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return WorkerResponse{}, fmt.Errorf("marshal request: %w", err)
	}
	reqBytes = append(reqBytes, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()

	// Reconnect if needed.
	if w.conn == nil {
		conn, err := net.Dial("unix", w.sockPath)
		if err != nil {
			return WorkerResponse{}, fmt.Errorf("connect to worker socket: %w", err)
		}
		w.conn = conn
	}

	// Apply context deadline.
	if dl, ok := ctx.Deadline(); ok {
		_ = w.conn.SetDeadline(dl)
	} else {
		_ = w.conn.SetDeadline(time.Now().Add(30 * time.Second))
	}

	if _, err := w.conn.Write(reqBytes); err != nil {
		// Broken pipe — close and retry once.
		_ = w.conn.Close()
		w.conn = nil
		conn, err2 := net.Dial("unix", w.sockPath)
		if err2 != nil {
			return WorkerResponse{}, fmt.Errorf("reconnect after write error: %w", err2)
		}
		w.conn = conn
		_ = w.conn.SetDeadline(time.Now().Add(30 * time.Second))
		if _, err = w.conn.Write(reqBytes); err != nil {
			return WorkerResponse{}, fmt.Errorf("write request: %w", err)
		}
	}

	line, err := bufio.NewReader(w.conn).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		_ = w.conn.Close()
		w.conn = nil
		return WorkerResponse{}, fmt.Errorf("read response: %w", err)
	}

	var resp WorkerResponse
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		return WorkerResponse{}, fmt.Errorf("unmarshal response: %w", err)
	}
	return resp, nil
}

// waitForSocket polls until the Unix socket file appears or the timeout expires.
// We only stat the file — not dial — because an immediate open+close confuses
// the Deno 2.x UnixListener and causes the next accept() to fail with os error 22.
func (w *denoWorker) waitForSocket(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(w.sockPath); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timeout after %s waiting for %s", timeout, w.sockPath)
}

// prefixWriter prefixes each write with a fixed string (for log output).
type prefixWriter struct {
	prefix string
	w      io.Writer
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	scanner := bufio.NewScanner(bufio.NewReader(
		// wrap in a reader so we can scan lines
		&bytesReader{b: b},
	))
	for scanner.Scan() {
		fmt.Fprintln(p.w, p.prefix+scanner.Text())
	}
	return len(b), nil
}

type bytesReader struct {
	b   []byte
	pos int
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}
