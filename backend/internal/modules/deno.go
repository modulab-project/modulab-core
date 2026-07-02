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

	mu      sync.RWMutex
	workers map[string]*denoWorker
}

// NewWorkerPool creates an empty WorkerPool. Call Start for each installed
// Tier 2/3 module at startup. dbURL is the PostgreSQL connection string that
// will be passed to each Deno worker so modules can query the database.
func NewWorkerPool(dataDir, dbURL string) *WorkerPool {
	return &WorkerPool{
		dataDir: dataDir,
		dbURL:   dbURL,
		workers: make(map[string]*denoWorker),
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
		moduleRoot:     filepath.Dir(sockPath),
		egressHosts:    append([]string(nil), opts.EgressHosts...),
		jobEntrypoints: jobs,
	}
	if err := w.start(); err != nil {
		return fmt.Errorf("worker %q: start: %w", name, err)
	}

	p.workers[name] = w
	log.Printf("modules: deno worker %q started (pid %d, socket %s, egress=%v)",
		name, w.cmd.Process.Pid, sockPath, opts.EgressHosts)
	return nil
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
	opts := WorkerOptions{EgressHosts: hosts, Jobs: existing.jobEntrypoints}
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
	moduleRoot     string
	egressHosts    []string          // hostnames granted via --allow-net; empty = no network
	jobEntrypoints map[string]string // job name -> absolute .ts path, from manifest.yaml jobs:

	cmd    *exec.Cmd
	cancel context.CancelFunc

	// mu protects conn (the reusable Unix socket connection).
	mu   sync.Mutex
	conn net.Conn
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
const jobHandlers: Record<string, (ctx: { db: typeof db }) => Promise<void>> = {};
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
        let resp: { status: number; body: unknown };
        try {
          const req = JSON.parse(line);
          if (req.job) {
            // Job invocation (see JobRunner in Go's jobs.go): no HTTP
            // envelope, just { db } as the JobContext. Job handlers return
            // void — success is "didn't throw" and we report a fixed 200.
            const jobFn = jobHandlers[req.job];
            if (!jobFn) {
              resp = { status: 404, body: { error: "unknown job: " + req.job } };
            } else {
              await jobFn({ db });
              resp = { status: 200, body: { ok: true } };
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
	//   --allow-net   limited to the hostnames from the module's manifest
	//                 egress_allowlist (opts.EgressHosts). No entry = no
	//                 outbound network for this worker at all. There is no
	//                 wildcard/"allow everything" host — modules whose
	//                 destination is only known at runtime must call
	//                 ReloadEgress once the destination is known (see
	//                 WorkerResponse.RestartHosts).
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
	if len(w.egressHosts) > 0 {
		args = append(args, "--allow-net="+strings.Join(w.egressHosts, ","))
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

	// Clean up the temp script file after the process exits.
	go func() {
		_ = w.cmd.Wait()
		_ = os.Remove(tmpScript.Name())
		log.Printf("modules: deno worker %q exited", w.name)
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
