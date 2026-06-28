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

	mu      sync.RWMutex
	workers map[string]*denoWorker
}

// NewWorkerPool creates an empty WorkerPool. Call Start for each installed
// Tier 2/3 module at startup.
func NewWorkerPool(dataDir string) *WorkerPool {
	return &WorkerPool{
		dataDir: dataDir,
		workers: make(map[string]*denoWorker),
	}
}

// Start spawns a Deno worker for the given module. entrypoint is the absolute
// path to the module's handler file (e.g. /var/lib/modulab/modules/rezepte/handlers/index.ts).
// The worker socket is placed at {dataDir}/{name}/worker.sock.
//
// If a worker for this module is already running, it is stopped first.
func (p *WorkerPool) Start(name, entrypoint string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, ok := p.workers[name]; ok {
		existing.stop()
		delete(p.workers, name)
	}

	sockPath := filepath.Join(p.dataDir, name, "worker.sock")
	// Remove stale socket file from a previous crash.
	_ = os.Remove(sockPath)

	w := &denoWorker{
		name:       name,
		entrypoint: entrypoint,
		sockPath:   sockPath,
	}
	if err := w.start(); err != nil {
		return fmt.Errorf("worker %q: start: %w", name, err)
	}

	p.workers[name] = w
	log.Printf("modules: deno worker %q started (pid %d, socket %s)", name, w.cmd.Process.Pid, sockPath)
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
type WorkerRequest struct {
	Method      string          `json:"method"`
	Path        string          `json:"path"`
	Body        json.RawMessage `json:"body,omitempty"`
	Auth        WorkerAuth      `json:"auth"`
	Credentials map[string]string `json:"credentials,omitempty"`
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
}

// ── denoWorker (internal) ─────────────────────────────────────────────────────

// denoWorker manages a single Deno subprocess.
type denoWorker struct {
	name       string
	entrypoint string
	sockPath   string

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

const listener = Deno.listen({ path: "%s", transport: "unix" });
console.log("[modulab-worker] listening on %s");

for await (const conn of listener) {
  handleConn(conn);
}

async function handleConn(conn: Deno.Conn) {
  const buf = new TextDecoder();
  const enc = new TextEncoder();
  const reader = conn.readable.getReader();
  const writer = conn.writable.getWriter();
  let partial = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      partial += buf.decode(value);
      const lines = partial.split("\n");
      partial = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.trim()) continue;
        let resp: { status: number; body: unknown };
        try {
          const req = JSON.parse(line);
          resp = await handler(req);
        } catch (e) {
          resp = { status: 500, body: { error: String(e) } };
        }
        await writer.write(enc.encode(JSON.stringify(resp) + "\n"));
      }
    }
  } catch { /* connection closed */ } finally {
    reader.releaseLock();
    writer.releaseLock();
    conn.close();
  }
}
`

// start launches the Deno subprocess using the bootstrap script.
func (w *denoWorker) start() error {
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel

	// Write the bootstrap script to a temp file so we can pass it to deno run.
	bootstrap := fmt.Sprintf(workerBootstrapScript, w.entrypoint, w.sockPath, w.sockPath)
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

	sockDir := filepath.Dir(w.sockPath)
	args := []string{
		"run",
		"--no-prompt",
		"--allow-read=" + filepath.Dir(w.entrypoint) + "," + sockDir,
		"--allow-write=" + sockDir, // Unix-domain socket (Deno 2.x: --allow-unix was removed)
		"--allow-net",              // restricted per egress_allowlist at network layer (Traefik / iptables)
		tmpScript.Name(),
	}

	w.cmd = exec.CommandContext(ctx, "deno", args...)
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
func (w *denoWorker) waitForSocket(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(w.sockPath); err == nil {
			// Socket file exists — try to connect to confirm it's listening.
			conn, err := net.Dial("unix", w.sockPath)
			if err == nil {
				conn.Close()
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
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
