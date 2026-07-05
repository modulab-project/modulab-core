package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/notify"
)

// maxModuleAuditDetailsLen caps the Details field a module can attach to an
// audit event (ModuleAuditEvent) — audit_log is append-only and never
// pruned, so an unbounded module-supplied blob would grow it forever.
const maxModuleAuditDetailsLen = 2000

// moduleAuditEventSuffix is the allowed shape of the module-controlled part
// of an audit event type: lowercase alphanumerics, underscore, and dot as a
// separator. A malformed EventType is rejected outright (logged, not
// written) rather than sanitised, so it never silently becomes a different,
// unintended event. See ModuleAuditEvent's doc comment (deno.go) for the
// full trust-boundary rationale.
var moduleAuditEventSuffix = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*$`)

// recordModuleAuditEvents writes one audit_log entry per ModuleAuditEvent a
// module handler's response asked Core to record. Event type is always
// re-prefixed with "module.<moduleName>." and actor identity always comes
// from the already-verified session — never from the module's own claims.
func recordModuleAuditEvents(ctx context.Context, authDeps auth.Deps, moduleName string, sess auth.Session, events []ModuleAuditEvent) {
	for _, ev := range events {
		if !moduleAuditEventSuffix.MatchString(ev.EventType) {
			log.Printf("modules: %q: rejected audit event with invalid type %q", moduleName, ev.EventType)
			continue
		}
		details := truncateUTF8(ev.Details, maxModuleAuditDetailsLen)
		logModuleAudit(ctx, authDeps, audit.LogParams{
			EventType:   "module." + moduleName + "." + ev.EventType,
			ActorID:     sess.UserID,
			ActorEmail:  sess.Email,
			TargetID:    ev.TargetID,
			TargetEmail: ev.TargetEmail,
			Details:     details,
		})
	}
}

// truncateUTF8 cuts s to at most maxBytes bytes without splitting a
// multi-byte UTF-8 rune in half. Plain byte-slicing (s[:maxBytes]) can leave
// a truncated rune at the end, which fails Postgres's UTF-8 validation on
// insert — silently dropping the whole audit entry under the existing
// log-and-continue error handling. Backing off rune-by-rune from maxBytes
// is O(4) worst case (max UTF-8 rune width), not a real cost.
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	b := []byte(s)[:maxBytes]
	for len(b) > 0 && !utf8.RuneStart(b[len(b)-1]) {
		b = b[:len(b)-1]
	}
	return string(b)
}

// maxUploadBytes is the per-request upload cap for module image uploads.
// Separate from Core's global max_body_bytes because module storage is
// intentionally larger (images vs. JSON API payloads).
const maxUploadBytes = 20 << 20 // 20 MB

// ModuleProxyHandler returns an http.Handler that forwards every request under
// /v1/modules/{name}/* to the Deno worker for that module.
//
// Auth is verified by Core before the request reaches Deno. The handler
// populates WorkerRequest.Auth from the active session so the module code
// never has to touch tokens or cookies.
//
// File uploads (multipart/form-data with a "file" field) are intercepted here:
// the file is written to the module's storage directory and the path is passed
// to the Deno handler as Body.file_path instead of raw bytes.
func ModuleProxyHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ── Auth ──────────────────────────────────────────────────────────
		sess, ok := auth.RequireActiveSession(authDeps, w, r)
		if !ok {
			return
		}

		// ── Resolve module name from path ─────────────────────────────────
		// Path pattern: /v1/modules/{name}/*subpath
		// We strip the prefix up to and including {name}.
		moduleName := r.PathValue("name")
		if moduleName == "" {
			http.Error(w, "missing module name", http.StatusBadRequest)
			return
		}

		// The sub-path is everything after /v1/modules/{name}/api.
		// Strip both the module prefix and the /api segment so the Deno handler
		// receives clean paths like "/recipes" instead of "/api/recipes".
		subPath := strings.TrimPrefix(r.URL.Path, "/v1/modules/"+moduleName+"/api")
		if subPath == "" {
			subPath = "/"
		}
		if q := r.URL.RawQuery; q != "" {
			subPath += "?" + q
		}

		// ── Check module is active ─────────────────────────────────────────
		row, found, err := d.DB.GetInstalledModule(r.Context(), moduleName)
		if err != nil || !found {
			http.Error(w, "module not installed", http.StatusNotFound)
			return
		}
		if row.Status != "active" {
			http.Error(w, fmt.Sprintf("module is %s", row.Status), http.StatusServiceUnavailable)
			return
		}

		// ── Build WorkerAuth from session ──────────────────────────────────
		workerAuth := WorkerAuth{
			UserID:    sess.UserID,
			UserEmail: sess.Email,
			UserName:  sess.Name,
			Roles:     []string{sess.Role},
			Scopes:    []string{},
		}

		// ── Handle file uploads ────────────────────────────────────────────
		var bodyJSON json.RawMessage
		ct := r.Header.Get("Content-Type")
		mediaType, _, _ := mime.ParseMediaType(ct)

		if mediaType == "multipart/form-data" {
			savedPath, err := saveUploadedFile(r, d.DataDir, moduleName)
			if err != nil {
				http.Error(w, "file upload failed: "+err.Error(), http.StatusBadRequest)
				return
			}
			bodyJSON, _ = json.Marshal(map[string]string{"file_path": savedPath})
		} else {
			raw, _ := io.ReadAll(io.LimitReader(r.Body, 10<<20))
			if len(raw) > 0 {
				bodyJSON = json.RawMessage(raw)
			}
		}

		// ── Dispatch to Deno worker ────────────────────────────────────────
		workerReq := WorkerRequest{
			Method: r.Method,
			Path:   subPath,
			Body:   bodyJSON,
			Auth:   workerAuth,
		}

		resp, err := d.Workers.Dispatch(r.Context(), moduleName, workerReq)
		if err != nil {
			log.Printf("modules: proxy %q %s: dispatch error: %v", moduleName, subPath, err)
			if err == ErrWorkerNotFound {
				http.Error(w, "module worker not running", http.StatusServiceUnavailable)
			} else {
				http.Error(w, "module error: "+err.Error(), http.StatusBadGateway)
			}
			return
		}

		// ── Write response ─────────────────────────────────────────────────
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.Status)
		_, _ = w.Write(resp.Body)

		// ── Runtime egress reload (unifi-network and similar) ───────────────
		// A handler that just wrote a new runtime destination to its own
		// schema (e.g. createGateway/updateGateway) can ask Core to restart
		// its worker with an updated --allow-net host list by setting
		// restartHosts on its response. This runs after the response has
		// already been written to the client so the reload latency (a few
		// hundred ms for the Deno process to respawn) is not on the request
		// path; the very next module request will hit the new worker.
		if resp.RestartHosts != nil {
			go func(name string, hosts []string) {
				if err := d.Workers.ReloadEgress(name, hosts); err != nil {
					log.Printf("modules: %q: egress reload failed: %v", name, err)
				}
			}(moduleName, resp.RestartHosts)
		}

		// A handler can also surface async notifications the same way a
		// scheduled job does (see WorkerResponse.Notifications' doc
		// comment and modules.JobRunner.dispatchJob's identical publish
		// loop, jobs.go) â e.g. unifi-network's createDevice/approveDevice
		// notifying admins that a device is waiting for approval, or was
		// just approved. Published under the single generic
		// "module.notification" event type; the payload is already fully
		// rendered text (ModuleNotification.Message), so Core has nothing
		// module-specific to key on here either.
		if d.Valkey != nil {
			for _, n := range resp.Notifications {
				ev := notify.Event{Type: "module.notification", Data: map[string]any{"message": n.Message, "actionPath": n.ActionPath}}
				if err := notify.Publish(r.Context(), d.Valkey, notify.AdminChannel(), ev); err != nil {
					log.Printf("modules: %q: publish notification: %v", moduleName, err)
				}
			}
		}

		// A handler can also ask Core to record an audit_log entry for a
		// security-relevant action it just performed on its own data (e.g.
		// a RADIUS module creating/deleting an account) — see
		// ModuleAuditEvent's doc comment (deno.go) for why the event type
		// prefix and actor identity are enforced here rather than trusted
		// from the module's response.
		if len(resp.AuditEvents) > 0 {
			recordModuleAuditEvents(r.Context(), authDeps, moduleName, sess, resp.AuditEvents)
		}
	}
}

// allowedImageTypes lists the MIME types accepted for module image uploads.
var allowedImageTypes = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/webp": true,
	"image/gif":  true,
	"image/avif": true,
}

// saveUploadedFile extracts the "file" field from a multipart upload, validates
// that it is an image, and saves it to {dataDir}/{moduleName}/storage/uploads/.
// Returns a stable relative path ("uploads/{filename}") — never an absolute
// path — so that the value stored in the DB is portable across environments
// (local dev, Docker, different data dir mounts).
func saveUploadedFile(r *http.Request, dataDir, moduleName string) (string, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		return "", fmt.Errorf("parse multipart: %w", err)
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		return "", fmt.Errorf("form file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("modules: saveUploadedFile: close uploaded file: %v", err)
		}
	}()

	// Validate MIME type by reading the first 512 bytes (content sniffing).
	buf := make([]byte, 512)
	n, _ := file.Read(buf)
	detectedType := http.DetectContentType(buf[:n])
	// Seek back to start so the full file is written.
	if seeker, ok := file.(io.Seeker); ok {
		if _, err := seeker.Seek(0, io.SeekStart); err != nil {
			return "", fmt.Errorf("seek file: %w", err)
		}
	}
	// Strip parameters (e.g. "image/jpeg; charset=...") before lookup.
	mediaType, _, _ := mime.ParseMediaType(detectedType)
	if !allowedImageTypes[mediaType] {
		return "", fmt.Errorf("only image files are allowed (got %s)", detectedType)
	}

	// Sanitise filename — keep only the base name, no path traversal.
	// filepath.Base does NOT collapse ".." the way filepath.Clean/Join would
	// — for an input of exactly ".." (no slashes) it returns ".." unchanged,
	// which filepath.Join below would then resolve to uploadDir's parent
	// directory. Today that's only incidentally harmless (os.Create fails on
	// an existing directory rather than writing into it), not a deliberate
	// guarantee — reject it explicitly rather than relying on that (found
	// 2026-07-05, alongside the same class of check added to the modules'
	// own file_path validation).
	safeName := filepath.Base(header.Filename)
	if safeName == "." || safeName == ".." || safeName == "/" {
		return "", fmt.Errorf("invalid filename")
	}

	uploadDir := filepath.Join(dataDir, moduleName, "storage", "uploads")
	if err := os.MkdirAll(uploadDir, 0o750); err != nil {
		return "", fmt.Errorf("create upload dir: %w", err)
	}

	dst := filepath.Join(uploadDir, safeName)
	out, err := os.Create(dst)
	if err != nil {
		return "", fmt.Errorf("create file: %w", err)
	}
	defer func() {
		if err := out.Close(); err != nil {
			log.Printf("modules: saveUploadedFile: close %s: %v", dst, err)
		}
	}()

	if _, err := io.Copy(out, file); err != nil {
		return "", fmt.Errorf("write file: %w", err)
	}

	// Return a relative path so the DB value is portable across environments.
	// The storage handler reconstructs the absolute path from DataDir at serve time.
	return "uploads/" + safeName, nil
}

// ModuleLocaleHandler serves a module's locale file from its installed
// directory. Path: GET /v1/modules/{name}/locales/{lng}.json
//
// Auth is required (any active session) to prevent locale enumeration by
// unauthenticated clients. The file is served with Cache-Control: no-store
// so the frontend always gets the version matching the installed module.
func ModuleLocaleHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireActiveSession(authDeps, w, r); !ok {
			return
		}
		moduleName := r.PathValue("name")
		lng := r.PathValue("lng")
		if moduleName == "" || lng == "" {
			http.Error(w, "missing module name or language", http.StatusBadRequest)
			return
		}
		// Sanitise: only allow simple language codes like "en", "de", "en-US".
		for _, c := range lng {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '-' {
				http.Error(w, "invalid language code", http.StatusBadRequest)
				return
			}
		}
		localePath := filepath.Join(d.DataDir, moduleName, "locales", lng+".json")
		info, err := os.Stat(localePath)
		if err != nil || info.IsDir() {
			http.Error(w, "locale not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFile(w, r, localePath)
	}
}

// ModuleBundleHandler serves a module's compiled UI bundle.
// Path: GET /v1/modules/{name}/ui/bundle.js
//
// Auth is required. The frontend fetches the bundle via fetch() with a Bearer
// token, then loads it via a Blob URL — this avoids the limitation of dynamic
// import() not being able to send Authorization headers.
func ModuleBundleHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Loaded via fetch() with a Bearer header per the doc comment above,
		// but also reachable as a <script src> in some module-loading paths —
		// query-token fallback kept narrowly scoped to this handler and
		// ModuleStorageHandler. See auth.BearerTokenAllowQuery.
		if _, ok := auth.RequireActiveSessionAllowQueryToken(authDeps, w, r); !ok {
			return
		}
		moduleName := r.PathValue("name")
		if moduleName == "" {
			http.Error(w, "missing module name", http.StatusBadRequest)
			return
		}
		// Sanitise: only allow simple module names (alphanumeric, dash, underscore).
		for _, c := range moduleName {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				http.Error(w, "invalid module name", http.StatusBadRequest)
				return
			}
		}
		bundlePath := filepath.Join(d.DataDir, moduleName, "bundle", "bundle.js")
		info, err := os.Stat(bundlePath)
		if err != nil || info.IsDir() {
			http.Error(w, "bundle not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFile(w, r, bundlePath)
	}
}

// ModuleStorageHandler serves files from a module's storage/uploads directory.
// Path: GET /v1/modules/{name}/storage/{path...}
//
// Auth is required. Only files within the module's own storage directory are
// served; path traversal attempts are rejected by filepath.Clean.
func ModuleStorageHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// <img src="...">-loaded files cannot carry an Authorization header,
		// so this is the one place a ?t= query token is accepted — see
		// auth.BearerTokenAllowQuery for why this must stay narrowly scoped.
		if _, ok := auth.RequireActiveSessionAllowQueryToken(authDeps, w, r); !ok {
			return
		}
		moduleName := r.PathValue("name")
		filePath := r.PathValue("path")
		if moduleName == "" || filePath == "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		// Sanitise module name.
		for _, c := range moduleName {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				http.Error(w, "invalid module name", http.StatusBadRequest)
				return
			}
		}
		// Build the absolute path and verify it stays within the storage directory.
		storageRoot := filepath.Join(d.DataDir, moduleName, "storage")
		absPath := filepath.Clean(filepath.Join(storageRoot, filePath))
		if !strings.HasPrefix(absPath, storageRoot+string(filepath.Separator)) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		info, err := os.Stat(absPath)
		if err != nil || info.IsDir() {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		// Cache uploaded images for a day; they are content-addressed by filename.
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeFile(w, r, absPath)
	}
}

// RegisterModuleRoutes wires the module proxy, locale, bundle, and storage
// handlers into mux. Called from main.go after module install and at startup
// for each already-installed module.
//
// Note: the literal /v1/modules and /v1/modules/install etc. routes that
// handle the lifecycle API are registered first in main.go and take
// precedence over this wildcard because Go's 1.22 ServeMux gives more-
// specific paths priority over less-specific ones.
func RegisterModuleRoutes(mux *http.ServeMux, d Deps, authDeps auth.Deps) {
	mux.HandleFunc("GET /v1/modules/{name}/locales/{lng}", ModuleLocaleHandler(d, authDeps))
	mux.HandleFunc("/v1/modules/{name}/api/", ModuleProxyHandler(d, authDeps))
	mux.HandleFunc("GET /v1/modules/{name}/ui/bundle.js", ModuleBundleHandler(d, authDeps))
	mux.HandleFunc("GET /v1/modules/{name}/storage/{path...}", ModuleStorageHandler(d, authDeps))
}
