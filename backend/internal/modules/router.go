package modules

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/httperr"
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

// defaultMaxUploadBytes is the fallback module image-upload cap used when
// the max_upload_body_bytes setting (see MaxUploadBodyBytes) has never been
// set.
const defaultMaxUploadBytes = 20 << 20 // 20 MB

// unlimitedUploadParseMemory bounds how much of a module upload
// ParseMultipartForm buffers in memory when the configured limit is 0
// ("unlimited"). ParseMultipartForm's maxMemory parameter cannot itself be
// "unlimited" in any meaningful sense - it always needs a real number - so
// this is a fixed, generous ceiling (matching Go's own historical default
// for multipart parsing elsewhere in net/http) rather than a per-request
// unbounded buffer, regardless of what admins set max_upload_body_bytes to.
const unlimitedUploadParseMemory = 32 << 20 // 32 MB

// MaxUploadBodyBytes reads the module-upload body size cap from
// core_settings ("max_upload_body_bytes"), separate from Core's general
// max_body_bytes cap that every other route uses (see maxBodyMiddleware in
// cmd/core/main.go) — module storage (spot photos, recipe images, module
// install ZIPs, etc.) intentionally allows much larger payloads than a
// typical JSON API request. Defaults to defaultMaxUploadBytes (20 MB) if
// unset; 0 means unlimited, the same convention max_body_bytes uses.
//
// Exists because this used to be a hardcoded Go constant with no admin
// control at all — fine until a real photo upload needed to be bigger than
// whatever the constant happened to be, at which point fixing it required a
// code change and a redeploy instead of an admin settings update. See
// adminapi.AdminLimitsHandler, which exposes this alongside every other
// upload/rate/pool limit that had the same problem.
func MaxUploadBodyBytes(ctx context.Context, pool *db.Pool) int64 {
	val, ok, err := pool.GetSetting(ctx, "max_upload_body_bytes")
	if err != nil || !ok || val == "" {
		return defaultMaxUploadBytes
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil || n < 0 {
		return defaultMaxUploadBytes
	}
	return n
}

// ModuleProxyHandler returns an http.Handler that forwards every request under
// /v1/modules/{name}/* to the Deno worker for that module.
//
// Auth is verified by Core before the request reaches Deno. The handler
// populates WorkerRequest.Auth from the active session so the module code
// never has to touch tokens or cookies.
//
// File uploads (multipart/form-data with a "file" field) are intercepted here:
// the file is written to the module's storage directory, and the Deno handler
// receives both a stable relative path (Body.file_path, for persisting a
// portable DB reference) and the same content base64-encoded (Body.file_base64
// + Body.file_mime_type, 2026-07-18 addition - see saveUploadedFile/
// uploadedFile below) for modules that need to forward the upload somewhere
// else server-side without ever touching the filesystem themselves.
func ModuleProxyHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ── Resolve module name from path ─────────────────────────────────
		// Path pattern: /v1/modules/{name}/*subpath
		// We strip the prefix up to and including {name}.
		moduleName := r.PathValue("name")
		if moduleName == "" {
			http.Error(w, "missing module name", http.StatusBadRequest)
			return
		}

		// ── Auth ──────────────────────────────────────────────────────────
		// Module-scoped token only (see auth/moduletoken.go) - resolved
		// before the auth check above needs moduleName, so this moved ahead
		// of the "resolve module name" block that used to come after it. A
		// module's own API must never be reachable with the caller's full
		// session token; the frontend mints a token scoped to this exact
		// module via GET /v1/modules/{name}/token (ModuleTokenHandler) before
		// ever loading the module's bundle.
		sess, ok := auth.RequireModuleToken(authDeps, moduleName, w, r, false)
		if !ok {
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

		// ── Tier 1: generic CRUD, no Deno worker at all ─────────────────────
		// See crud.go / docs/tier1-crud-plan.md. Everything below this point
		// (file uploads, WorkerAuth, Dispatch, egress reload, notifications,
		// audit events) is Tier 2/3-only - a Tier 1 module has none of that.
		if row.Tier == 1 {
			ServeCrudRequest(w, r, d, moduleName, row.Manifest, sess)
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
			uploadLimit := MaxUploadBodyBytes(r.Context(), d.DB)
			// Reject oversized uploads before reading any body bytes, same
			// reasoning as maxBodyMiddleware's Content-Length pre-check
			// (cmd/core/main.go): letting http.MaxBytesReader trip mid-stream
			// instead aborts the connection, which any reverse proxy in
			// front of Core reports as a bare 502 rather than a real status
			// code.
			if uploadLimit > 0 && r.ContentLength > uploadLimit {
				http.Error(w, "file too large", http.StatusRequestEntityTooLarge)
				return
			}
			saved, err := saveUploadedFile(r, d.DataDir, moduleName, uploadLimit)
			if err != nil {
				http.Error(w, "file upload failed: "+err.Error(), http.StatusBadRequest)
				return
			}
			// file_base64/file_mime_type (2026-07-18, added for pantry's
			// receipt-scan feature): every module upload used to hand the
			// Deno worker only a relative file_path, on the assumption that
			// nothing ever needs the actual bytes server-side - recipes/
			// unifi-network only ever pass that path back out to the browser,
			// which re-fetches it from ModuleStorageHandler itself. That
			// assumption breaks for a module that needs to forward the
			// uploaded content somewhere else server-side (e.g. to an AI
			// vision API) - the Deno worker has no portable way to know its
			// own moduleRoot/dataDir (never passed in as an env var, and
			// hardcoding it defeats the whole point of saveUploadedFile
			// returning a relative, environment-independent path in the
			// first place, see that function's doc comment). Since Core
			// already has the bytes in hand right here, it's cheapest to
			// just include them - existing modules that only read
			// body.file_path are unaffected by the additive fields.
			bodyJSON, _ = json.Marshal(map[string]string{
				"file_path":      saved.relPath,
				"file_base64":    base64.StdEncoding.EncodeToString(saved.bytes),
				"file_mime_type": saved.mimeType,
			})
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

// allowedImageTypes lists the MIME types accepted for module uploads via
// this same generic multipart proxy - despite the name, not image-only
// anymore: application/pdf was added 2026-07-19 for pantry's receipt scan
// (a module forwards a scanned document to a vision/document-capable AI
// provider, not just a photo). Kept as one shared allowlist rather than a
// per-module one since every module upload goes through this single
// ModuleProxyHandler code path; a module that specifically needs an actual
// image (e.g. pantry's own item-photo upload, POST /items/:id/image) is
// still free to reject a non-image mimeType itself once it receives
// file_mime_type, same as any other request validation it already does.
var allowedImageTypes = map[string]bool{
	"image/jpeg":      true,
	"image/png":       true,
	"image/webp":      true,
	"image/gif":       true,
	"image/avif":      true,
	"application/pdf": true,
}

// uploadedFile is saveUploadedFile's result: everything the caller needs to
// both persist a reference to the file (relPath, unchanged behavior) and, as
// of 2026-07-18, hand the raw content to the module's own Deno handler
// without that handler ever needing filesystem access or to know its own
// absolute storage location (see the ModuleProxyHandler call site's comment).
type uploadedFile struct {
	relPath  string // e.g. "uploads/{filename}" - stable, portable, unchanged from before
	bytes    []byte // full file content, already validated as an allowed image type
	mimeType string // sniffed content type, e.g. "image/jpeg" - stripped of any ";charset=..." parameters
}

// saveUploadedFile extracts the "file" field from a multipart upload, validates
// that it is an image, and saves it to {dataDir}/{moduleName}/storage/uploads/.
// The returned relPath ("uploads/{filename}") is never an absolute path, so
// that the value stored in the DB is portable across environments (local dev,
// Docker, different data dir mounts) - the returned bytes/mimeType are for the
// caller to forward to the module's handler in the same request, not for any
// portability-sensitive persistence.
//
// limit is the caller-resolved max_upload_body_bytes value (see
// MaxUploadBodyBytes) — resolved once by the caller rather than looked up
// again here so the Content-Length pre-check and the actual read enforce
// the exact same number. 0 means unlimited.
func saveUploadedFile(r *http.Request, dataDir, moduleName string, limit int64) (uploadedFile, error) {
	parseMemory := limit
	if limit <= 0 {
		parseMemory = unlimitedUploadParseMemory
	} else {
		r.Body = http.MaxBytesReader(nil, r.Body, limit)
	}
	if err := r.ParseMultipartForm(parseMemory); err != nil {
		return uploadedFile{}, fmt.Errorf("parse multipart: %w", err)
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		return uploadedFile{}, fmt.Errorf("form file: %w", err)
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
	// Seek back to start so the full file is read/written from the beginning.
	if seeker, ok := file.(io.Seeker); ok {
		if _, err := seeker.Seek(0, io.SeekStart); err != nil {
			return uploadedFile{}, fmt.Errorf("seek file: %w", err)
		}
	}
	// Strip parameters (e.g. "image/jpeg; charset=...") before lookup.
	mediaType, _, _ := mime.ParseMediaType(detectedType)
	if !allowedImageTypes[mediaType] {
		return uploadedFile{}, fmt.Errorf("only image or PDF files are allowed (got %s)", detectedType)
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
		return uploadedFile{}, fmt.Errorf("invalid filename")
	}

	uploadDir := filepath.Join(dataDir, moduleName, "storage", "uploads")
	if err := os.MkdirAll(uploadDir, 0o750); err != nil {
		return uploadedFile{}, fmt.Errorf("create upload dir: %w", err)
	}

	dst := filepath.Join(uploadDir, safeName)
	out, err := os.Create(dst)
	if err != nil {
		return uploadedFile{}, fmt.Errorf("create file: %w", err)
	}
	defer func() {
		if err := out.Close(); err != nil {
			log.Printf("modules: saveUploadedFile: close %s: %v", dst, err)
		}
	}()

	// TeeReader so the file is written to disk and buffered into memory in
	// one pass, instead of writing it and then re-reading it back off disk -
	// the content is already fully in the kernel's page cache/multipart
	// buffer at this point, so holding one copy in memory here is not a
	// meaningfully different cost than what ParseMultipartForm already did.
	var content bytes.Buffer
	if _, err := io.Copy(out, io.TeeReader(file, &content)); err != nil {
		return uploadedFile{}, fmt.Errorf("write file: %w", err)
	}

	// Re-validate the full file against its sniffed mediaType, not just the
	// first 512 bytes DetectContentType looked at above. A small, otherwise
	// arbitrary payload can be crafted to start with valid magic bytes (a
	// "polyglot") while the rest of the file is garbage or smuggled content -
	// decoding the real structure now catches that, and also rejects a
	// decompression-bomb-style image (tiny file, absurd pixel dimensions)
	// before it reaches any downstream consumer (AI vision providers, image
	// resizing, etc.).
	if err := validateUploadedFileStructure(mediaType, content.Bytes()); err != nil {
		if rmErr := os.Remove(dst); rmErr != nil {
			log.Printf("modules: saveUploadedFile: remove rejected upload %s: %v", dst, rmErr)
		}
		return uploadedFile{}, fmt.Errorf("upload rejected: %w", err)
	}

	// Return a relative path so the DB value is portable across environments.
	// The storage handler reconstructs the absolute path from DataDir at serve time.
	return uploadedFile{relPath: "uploads/" + safeName, bytes: content.Bytes(), mimeType: mediaType}, nil
}

// maxUploadImageDimension caps the width/height (in pixels) accepted for an
// uploaded image, checked against the image's own decoded header rather
// than file size alone - a tiny file can still declare an enormous pixel
// count (a decompression bomb), which is cheap to upload but expensive for
// whatever decodes it downstream.
const maxUploadImageDimension = 12000

// validateUploadedFileStructure re-checks an uploaded file's full content
// against its sniffed mediaType, beyond the magic-byte check
// http.DetectContentType already did on only the first 512 bytes. Only
// checked for types the standard library can actually decode (jpeg/png/gif)
// plus a lightweight structural check for PDF; image/webp and image/avif
// have no std-lib decoder (a third-party dependency would be needed - not
// pulled in here without discussing it first), so those two still rely on
// the magic-byte sniff alone, same as before this check existed.
func validateUploadedFileStructure(mediaType string, data []byte) error {
	switch mediaType {
	case "image/jpeg":
		cfg, err := jpeg.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("not a valid JPEG: %w", err)
		}
		return checkUploadImageDimensions(cfg.Width, cfg.Height)
	case "image/png":
		cfg, err := png.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("not a valid PNG: %w", err)
		}
		return checkUploadImageDimensions(cfg.Width, cfg.Height)
	case "image/gif":
		cfg, err := gif.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("not a valid GIF: %w", err)
		}
		return checkUploadImageDimensions(cfg.Width, cfg.Height)
	case "application/pdf":
		if !bytes.HasPrefix(data, []byte("%PDF-")) {
			return fmt.Errorf("not a valid PDF: missing %%PDF- header")
		}
		tail := data
		if len(tail) > 2048 {
			tail = tail[len(tail)-2048:]
		}
		if !bytes.Contains(tail, []byte("%%EOF")) {
			return fmt.Errorf("not a valid PDF: missing %%%%EOF trailer")
		}
	}
	return nil
}

func checkUploadImageDimensions(width, height int) error {
	if width <= 0 || height <= 0 || width > maxUploadImageDimension || height > maxUploadImageDimension {
		return fmt.Errorf("image dimensions %dx%d out of allowed range", width, height)
	}
	return nil
}

// ModuleLocaleHandler serves a module's locale file from its installed
// directory. Path: GET /v1/modules/{name}/locales/{lng}.json
//
// Auth is required: a module-scoped token minted for this exact module (see
// auth/moduletoken.go) - same reasoning as ModuleProxyHandler, this is a
// route the module's own frontend code calls, not a host-only endpoint.
// The file is served with Cache-Control: no-store so the frontend always
// gets the version matching the installed module.
func ModuleLocaleHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		moduleName := r.PathValue("name")
		lng := r.PathValue("lng")
		if moduleName == "" || lng == "" {
			http.Error(w, "missing module name or language", http.StatusBadRequest)
			return
		}
		if _, ok := auth.RequireModuleToken(authDeps, moduleName, w, r, false); !ok {
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
// Auth is required: a module-scoped token minted for this exact module (see
// auth/moduletoken.go) - this is the file whose contents then run with full
// DOM access in the host page (ModulePage.tsx's Blob-URL import()), so it
// must never be fetchable with the caller's full session token either. The
// frontend fetches it via fetch() with a Bearer header, then loads it via a
// Blob URL — this avoids the limitation of dynamic import() not being able
// to send Authorization headers. Query-token fallback kept narrowly scoped
// to this handler and ModuleStorageHandler. See auth.BearerTokenAllowQuery.
func ModuleBundleHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		moduleName := r.PathValue("name")
		if moduleName == "" {
			http.Error(w, "missing module name", http.StatusBadRequest)
			return
		}
		if _, ok := auth.RequireModuleToken(authDeps, moduleName, w, r, true); !ok {
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
// Auth is required: a module-scoped token minted for this exact module (see
// auth/moduletoken.go). <img src="...">-loaded files cannot carry an
// Authorization header, so this is one of the two places a ?t= query token
// is accepted — see auth.BearerTokenAllowQuery for why this must stay
// narrowly scoped. Only files within the module's own storage directory are
// served; path traversal attempts are rejected by filepath.Clean.
func ModuleStorageHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		moduleName := r.PathValue("name")
		filePath := r.PathValue("path")
		if moduleName == "" || filePath == "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if _, ok := auth.RequireModuleToken(authDeps, moduleName, w, r, true); !ok {
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

// ModuleTokenHandler is GET /v1/modules/{name}/token: mints a short-lived,
// module-scoped token (auth.CreateModuleToken) for the caller's own
// already-active, full session - so the frontend can hand THAT to a
// module's UI bundle (ModulePage.tsx) instead of the caller's full session
// bearer token. Requires a full session, not a module token, deliberately:
// this is the one door through which a module-scoped token gets minted at
// all, so it must not itself be reachable with one (that would let an
// already-loaded module mint itself a token for a different module).
func ModuleTokenHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireActiveSession(authDeps, w, r); !ok {
			return
		}
		moduleName := r.PathValue("name")
		if moduleName == "" {
			http.Error(w, "missing module name", http.StatusBadRequest)
			return
		}
		row, found, err := d.DB.GetInstalledModule(r.Context(), moduleName)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		if !found {
			http.Error(w, "module not installed", http.StatusNotFound)
			return
		}
		if row.Status != "active" {
			http.Error(w, fmt.Sprintf("module is %s", row.Status), http.StatusServiceUnavailable)
			return
		}
		token, err := auth.CreateModuleToken(r.Context(), authDeps, auth.BearerToken(r), moduleName)
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		writeModuleJSON(w, http.StatusOK, struct {
			Token     string `json:"token"`
			ExpiresIn int    `json:"expires_in"`
		}{Token: token, ExpiresIn: int(auth.ModuleTokenTTL.Seconds())})
	}
}

// ModuleUsersDirectoryHandler is GET /v1/modules/{name}/api/_users-directory:
// a minimal, admin-gated user directory any Tier 2/3 module can call to
// build a "pick a ModuLab user" UI (e.g. a group-membership admin screen)
// without needing its own Deno worker to reach Core's users table.
//
// Deliberately NOT proxied to the module's Deno worker like every other
// /api/ route (see ModuleProxyHandler) - implemented directly in Go instead,
// specifically so a module's own Postgres role never needs a cross-schema
// grant onto the users table just to look someone up. Go itself does the
// query (db.Pool.ListUsers, the same one UsersHandler/admin.go's
// /v1/admin/users uses) and hands back only the two fields a module could
// plausibly need to reference a real account: Subject (id - the actual
// value that must be stored to match WorkerAuth.UserID on a later request)
// and Name (so an admin can tell users apart in a picker). Email, role,
// approval/lock status etc. are intentionally not exposed here - a module
// has no legitimate use for them, and the admin already reviews those on
// Core's own /v1/admin/users page.
//
// Gated by auth.RequireAdminSession, the same admin check
// /v1/admin/users itself uses - NOT auth.RequireModuleToken (every other
// route in this file). A module-scoped token is deliberately not accepted
// here: it identifies "some active session calling this module's API", not
// "an admin", and this endpoint must not be reachable by a regular group
// member.
func ModuleUsersDirectoryHandler(d Deps, authDeps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.RequireAdminSession(authDeps, w, r); !ok {
			return
		}
		users, err := d.DB.ListUsers(r.Context())
		if err != nil {
			httperr.Internal(w, err)
			return
		}
		type directoryEntry struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		resp := make([]directoryEntry, 0, len(users))
		for _, u := range users {
			resp = append(resp, directoryEntry{ID: u.Subject, Name: u.Name})
		}
		writeModuleJSON(w, http.StatusOK, resp)
	}
}

// RegisterModuleRoutes wires the module proxy, locale, bundle, storage, and
// token handlers into mux. Called from main.go after module install and at
// startup for each already-installed module.
//
// Note: the literal /v1/modules and /v1/modules/install etc. routes that
// handle the lifecycle API are registered first in main.go and take
// precedence over this wildcard because Go's 1.22 ServeMux gives more-
// specific paths priority over less-specific ones. The same rule is why
// _users-directory below (a fixed final path segment) takes priority over
// the "/v1/modules/{name}/api/" trailing-slash pattern for that one exact
// path, even though both are registered on this same mux.
func RegisterModuleRoutes(mux *http.ServeMux, d Deps, authDeps auth.Deps) {
	mux.HandleFunc("GET /v1/modules/{name}/token", ModuleTokenHandler(d, authDeps))
	mux.HandleFunc("GET /v1/modules/{name}/locales/{lng}", ModuleLocaleHandler(d, authDeps))
	mux.HandleFunc("GET /v1/modules/{name}/api/_users-directory", ModuleUsersDirectoryHandler(d, authDeps))
	mux.HandleFunc("/v1/modules/{name}/api/", ModuleProxyHandler(d, authDeps))
	mux.HandleFunc("GET /v1/modules/{name}/ui/bundle.js", ModuleBundleHandler(d, authDeps))
	mux.HandleFunc("GET /v1/modules/{name}/storage/{path...}", ModuleStorageHandler(d, authDeps))
}
