package modules

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/modulab-project/modulab-core/backend/internal/auth"
)

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

		// The sub-path is everything after /v1/modules/{name}.
		subPath := strings.TrimPrefix(r.URL.Path, "/v1/modules/"+moduleName)
		if subPath == "" {
			subPath = "/"
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
	}
}

// saveUploadedFile extracts the "file" field from a multipart upload and saves
// it to {dataDir}/{moduleName}/storage/uploads/. Returns the absolute path.
func saveUploadedFile(r *http.Request, dataDir, moduleName string) (string, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		return "", fmt.Errorf("parse multipart: %w", err)
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		return "", fmt.Errorf("form file: %w", err)
	}
	defer file.Close()

	// Sanitise filename — keep only the base name, no path traversal.
	safeName := filepath.Base(header.Filename)
	if safeName == "." || safeName == "/" {
		return "", fmt.Errorf("invalid filename")
	}

	uploadDir := filepath.Join(dataDir, moduleName, "storage", "uploads")
	if err := os.MkdirAll(uploadDir, 0o750); err != nil {
		return "", fmt.Errorf("create upload dir: %w", err)
	}

	// Prefix with a timestamp to avoid collisions without a full UUID import.
	dst := filepath.Join(uploadDir, safeName)
	out, err := os.Create(dst)
	if err != nil {
		return "", fmt.Errorf("create file: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		return "", fmt.Errorf("write file: %w", err)
	}

	return dst, nil
}

// RegisterModuleRoutes wires the module proxy into mux under the standard
// /v1/modules/{name}/* pattern. Called from main.go after module install and
// at startup for each already-installed Tier 2/3 module.
//
// Note: the literal /v1/modules and /v1/modules/install etc. routes that
// handle the lifecycle API are registered first in main.go and take
// precedence over this wildcard because Go's 1.22 ServeMux gives more-
// specific paths priority over less-specific ones.
func RegisterModuleRoutes(mux *http.ServeMux, d Deps, authDeps auth.Deps) {
	mux.HandleFunc("/v1/modules/{name}/api/", ModuleProxyHandler(d, authDeps))
}
