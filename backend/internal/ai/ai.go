// Package ai implements the AI chat feature: admin-managed provider
// configuration, per-user API key overrides, and a streaming chat endpoint.
//
// Providers come in two flavours:
//
//   - "anthropic"    — Anthropic's own Messages API (messages/stream format)
//   - "openai_compat" — any OpenAI-compatible endpoint (OpenAI, Gemini,
//     DeepSeek, Ollama, Groq, …); base_url selects the target
//
// Key resolution follows the hybrid model: a user's own key (if present and
// the provider allows overrides) wins; the admin key is the fallback. Both
// are stored GCM-encrypted in the database and never leave the backend.
//
// Admin endpoints (super-admin only):
//
//	GET    /v1/admin/ai/providers              → []ProviderResponse
//	POST   /v1/admin/ai/providers              → ProviderResponse   (create)
//	PATCH  /v1/admin/ai/providers/{id}         → ProviderResponse   (update)
//	DELETE /v1/admin/ai/providers/{id}         → 204
//	DELETE /v1/admin/ai/providers/{id}/key     → 204  (clear admin key only)
//
// User endpoints (any approved session):
//
//	GET    /v1/ai/providers                    → []UserProviderResponse
//	PUT    /v1/ai/keys/{id}                    → 204  (set own key)
//	DELETE /v1/ai/keys/{id}                    → 204  (remove own key)
//
// Chat endpoint (any approved session):
//
//	POST   /v1/ai/chat                         → text/event-stream SSE
package ai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/auth"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/netguard"
	"github.com/modulab-project/modulab-core/backend/internal/notify"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
)

// safeProviderClient and safeProviderStreamClient are used for requests
// whose target host comes from an admin-configured AI provider's base_url
// (fetchModels, streamOpenAICompat) - unlike the fixed
// api.anthropic.com/api.deepseek.com URLs used elsewhere in this file,
// base_url for a "custom" provider is arbitrary admin input, so both go
// through netguard's dial-time IP allowlist instead of http.DefaultClient.
// See netguard's doc comment for why (SSRF/DNS rebinding).
//
// Two separate clients because a client-level Timeout applies to the whole
// round trip including reading the response body: fine for fetchModels (a
// quick metadata call), wrong for streamOpenAICompat, which reads an SSE
// stream that can legitimately run far longer than any fixed timeout - that
// one relies solely on the caller's request context for cancellation
// (Timeout: 0 disables the client-level cutoff), same as the existing
// Anthropic streaming client below already does via http.DefaultClient.
//
// safeProviderClient itself now has Timeout: 0 too (previously a fixed 30s)
// - the actual bound is the admin-configurable ai_provider_timeout_seconds
// setting (see ProviderTimeoutSeconds), applied per-request in fetchModels
// via context.WithTimeout instead of baked into the client at package-init
// time. This matters in practice for local/self-hosted model backends
// (Ollama etc.), which can legitimately take longer than 30s to answer a
// models-list request on modest homelab hardware.
var (
	safeProviderClient       = netguard.SafeHTTPClient(0)
	safeProviderStreamClient = netguard.SafeHTTPClient(0)
)

// defaultProviderTimeoutSeconds is ProviderTimeoutSeconds's fallback - mirrors
// the fixed value this replaced.
const defaultProviderTimeoutSeconds = 30

// SettingKeyProviderTimeoutSeconds/SettingKeyChatRPMLimit/SettingKeyMaxBodyBytes
// name the core_settings keys ProviderTimeoutSeconds/ChatRPMLimit/MaxBodyBytes
// below read. Exported so adminapi.AdminLimitsHandler's PATCH handler writes
// through these instead of a second, independently-hardcoded string literal -
// found 2026-07-27 as the same "two copies, one of which can drift" pattern
// as the __Host-modulab_session cookie-name bug.
const (
	SettingKeyProviderTimeoutSeconds = "ai_provider_timeout_seconds"
	SettingKeyChatRPMLimit           = "ai_chat_rpm_limit"
	SettingKeyMaxBodyBytes           = "max_body_bytes"
)

// ProviderTimeoutSeconds reads the fetchModels HTTP timeout (seconds) from
// core_settings ("ai_provider_timeout_seconds"), same pattern as
// modules.MaxUploadBodyBytes. Defaults to defaultProviderTimeoutSeconds if
// unset. See AdminLimitsHandler's doc comment.
func ProviderTimeoutSeconds(ctx context.Context, pool *db.Pool) int {
	val, ok, err := pool.GetSetting(ctx, SettingKeyProviderTimeoutSeconds)
	if err != nil || !ok || val == "" {
		return defaultProviderTimeoutSeconds
	}
	n, err := strconv.Atoi(val)
	if err != nil || n <= 0 {
		return defaultProviderTimeoutSeconds
	}
	return n
}

// ---- types -----------------------------------------------------------------

// ProviderResponse is the JSON shape returned to admin callers.
type ProviderResponse struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	Name            string `json:"name"`
	BaseURL         string `json:"base_url,omitempty"`
	HasAdminKey     bool   `json:"has_admin_key"`
	DefaultModel    string `json:"default_model"`
	UserCanOverride bool   `json:"user_can_override"`
	Enabled         bool   `json:"enabled"`
	SortOrder       int    `json:"sort_order"`
}

// UserProviderResponse is the JSON shape returned to non-admin callers.
// It shows whether a key is available (admin or user) and whether the user
// has their own key set — without exposing any key material.
type UserProviderResponse struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	DefaultModel   string `json:"default_model"`   // admin-set model; always shown
	PreferredModel string `json:"preferred_model"` // user's own model choice; only used when has_user_key
	Available      bool   `json:"available"`       // true when at least one key exists
	Enabled        bool   `json:"enabled"`
	HasUserKey     bool   `json:"has_user_key"`
	HasAdminKey    bool   `json:"has_admin_key"`
	CanOverride    bool   `json:"can_override"`
}

// createProviderRequest is the body of POST /v1/admin/ai/providers.
type createProviderRequest struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	Name            string `json:"name"`
	BaseURL         string `json:"base_url"`
	AdminKey        string `json:"admin_key"`
	DefaultModel    string `json:"default_model"`
	UserCanOverride bool   `json:"user_can_override"`
	Enabled         bool   `json:"enabled"`
	SortOrder       int    `json:"sort_order"`
}

// patchProviderRequest is the body of PATCH /v1/admin/ai/providers/{id}.
// Only non-zero/non-empty fields are applied.
type patchProviderRequest struct {
	Name            *string `json:"name"`
	BaseURL         *string `json:"base_url"`
	AdminKey        *string `json:"admin_key"`
	DefaultModel    *string `json:"default_model"`
	UserCanOverride *bool   `json:"user_can_override"`
	Enabled         *bool   `json:"enabled"`
	SortOrder       *int    `json:"sort_order"`
}

// setKeyRequest is the body of PUT /v1/ai/keys/{id}.
type setKeyRequest struct {
	Key string `json:"key"`
}

// chatRequest is the body of POST /v1/ai/chat.
type chatRequest struct {
	ProviderID string        `json:"provider_id"`
	Model      string        `json:"model"`
	Messages   []chatMessage `json:"messages"`
}

type chatMessage struct {
	Role    string `json:"role"` // "user" or "assistant"
	Content string `json:"content"`
}

// ---- helpers ----------------------------------------------------------------

func rowToResponse(r db.AIProviderRow) ProviderResponse {
	return ProviderResponse{
		ID:              r.ID,
		Type:            r.Type,
		Name:            r.Name,
		BaseURL:         r.BaseURL,
		HasAdminKey:     r.HasAdminKey,
		DefaultModel:    r.DefaultModel,
		UserCanOverride: r.UserCanOverride,
		Enabled:         r.Enabled,
		SortOrder:       r.SortOrder,
	}
}

// ChatRPMLimit reads the configured chat requests-per-minute limit from
// core_settings. Returns 60 as the default when the key is absent or
// unparseable; 0 means unlimited. Exported so adminapi.AdminLimitsHandler
// can surface/persist it on GET/PATCH /v1/admin/system/limits — the setting
// used to have its own PATCH /v1/admin/ai/settings endpoint (ai.
// AdminSettingsHandler), but that handler only ever exposed this one field,
// so it was folded into the same cross-cutting-limits page as its sibling
// ai_chat_ip_rate_limit_max instead of staying on a single-field page of its
// own. See adminapi/limits.go's package doc comment for the underlying
// "hardcoded, undiscoverable, wrong place" pattern this consolidation fixes.
func ChatRPMLimit(ctx context.Context, pool *db.Pool) int {
	val, ok, err := pool.GetSetting(ctx, SettingKeyChatRPMLimit)
	if err != nil || !ok || val == "" {
		return 60 // default: 60 RPM
	}
	n, err := strconv.Atoi(val)
	if err != nil || n < 0 {
		return 60
	}
	return n
}

// MaxBodyBytes reads the configured request body size limit from core_settings.
// Returns 1 MB (1<<20) as the default when the key is absent or unparseable;
// 0 means unlimited. Exported so main.go's middleware can use it.
func MaxBodyBytes(ctx context.Context, pool *db.Pool) int64 {
	val, ok, err := pool.GetSetting(ctx, SettingKeyMaxBodyBytes)
	if err != nil || !ok || val == "" {
		return 1 << 20 // default: 1 MB
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil || n < 0 {
		return 1 << 20
	}
	return n
}

// writeSSE sends a single SSE data line.
func writeSSE(w http.ResponseWriter, data string) {
	if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
		// Best-effort: the client may have already disconnected mid-stream,
		// which is a normal occurrence for SSE, not something to fail on.
		log.Printf("ai: writeSSE: %v", err)
		return
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// ---- admin handlers --------------------------------------------------------

// AdminListHandler handles GET /v1/admin/ai/providers.
// Returns all providers regardless of enabled state (admins see everything).
// Auth is enforced by the superAdminOnly middleware in main.go.
func AdminListHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rows, err := deps.Pool.ListAIProviders(r.Context())
		if err != nil {
			log.Printf("ai: list providers: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		out := make([]ProviderResponse, len(rows))
		for i, row := range rows {
			out[i] = rowToResponse(row)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// AdminCreateHandler handles POST /v1/admin/ai/providers.
func AdminCreateHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req createProviderRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.ID == "" || req.Type == "" || req.Name == "" {
			http.Error(w, "id, type, and name are required", http.StatusBadRequest)
			return
		}
		validTypes := map[string]bool{
			"anthropic": true, "openai": true, "gemini": true,
			"deepseek": true, "kimi": true, "mistral": true,
			"openrouter": true, "requesty": true, "openai_compat": true,
		}
		if !validTypes[req.Type] {
			http.Error(w, "invalid type", http.StatusBadRequest)
			return
		}
		row := db.AIProviderRow{
			ID:              req.ID,
			Type:            req.Type,
			Name:            req.Name,
			BaseURL:         req.BaseURL,
			DefaultModel:    req.DefaultModel,
			UserCanOverride: req.UserCanOverride,
			Enabled:         req.Enabled,
			SortOrder:       req.SortOrder,
		}
		if err := deps.Pool.UpsertAIProvider(r.Context(), row, req.AdminKey); err != nil {
			log.Printf("ai: upsert provider: %v", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}

		// Best-effort audit; a failed write must not block the response.
		sess, _ := auth.SessionFromContext(r.Context())
		if masterKey, err := setup.ResolveMasterKey(r.Context(), deps.Pool, deps.MasterKeyEnv); err == nil {
			if err := audit.Log(r.Context(), deps.Pool, masterKey, audit.LogParams{
				EventType:  audit.EventConfigAIProvider,
				ActorID:    sess.UserID,
				ActorEmail: sess.Email,
				Details:    fmt.Sprintf(`{"action":"create","provider_id":%q,"name":%q}`, req.ID, req.Name),
			}); err != nil {
				log.Printf("ai: audit create provider %q: %v", req.ID, err)
			}
		}

		created, _, err := deps.Pool.GetAIProvider(r.Context(), req.ID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(rowToResponse(created))
	}
}

// AdminPatchHandler handles PATCH /v1/admin/ai/providers/{id}.
func AdminPatchHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		existing, found, err := deps.Pool.GetAIProvider(r.Context(), id)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "provider not found", http.StatusNotFound)
			return
		}

		var req patchProviderRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		// Apply patch fields to the existing row.
		if req.Name != nil {
			existing.Name = *req.Name
		}
		if req.BaseURL != nil {
			existing.BaseURL = *req.BaseURL
		}
		if req.DefaultModel != nil {
			existing.DefaultModel = *req.DefaultModel
		}
		if req.UserCanOverride != nil {
			existing.UserCanOverride = *req.UserCanOverride
		}
		if req.Enabled != nil {
			existing.Enabled = *req.Enabled
		}
		if req.SortOrder != nil {
			existing.SortOrder = *req.SortOrder
		}

		adminKey := ""
		if req.AdminKey != nil {
			adminKey = *req.AdminKey
		}
		if err := deps.Pool.UpsertAIProvider(r.Context(), existing, adminKey); err != nil {
			log.Printf("ai: patch provider %q: %v", id, err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}

		// Best-effort audit; a failed write must not block the response.
		sess, _ := auth.SessionFromContext(r.Context())
		if masterKey, err := setup.ResolveMasterKey(r.Context(), deps.Pool, deps.MasterKeyEnv); err == nil {
			if err := audit.Log(r.Context(), deps.Pool, masterKey, audit.LogParams{
				EventType:  audit.EventConfigAIProvider,
				ActorID:    sess.UserID,
				ActorEmail: sess.Email,
				Details:    fmt.Sprintf(`{"action":"patch","provider_id":%q,"name":%q}`, id, existing.Name),
			}); err != nil {
				log.Printf("ai: audit patch provider %q: %v", id, err)
			}
		}

		updated, _, _ := deps.Pool.GetAIProvider(r.Context(), id)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rowToResponse(updated))
	}
}

// AdminDeleteHandler handles DELETE /v1/admin/ai/providers/{id}.
func AdminDeleteHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := r.PathValue("id")

		// Read the name before deleting so the audit entry can include it.
		// Best-effort: if the lookup fails, fall back to the ID.
		provName := id
		if prov, found, err := deps.Pool.GetAIProvider(r.Context(), id); err == nil && found {
			provName = prov.Name
		}

		found, err := deps.Pool.DeleteAIProvider(r.Context(), id)
		if err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "provider not found", http.StatusNotFound)
			return
		}

		// Best-effort audit; a failed write must not turn a successful delete
		// into an error.
		sess, _ := auth.SessionFromContext(r.Context())
		if masterKey, err := setup.ResolveMasterKey(r.Context(), deps.Pool, deps.MasterKeyEnv); err == nil {
			if err := audit.Log(r.Context(), deps.Pool, masterKey, audit.LogParams{
				EventType:  audit.EventConfigAIProviderDel,
				ActorID:    sess.UserID,
				ActorEmail: sess.Email,
				Details:    fmt.Sprintf(`{"provider_id":%q,"name":%q}`, id, provName),
			}); err != nil {
				log.Printf("ai: audit delete provider %q: %v", id, err)
			}
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// AdminClearKeyHandler handles DELETE /v1/admin/ai/providers/{id}/key.
// Removes the admin key without deleting the provider itself.
func AdminClearKeyHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := r.PathValue("id")
		if err := deps.Pool.ClearAIProviderAdminKey(r.Context(), id); err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}

		// Best-effort audit.
		sess, _ := auth.SessionFromContext(r.Context())
		if masterKey, err := setup.ResolveMasterKey(r.Context(), deps.Pool, deps.MasterKeyEnv); err == nil {
			if err := audit.Log(r.Context(), deps.Pool, masterKey, audit.LogParams{
				EventType:  audit.EventConfigAIKeyCleared,
				ActorID:    sess.UserID,
				ActorEmail: sess.Email,
				Details:    fmt.Sprintf(`{"provider_id":%q}`, id),
			}); err != nil {
				log.Printf("ai: audit clear key for provider %q: %v", id, err)
			}
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// AdminListModelsHandler handles GET /v1/admin/ai/providers/{id}/models.
// It proxies the provider's model-list API and returns a sorted list of model
// IDs. Only the stored admin key is used — the user key is never sent to this
// endpoint. Requires a stored admin key.
func AdminListModelsHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := r.PathValue("id")
		prov, found, err := deps.Pool.GetAIProvider(r.Context(), id)
		if err != nil || !found {
			http.Error(w, "provider not found", http.StatusNotFound)
			return
		}
		// Resolve admin key only (not the user key — this is an admin action).
		adminKey, err := deps.Pool.GetAIProviderAdminKey(r.Context(), id)
		if err != nil || adminKey == "" {
			http.Error(w, "no admin API key configured for this provider", http.StatusServiceUnavailable)
			return
		}

		baseURL := prov.BaseURL
		if baseURL == "" {
			baseURL = defaultBaseURL(prov.Type)
		}

		models, err := fetchModels(r.Context(), deps.Pool, prov.Type, baseURL, adminKey)
		if err != nil {
			log.Printf("ai: fetch models (provider=%s): %v", id, err)
			http.Error(w, "failed to fetch models from provider", http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]string{"models": models})
	}
}

// fetchModels calls the provider's model-list endpoint and returns sorted
// model IDs. Anthropic uses a dedicated header; all others use Bearer auth
// against their OpenAI-compatible /models endpoint.
func fetchModels(ctx context.Context, pool *db.Pool, provType, baseURL, apiKey string) ([]string, error) {
	timeout := time.Duration(ProviderTimeoutSeconds(ctx, pool)) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var req *http.Request
	var err error

	if provType == "anthropic" {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet,
			"https://api.anthropic.com/v1/models", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("x-api-key", apiKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet,
			strings.TrimRight(baseURL, "/")+"/models", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := safeProviderClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("ai: close response body: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("provider returned %d: %s", resp.StatusCode, body)
	}

	// Both Anthropic and OpenAI-compat return {"data": [{"id": "..."}, ...]}.
	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	ids := make([]string, 0, len(result.Data))
	for _, m := range result.Data {
		if m.ID == "" || !isCompatibleModel(provType, m.ID) {
			continue
		}
		ids = append(ids, normalizeModelID(provType, m.ID))
	}
	sort.Strings(ids)
	return ids, nil
}

// normalizeModelID strips provider-specific noise from model IDs so the
// cleaned name can be stored in the DB and displayed directly.
//
//   - Gemini:    "models/gemini-2.5-flash"  → "gemini-2.5-flash"
//   - Anthropic: "claude-haiku-4-5-20251001" → "claude-haiku-4-5"
//     (date suffix YYYYMMDD removed; without it Anthropic always routes to
//     the latest safe version of that model, which is fine for everyday use)
//   - All others: unchanged
func normalizeModelID(provType, id string) string {
	switch provType {
	case "gemini":
		return strings.TrimPrefix(id, "models/")
	case "anthropic":
		// Strip trailing -YYYYMMDD suffix (8 digits after the last hyphen).
		if idx := len(id) - 9; idx > 0 && id[idx] == '-' {
			suffix := id[idx+1:]
			allDigits := true
			for _, c := range suffix {
				if c < '0' || c > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				return id[:idx]
			}
		}
	}
	return id
}

// isCompatibleModel returns false for models that are known to be incompatible
// with the OpenAI-compat chat/completions endpoint (e.g. Gemini Live/realtime
// and embedding-only models). For non-Gemini providers every model is passed
// through unchanged.
func isCompatibleModel(provType, modelID string) bool {
	if provType != "gemini" {
		return true
	}
	lower := strings.ToLower(modelID)
	// Drop live/realtime, embedding, and AQA models — they only support
	// Gemini's native Interactions or Embeddings API, not chat/completions.
	for _, skip := range []string{"live", "embedding", "-aqa", "imagen"} {
		if strings.Contains(lower, skip) {
			return false
		}
	}
	return true
}

// AdminBalanceHandler handles GET /v1/admin/ai/providers/{id}/balance.
// Queries the provider's credit/balance API and returns the result.
// Currently supported: deepseek, openai.
// Returns {"supported": false} for providers without a public balance API.
func AdminBalanceHandler(deps auth.Deps) http.HandlerFunc {
	type balanceResp struct {
		Supported bool    `json:"supported"`
		Currency  string  `json:"currency,omitempty"`
		Amount    float64 `json:"amount,omitempty"`
		Error     string  `json:"error,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := r.PathValue("id")

		prov, found, err := deps.Pool.GetAIProvider(r.Context(), id)
		if err != nil || !found {
			http.Error(w, "provider not found", http.StatusNotFound)
			return
		}
		adminKey, err := deps.Pool.GetAIProviderAdminKey(r.Context(), id)
		if err != nil || adminKey == "" {
			http.Error(w, "no admin API key configured for this provider", http.StatusServiceUnavailable)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch prov.Type {
		case "deepseek":
			bal, currency, fetchErr := fetchDeepSeekBalance(r.Context(), adminKey)
			if fetchErr != nil {
				_ = json.NewEncoder(w).Encode(balanceResp{Supported: true, Error: fetchErr.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(balanceResp{Supported: true, Currency: currency, Amount: bal})

		default:
			// OpenAI, Anthropic, Gemini, and custom providers do not have a
			// reliably accessible public balance API (OpenAI's credits endpoint
			// returns 404 for most account types), so we report unsupported.
			_ = json.NewEncoder(w).Encode(balanceResp{Supported: false})
		}
	}
}

// fetchDeepSeekBalance calls https://api.deepseek.com/user/balance and returns
// the total available balance in USD.
func fetchDeepSeekBalance(ctx context.Context, apiKey string) (float64, string, error) {
	// Bounded independently of the caller's context: this runs on r.Context()
	// from the admin balance-check handler, which has no deadline of its own,
	// so a slow/hung DeepSeek API call would otherwise hold the request (and
	// the underlying connection) open indefinitely.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.deepseek.com/user/balance", nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("ai: deepseek: close response body: %v", err)
		}
	}()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("deepseek returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		IsAvailable  bool `json:"is_available"`
		BalanceInfos []struct {
			Currency        string `json:"currency"`
			TotalBalance    string `json:"total_balance"`
			GrantedBalance  string `json:"granted_balance"`
			ToppedUpBalance string `json:"topped_up_balance"`
		} `json:"balance_infos"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, "", fmt.Errorf("parse error: %w", err)
	}
	if len(result.BalanceInfos) == 0 {
		return 0, "", fmt.Errorf("no balance info returned")
	}
	info := result.BalanceInfos[0]
	var total float64
	if _, err := fmt.Sscanf(info.TotalBalance, "%f", &total); err != nil {
		return 0, "", fmt.Errorf("parse balance %q: %w", info.TotalBalance, err)
	}
	return total, info.Currency, nil
}

// ---- user handlers ---------------------------------------------------------

// userProvidersResponse wraps the provider list with the user's preferred
// provider ID so the frontend can restore the last selection on load.
type userProvidersResponse struct {
	Providers           []UserProviderResponse `json:"providers"`
	PreferredProviderID string                 `json:"preferred_provider_id"`
}

// UserProvidersHandler handles GET /v1/ai/providers.
// Returns only enabled providers with availability info for this user.
func UserProvidersHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sess, ok := auth.RequireActiveSession(deps, w, r)
		if !ok {
			return
		}
		rows, err := deps.Pool.ListAIProvidersForUser(r.Context(), sess.UserID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		out := make([]UserProviderResponse, 0, len(rows))
		for _, row := range rows {
			available := row.HasAdminKey || (row.HasUserKey && row.UserCanOverride)
			out = append(out, UserProviderResponse{
				ID:             row.ID,
				Name:           row.Name,
				Type:           row.Type,
				DefaultModel:   row.DefaultModel,
				PreferredModel: row.PreferredModel,
				Available:      available,
				Enabled:        row.Enabled,
				HasUserKey:     row.HasUserKey,
				HasAdminKey:    row.HasAdminKey,
				CanOverride:    row.UserCanOverride,
			})
		}
		preferredProviderID, _ := deps.Pool.GetPreferredProvider(r.Context(), sess.UserID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(userProvidersResponse{
			Providers:           out,
			PreferredProviderID: preferredProviderID,
		})
	}
}

// UserSetPreferredProviderHandler handles PATCH /v1/ai/preference.
// Persists the user's preferred provider ID cross-device.
func UserSetPreferredProviderHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sess, ok := auth.RequireActiveSession(deps, w, r)
		if !ok {
			return
		}
		var body struct {
			ProviderID string `json:"provider_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := deps.Pool.SetPreferredProvider(r.Context(), sess.UserID, body.ProviderID); err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// UserSetKeyHandler handles PUT /v1/ai/keys/{id}.
func UserSetKeyHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sess, ok := auth.RequireActiveSession(deps, w, r)
		if !ok {
			return
		}
		providerID := r.PathValue("id")
		if providerID == "" {
			http.Error(w, "missing provider id", http.StatusBadRequest)
			return
		}
		// Verify provider exists and allows user override.
		prov, found, err := deps.Pool.GetAIProvider(r.Context(), providerID)
		if err != nil || !found {
			http.Error(w, "provider not found", http.StatusNotFound)
			return
		}
		if !prov.UserCanOverride {
			http.Error(w, "this provider does not allow user keys", http.StatusForbidden)
			return
		}
		var req setKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" {
			http.Error(w, "key is required", http.StatusBadRequest)
			return
		}
		if err := deps.Pool.SetAIUserKey(r.Context(), sess.UserID, providerID, req.Key); err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		// Best-effort audit, same treatment as AdminClearKeyHandler's below -
		// a failed write must not turn a successful key save into an error.
		// Unlike the admin key handlers, the key value itself never appears
		// here, encrypted or otherwise - only that provider_id had a key set.
		if masterKey, err := setup.ResolveMasterKey(r.Context(), deps.Pool, deps.MasterKeyEnv); err == nil {
			if err := audit.Log(r.Context(), deps.Pool, masterKey, audit.LogParams{
				EventType:  audit.EventAIUserKeySet,
				ActorID:    sess.UserID,
				ActorEmail: sess.Email,
				Details:    fmt.Sprintf(`{"provider_id":%q}`, providerID),
			}); err != nil {
				log.Printf("ai: audit set user key for provider %q: %v", providerID, err)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// UserDeleteKeyHandler handles DELETE /v1/ai/keys/{id}.
func UserDeleteKeyHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sess, ok := auth.RequireActiveSession(deps, w, r)
		if !ok {
			return
		}
		providerID := r.PathValue("id")
		if err := deps.Pool.DeleteAIUserKey(r.Context(), sess.UserID, providerID); err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		// Best-effort audit - see UserSetKeyHandler above for why this pair
		// needs the same treatment as their admin-key siblings.
		if masterKey, err := setup.ResolveMasterKey(r.Context(), deps.Pool, deps.MasterKeyEnv); err == nil {
			if err := audit.Log(r.Context(), deps.Pool, masterKey, audit.LogParams{
				EventType:  audit.EventAIUserKeyDeleted,
				ActorID:    sess.UserID,
				ActorEmail: sess.Email,
				Details:    fmt.Sprintf(`{"provider_id":%q}`, providerID),
			}); err != nil {
				log.Printf("ai: audit delete user key for provider %q: %v", providerID, err)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// UserSetPreferredModelHandler handles PATCH /v1/ai/keys/{id}/model.
// Saves the user's preferred model for a provider they have their own key for.
func UserSetPreferredModelHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sess, ok := auth.RequireActiveSession(deps, w, r)
		if !ok {
			return
		}
		providerID := r.PathValue("id")
		var body struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Model == "" {
			http.Error(w, "model is required", http.StatusBadRequest)
			return
		}
		if err := deps.Pool.SetAIUserPreferredModel(r.Context(), sess.UserID, providerID, body.Model); err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// UserListModelsHandler handles GET /v1/ai/keys/{id}/models.
// Fetches available models from the provider using the user's own stored key.
func UserListModelsHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sess, ok := auth.RequireActiveSession(deps, w, r)
		if !ok {
			return
		}
		providerID := r.PathValue("id")
		prov, found, err := deps.Pool.GetAIProvider(r.Context(), providerID)
		if err != nil || !found {
			http.Error(w, "provider not found", http.StatusNotFound)
			return
		}
		userKey, _, hasKey, err := deps.Pool.GetAIUserDecryptedKey(r.Context(), sess.UserID, providerID)
		if err != nil || !hasKey || userKey == "" {
			http.Error(w, "no user key stored for this provider", http.StatusServiceUnavailable)
			return
		}
		baseURL := prov.BaseURL
		if baseURL == "" {
			baseURL = defaultBaseURL(prov.Type)
		}
		models, err := fetchModels(r.Context(), deps.Pool, prov.Type, baseURL, userKey)
		if err != nil {
			log.Printf("ai: user fetch models (provider=%s): %v", providerID, err)
			http.Error(w, "failed to fetch models from provider", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]string{"models": models})
	}
}

// ---- chat handler ----------------------------------------------------------

// ChatHandler handles POST /v1/ai/chat and streams the response as SSE.
//
// Each SSE event carries either:
//
//	data: {"delta":"..."}   — a text chunk from the model
//	data: [DONE]            — stream finished
//	data: {"error":"..."}   — an error occurred
//
// The handler resolves the API key (user > admin), selects the right upstream
// client based on the provider's type, and proxies the stream back.
func ChatHandler(deps auth.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sess, ok := auth.RequireActiveSession(deps, w, r)
		if !ok {
			return
		}

		// Per-user rate limiting: check the configured RPM cap before doing
		// any DB or upstream AI work. A Valkey error here is non-fatal (fail
		// open) — a cache hiccup must not block legitimate chat traffic.
		rpmLimit := ChatRPMLimit(r.Context(), deps.Pool)
		if rpmLimit > 0 {
			rlKey := "ratelimit:chat:" + sess.UserID
			count, rlErr := deps.Valkey.IncrExpire(r.Context(), rlKey, time.Minute)
			if rlErr != nil {
				log.Printf("ai: rate limit check failed for %s: %v", sess.UserID, rlErr)
			} else if count > int64(rpmLimit) {
				log.Printf("ai: rate limit exceeded for %s: count=%d max=%d", sess.UserID, count, rpmLimit)
				// Same live admin-panel notification as main.go's shared
				// rateLimitMiddleware, gated the same way (only the request
				// that actually tripped the limit, not every retry after).
				if count == int64(rpmLimit)+1 {
					if pubErr := notify.Publish(r.Context(), deps.Valkey, notify.AdminChannel(), notify.Event{
						Type: "rate_limit.exceeded",
						Data: map[string]any{"label": "chat", "identifier": sess.Email, "count": count, "max": rpmLimit},
					}); pubErr != nil {
						log.Printf("ai: notify rate limit exceeded: %v", pubErr)
					}
				}
				if masterKey, mkErr := setup.ResolveMasterKey(r.Context(), deps.Pool, deps.MasterKeyEnv); mkErr == nil {
					if auditErr := audit.Log(r.Context(), deps.Pool, masterKey, audit.LogParams{
						EventType:  audit.EventRateLimitExceeded,
						ActorID:    sess.UserID,
						ActorEmail: sess.Email,
						Details:    fmt.Sprintf(`{"label":"chat","count":%d,"max":%d}`, count, rpmLimit),
					}); auditErr != nil {
						log.Printf("ai: audit rate limit exceeded: %v", auditErr)
					}
				}
				w.Header().Set("Retry-After", "60")
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}

		var req chatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.ProviderID == "" || len(req.Messages) == 0 {
			http.Error(w, "provider_id and messages are required", http.StatusBadRequest)
			return
		}

		prov, found, err := deps.Pool.GetAIProvider(r.Context(), req.ProviderID)
		if err != nil || !found || !prov.Enabled {
			http.Error(w, "provider not found or disabled", http.StatusNotFound)
			return
		}

		// Determine which key to use and which model to run.
		// Rule: user's own key → user picks the model (preferred_model, else
		// provider default). Admin key → admin-set default_model, fixed.
		var apiKey string
		var model string

		userKey, preferredModel, hasUserKey, ukErr := deps.Pool.GetAIUserDecryptedKey(
			r.Context(), sess.UserID, req.ProviderID)
		if ukErr != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if hasUserKey && prov.UserCanOverride && userKey != "" {
			apiKey = userKey
			// User can choose model; fall back to their preference, then provider default.
			if preferredModel != "" {
				model = preferredModel
			} else {
				model = prov.DefaultModel
			}
		} else {
			// Use admin key — model is fixed to what the admin configured.
			adminKey, akErr := deps.Pool.GetAIProviderAdminKey(r.Context(), req.ProviderID)
			if akErr != nil || adminKey == "" {
				http.Error(w, "no API key configured for this provider", http.StatusServiceUnavailable)
				return
			}
			apiKey = adminKey
			model = prov.DefaultModel
		}

		// A provider seeded without a default_model (see EnsureAISchema's doc
		// comment) has no model until the admin explicitly picks one via "load
		// models" - refuse the request rather than sending model="" upstream,
		// which every provider rejects with a confusing error anyway.
		if model == "" {
			http.Error(w, "no model selected for this provider — configure one in AI settings", http.StatusServiceUnavailable)
			return
		}

		// Set SSE headers before any streaming begins.
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no") // tell Nginx/Traefik not to buffer

		var streamErr error
		if prov.Type == "anthropic" {
			streamErr = streamAnthropic(r.Context(), w, apiKey, model, req.Messages)
		} else {
			baseURL := prov.BaseURL
			if baseURL == "" {
				baseURL = defaultBaseURL(prov.Type)
			}
			streamErr = streamOpenAICompat(r.Context(), w, apiKey, baseURL, model, req.Messages)
		}

		if streamErr != nil {
			log.Printf("ai: stream error (provider=%s): %v", req.ProviderID, streamErr)
			writeSSE(w, `{"error":"stream error"}`)
		}
		writeSSE(w, "[DONE]")
	}
}

// defaultBaseURL returns the canonical OpenAI-compatible base URL for
// well-known built-in providers. Custom providers always set base_url
// themselves, so this only covers the built-ins that happen to use the
// OpenAI-compat client (all except "anthropic", which has its own client).
func defaultBaseURL(providerType string) string {
	switch providerType {
	case "openai":
		return "https://api.openai.com/v1"
	case "gemini":
		return "https://generativelanguage.googleapis.com/v1beta/openai"
	case "deepseek":
		return "https://api.deepseek.com/v1"
	case "kimi":
		return "https://api.moonshot.ai/v1"
	case "mistral":
		return "https://api.mistral.ai/v1"
	case "openrouter":
		return "https://openrouter.ai/api/v1"
	case "requesty":
		return "https://router.requesty.ai/v1"
	default:
		return ""
	}
}

// ---- Anthropic streaming client --------------------------------------------

// streamAnthropic calls Anthropic's Messages API with stream=true and
// forwards content_block_delta events as SSE deltas.
func streamAnthropic(ctx context.Context, w http.ResponseWriter, apiKey, model string, messages []chatMessage) error {
	body := map[string]any{
		"model":      model,
		"max_tokens": 4096,
		"stream":     true,
		"system":     systemMessage,
		"messages":   messages,
	}
	bodyBytes, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("anthropic: request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("ai: anthropic: close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("anthropic: HTTP %d: %s", resp.StatusCode, string(b))
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}
		// Parse the Anthropic event to extract the delta text.
		var event struct {
			Type  string `json:"type"`
			Delta *struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}
		if event.Type == "content_block_delta" && event.Delta != nil && event.Delta.Type == "text_delta" {
			chunk, _ := json.Marshal(map[string]string{"delta": event.Delta.Text})
			writeSSE(w, string(chunk))
		}
	}
	return scanner.Err()
}

// ---- OpenAI-compatible streaming client ------------------------------------

// systemMessage is prepended to every chat request so models default to the
// user's language instead of falling back to English.
const systemMessage = "Always respond in the same language the user writes in. " +
	"If the user writes in German, reply in German. " +
	"If the user writes in English, reply in English."

// streamOpenAICompat calls any OpenAI-compatible /chat/completions endpoint
// with stream=true and forwards choices[0].delta.content events as SSE deltas.
func streamOpenAICompat(ctx context.Context, w http.ResponseWriter, apiKey, baseURL, model string, messages []chatMessage) error {
	// Prepend a system message to enforce language mirroring.
	apiMessages := make([]map[string]string, 0, len(messages)+1)
	apiMessages = append(apiMessages, map[string]string{"role": "system", "content": systemMessage})
	for _, m := range messages {
		apiMessages = append(apiMessages, map[string]string{"role": m.Role, "content": m.Content})
	}
	body := map[string]any{
		"model":    model,
		"stream":   true,
		"messages": apiMessages,
	}
	bodyBytes, _ := json.Marshal(body)

	url := strings.TrimRight(baseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := safeProviderStreamClient.Do(req)
	if err != nil {
		return fmt.Errorf("openai_compat: request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("ai: openai_compat: close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("openai_compat: HTTP %d: %s", resp.StatusCode, string(b))
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}
		var event struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}
		if len(event.Choices) > 0 && event.Choices[0].Delta.Content != "" {
			chunk, _ := json.Marshal(map[string]string{"delta": event.Choices[0].Delta.Content})
			writeSSE(w, string(chunk))
		}
	}
	return scanner.Err()
}
