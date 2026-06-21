// Package setup implements the first-boot Setup Wizard's backend endpoints:
// the bootstrap-token handshake (spec section 2.4, this file) and OIDC
// provider configuration (spec section 6.5, oidc.go).
package setup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/modulab-project/modulab-core/backend/internal/db"
)

// StatusResponse reports whether Core's master key is configured. Always
// true once Core is actually running - see InitHandler's doc comment.
type StatusResponse struct {
	Configured bool `json:"configured"`
}

// InitResponse confirms the bootstrap token presented to /v1/setup/init was
// valid. It used to also carry the freshly generated master key (see
// InitHandler's doc comment for why that no longer happens) - Ready is all
// that's left once that's gone, but the endpoint stays: it's still the
// frontend's signal that the token round-tripped successfully through
// bootstrapMgr.Middleware before persisting it client-side for the rest of
// the wizard.
type InitResponse struct {
	Ready bool `json:"ready"`
}

// StatusHandler reports whether the master key is configured. This is now
// always true if Core is running at all - config.Load refuses to start
// without a valid MODULAB_MASTER_KEY - but the endpoint is kept for
// anything that still polls it rather than checking /healthz.
func StatusHandler(pool *db.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, StatusResponse{Configured: true})
	}
}

// InitHandler used to generate a master key on first call and persist a
// copy to core_settings as a fallback for a missing .env value - removed
// 2026-06-21 on request: that fallback meant the key protecting every
// encrypted column sat in plaintext in the very database it was protecting,
// right next to what it decrypts. The master key now comes exclusively from
// MODULAB_MASTER_KEY, validated by config.Load at startup (Core refuses to
// start at all without it - see validateMasterKey there), so there is
// nothing left for this handler to generate or store. It still exists as
// the wizard's step 1 network round-trip: submitting the bootstrap token
// here is what proves to the frontend that the token is valid (a non-200
// response means bootstrapMgr.Middleware rejected it) before the wizard
// persists it client-side and moves to step 2.
func InitHandler(pool *db.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, InitResponse{Ready: true})
	}
}

// ResolveMasterKey returns the active master key. It only ever returns
// envValue (the real MODULAB_MASTER_KEY from env/.env, as loaded by
// config.Load) - there is no database fallback to fall back to anymore.
// The error path below should be unreachable in practice, since
// config.Load already refuses to start Core at all with an empty or
// malformed key; it stays as a defensive check rather than a trust
// assumption, in case ResolveMasterKey is ever called from a path that
// bypassed config.Load (e.g. a future test harness).
//
// Kept as a function with this exact signature, rather than callers just
// reading cfg.MasterKey directly, because internal/auth's resolveProvider
// and main.go's OIDC/DNS-challenge configure handlers all call it - this
// way the database-fallback removal only had to happen in one place.
func ResolveMasterKey(ctx context.Context, pool *db.Pool, envValue string) (string, error) {
	if envValue == "" {
		return "", fmt.Errorf("setup: MODULAB_MASTER_KEY is not set - this should be unreachable, since config.Load refuses to start Core without it")
	}
	return envValue, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
