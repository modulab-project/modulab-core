// Package setup implements the first-boot Setup Wizard's backend endpoints.
// Only the master-key bootstrap step is implemented here; the OIDC
// configuration step (spec section 6.5) is a follow-up commit.
package setup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/modulab-project/modulab-core/backend/internal/db"
)

const masterKeySettingKey = "master_key"

// StatusResponse reports whether Core has completed its master-key bootstrap.
type StatusResponse struct {
	Configured bool `json:"configured"`
}

// InitResponse is returned once after the master key is generated (or
// echoes the existing one if init is called again - it is intentionally
// idempotent so retrying a failed setup step is safe).
type InitResponse struct {
	MasterKey string `json:"master_key"`
	Generated bool   `json:"generated"`
}

// MasterKeyConfigured reports whether a master key has already been
// bootstrapped via core_settings (set by InitHandler below). This only
// covers the database half of the picture; callers such as /healthz are
// expected to also check cfg.MasterKey (the env/.env value) themselves and
// OR the two together, since config.Config is intentionally not imported
// here to avoid a setup -> config -> setup dependency tangle.
func MasterKeyConfigured(ctx context.Context, pool *db.Pool) (bool, error) {
	_, exists, err := pool.GetSetting(ctx, masterKeySettingKey)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// StatusHandler reports whether the master key has already been bootstrapped.
func StatusHandler(pool *db.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, exists, err := pool.GetSetting(r.Context(), masterKeySettingKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, StatusResponse{Configured: exists})
	}
}

// InitHandler generates and persists MODULAB_MASTER_KEY if it does not exist
// yet (spec section 2.4). The generated key is returned in the response body
// exactly once so the operator can copy it into their .env; Core also keeps
// a copy in core_settings as a fallback so a missing .env value does not
// strand the instance, but config.Load's MODULAB_MASTER_KEY env value always
// takes precedence once set.
func InitHandler(pool *db.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		existing, exists, err := pool.GetSetting(ctx, masterKeySettingKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if exists {
			writeJSON(w, http.StatusOK, InitResponse{MasterKey: existing, Generated: false})
			return
		}

		key, err := generateMasterKey()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := pool.SetSetting(ctx, masterKeySettingKey, key); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusCreated, InitResponse{MasterKey: key, Generated: true})
	}
}

// generateMasterKey produces a 256-bit random key, hex-encoded.
func generateMasterKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
