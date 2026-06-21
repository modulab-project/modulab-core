// This file implements the Setup Wizard's group-prefix step (spec section
// 6.5 step 5): the operator defines the global prefix used to gate OIDC
// groups-claim membership (spec section 3.3's "Dynamic Prefix Hard Gate").
// ResolveGroupPrefix is what the actual login flow (internal/auth) reads at
// request time to enforce that gate.
package setup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/modulab-project/modulab-core/backend/internal/db"
)

const groupPrefixSettingKey = "group_prefix"

// validGroupPrefix matches the conservative charset spec section 3.3's
// examples use for OIDC groups-claim values: letters, digits, underscore,
// and hyphen. This is deliberately stricter than "anything non-empty" since
// the prefix is concatenated directly onto "Super-Admin", "Org-Admin", and
// "User" to form the literal group names operators must create in their
// OIDC provider - a stray space or control character would silently break
// that match at login time.
var validGroupPrefix = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// GroupPrefixConfigRequest is the body of POST /v1/setup/group-prefix/configure.
type GroupPrefixConfigRequest struct {
	Prefix string `json:"prefix"`
}

// GroupPrefixStatusResponse reports the configured prefix and the three
// resulting group names, exactly as the wizard shows the operator (spec
// section 6.5 step 5) so they know what to create in their OIDC provider.
type GroupPrefixStatusResponse struct {
	Configured bool     `json:"configured"`
	Prefix     string   `json:"prefix,omitempty"`
	Groups     []string `json:"groups,omitempty"`
}

// GroupPrefixConfigured reports whether a group prefix has already been
// persisted, without exposing the underlying setting key to callers outside
// this package. Used by main.go's startup log to summarize Setup Wizard
// progress.
func GroupPrefixConfigured(ctx context.Context, pool *db.Pool) (bool, error) {
	_, exists, err := pool.GetSetting(ctx, groupPrefixSettingKey)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// ResolveGroupPrefix returns the effective group prefix: a real
// MODULAB_GROUP_PREFIX (env/.env) always takes precedence once set,
// otherwise the prefix persisted by the Setup Wizard's
// /v1/setup/group-prefix/configure (step 5). Mirrors ResolveMasterKey in
// wizard.go. Called by the login flow (internal/auth) on every
// /v1/auth/login and /v1/auth/callback request, so a prefix chosen through
// the wizard takes effect immediately, without a Core restart.
func ResolveGroupPrefix(ctx context.Context, pool *db.Pool, envValue string) (string, error) {
	if envValue != "" {
		return envValue, nil
	}
	value, exists, err := pool.GetSetting(ctx, groupPrefixSettingKey)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf("setup: group prefix has not been configured yet (call /v1/setup/group-prefix/configure first)")
	}
	return value, nil
}

// GroupPrefixStatusHandler reports the currently persisted group prefix, if
// any, and the three group names derived from it.
func GroupPrefixStatusHandler(pool *db.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		prefix, exists, err := pool.GetSetting(r.Context(), groupPrefixSettingKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !exists {
			writeJSON(w, http.StatusOK, GroupPrefixStatusResponse{Configured: false})
			return
		}
		writeJSON(w, http.StatusOK, GroupPrefixStatusResponse{
			Configured: true,
			Prefix:     prefix,
			Groups:     groupNames(prefix),
		})
	}
}

// GroupPrefixConfigureHandler validates and persists the group prefix.
// Spec section 6.5 step 5 frames this as a one-time definition that only a
// Super-Admin can later change - that restriction depends on the auth/role
// system (spec section 3.1), which has not landed yet, so it is not
// enforced here. The bootstrap-token gate (see bootstrap.Manager) is the
// only access control in front of this endpoint for now.
func GroupPrefixConfigureHandler(pool *db.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req GroupPrefixConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
			return
		}

		prefix := strings.TrimSpace(req.Prefix)
		if prefix == "" {
			http.Error(w, "prefix must not be empty (spec section 3.3 hard gate)", http.StatusBadRequest)
			return
		}
		if !validGroupPrefix.MatchString(prefix) {
			http.Error(w, "prefix may only contain letters, digits, underscores, and hyphens", http.StatusBadRequest)
			return
		}

		if err := pool.SetSetting(r.Context(), groupPrefixSettingKey, prefix); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, GroupPrefixStatusResponse{
			Configured: true,
			Prefix:     prefix,
			Groups:     groupNames(prefix),
		})
	}
}

// groupNames derives the three group names operators must create in their
// OIDC provider (spec section 6.5 step 5 / section 3.3's example table).
func groupNames(prefix string) []string {
	return []string{
		prefix + "Super-Admin",
		prefix + "Org-Admin",
		prefix + "User",
	}
}
