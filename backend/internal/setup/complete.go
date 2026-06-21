// This file implements the Setup Wizard's final step (spec section 6.5
// step 7): once every prior step has actually been persisted (not merely
// attempted), it permanently disables the bootstrap-token gate via
// bootstrap.Manager.Complete so Core moves into normal operation.
package setup

import (
	"context"
	"net/http"

	"github.com/modulab-project/modulab-core/backend/internal/bootstrap"
	"github.com/modulab-project/modulab-core/backend/internal/db"
)

// CompleteResponse is the body of POST /v1/setup/complete.
type CompleteResponse struct {
	Completed bool     `json:"completed"`
	Missing   []string `json:"missing,omitempty"`
}

// CompleteHandler checks every wizard step's persisted state directly
// (rather than trusting that the client called each configure endpoint in
// order) before calling mgr.Complete. This matters most for step 6 ("Super-
// Admin binden"): a user can call /v1/auth/login and complete an OIDC
// round-trip without ever landing in the configured Super-Admin group
// (spec section 3.3's Dynamic Prefix Hard Gate leaves them RolePending
// instead) - db.Pool.HasSuperAdmin is what actually verifies step 6
// succeeded, not just that login was attempted.
func CompleteHandler(pool *db.Pool, mgr *bootstrap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		missing, err := missingSteps(ctx, pool)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(missing) > 0 {
			writeJSON(w, http.StatusPreconditionFailed, CompleteResponse{
				Completed: false,
				Missing:   missing,
			})
			return
		}

		mgr.Complete()
		writeJSON(w, http.StatusOK, CompleteResponse{Completed: true})
	}
}

// missingSteps reports which of the four prerequisites for completing the
// wizard (master key, OIDC, group prefix, a bound Super-Admin) have not
// actually been persisted yet, using each step's own *Configured helper so
// this stays in sync with them automatically.
//
// DNS-challenge (step 4) is deliberately not checked here even though it
// has its own *Configured helper: the wizard's step 4 has a "skip" button
// precisely because nothing in Core actually talks to a DNS-challenge
// provider yet (see dnschallenge.go's doc comment), so gating completion on
// it would make skipping permanently block the wizard. Once Core gains real
// DNS-challenge usage, revisit whether this should become mandatory.
func missingSteps(ctx context.Context, pool *db.Pool) ([]string, error) {
	var missing []string

	masterKeyDone, err := MasterKeyConfigured(ctx, pool)
	if err != nil {
		return nil, err
	}
	if !masterKeyDone {
		missing = append(missing, "master_key")
	}

	oidcDone, err := OIDCConfigured(ctx, pool)
	if err != nil {
		return nil, err
	}
	if !oidcDone {
		missing = append(missing, "oidc")
	}

	groupPrefixDone, err := GroupPrefixConfigured(ctx, pool)
	if err != nil {
		return nil, err
	}
	if !groupPrefixDone {
		missing = append(missing, "group_prefix")
	}

	hasSuperAdmin, err := pool.HasSuperAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if !hasSuperAdmin {
		missing = append(missing, "super_admin_login")
	}

	return missing, nil
}
