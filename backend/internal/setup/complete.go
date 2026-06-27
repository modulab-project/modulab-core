// This file implements the Setup Wizard's final step (spec section 6.5
// step 7): once every prior step has actually been persisted (not merely
// attempted), it permanently disables the bootstrap-token gate via
// bootstrap.Manager.Complete so Core moves into normal operation.
package setup

import (
	"context"
	"log"
	"net/http"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
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
//
// masterKeyEnv is the raw MODULAB_MASTER_KEY value, forwarded here so the
// handler can record an audit entry without requiring a separate wrapper.
func CompleteHandler(pool *db.Pool, mgr *bootstrap.Manager, masterKeyEnv string) http.HandlerFunc {
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

		// Best-effort audit. No user session exists at this point (the
		// endpoint is behind the bootstrap token, not a user session), so
		// actor_id is "bootstrap" and actor_email is left empty.
		if masterKey, err := ResolveMasterKey(ctx, pool, masterKeyEnv); err == nil {
			if err := audit.Log(ctx, pool, masterKey, audit.LogParams{
				EventType: audit.EventSetupComplete,
				ActorID:   "bootstrap",
			}); err != nil {
				log.Printf("setup: audit complete: %v", err)
			}
		}

		writeJSON(w, http.StatusOK, CompleteResponse{Completed: true})
	}
}

// WizardComplete reports whether the wizard has already been fully
// completed, purely by checking persisted state - the same check
// CompleteHandler runs, exposed for main.go to call at startup so it can
// decide between bootstrap.Manager.LogToken (still needs setting up) and
// bootstrap.Manager.Complete (already done in a previous run, do not print
// a fresh token or re-lock the Setup Wizard API).
func WizardComplete(ctx context.Context, pool *db.Pool) (bool, error) {
	missing, err := missingSteps(ctx, pool)
	if err != nil {
		return false, err
	}
	return len(missing) == 0, nil
}

// missingSteps reports which of the four prerequisites for completing the
// wizard (OIDC, DNS-challenge provider, group prefix, a bound Super-Admin)
// have not actually been persisted yet, using each step's own *Configured
// helper so this stays in sync with them automatically.
//
// The master key is deliberately NOT checked here anymore: it now comes
// exclusively from MODULAB_MASTER_KEY, validated by config.Load at startup
// (Core refuses to even start without it), so by the time this function can
// run at all, the master key is guaranteed present - there is nothing left
// to persist or verify for it.
//
// DNS-challenge (step 4) is mandatory here on purpose: the frontend no
// longer offers a "skip" button for it (removed 2026-06-21, after briefly
// shipping a skippable version that just moved the deadlock from "stuck on
// step 7" to "silently never configured"), so every wizard run that reaches
// this handler is expected to have gone through it for real.
func missingSteps(ctx context.Context, pool *db.Pool) ([]string, error) {
	var missing []string

	oidcDone, err := OIDCConfigured(ctx, pool)
	if err != nil {
		return nil, err
	}
	if !oidcDone {
		missing = append(missing, "oidc")
	}

	dnsChallengeDone, err := DNSChallengeConfigured(ctx, pool)
	if err != nil {
		return nil, err
	}
	if !dnsChallengeDone {
		missing = append(missing, "dns_challenge")
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
