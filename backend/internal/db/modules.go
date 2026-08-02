package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modulab-project/modulab-core/backend/internal/crypto"
)

// ---- Module Store -----------------------------------------------------------

// EnsureModuleStoreSchema extends the installed_modules stub (created above in
// EnsureCoreSchema) with the full column set needed for the module lifecycle
// pipeline (spec section 4.3/4.9/4.10), and creates the module_registry table
// for the daily registry-sync cache (spec section 4.10).
//
// All ALTERs use ADD COLUMN IF NOT EXISTS so this is safe to run on every boot.
func (p *Pool) EnsureModuleStoreSchema(ctx context.Context) error {
	// ── installed_modules: extend the stub with new columns ──────────────────

	// source: official | community | direct
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules
		    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'direct'
		    CHECK (source IN ('official', 'community', 'direct'))
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.source: %w", err)
	}

	// Same 'custom' addition as module_registry_source_check below, just
	// missed here originally: this table's CHECK was never updated when
	// custom sources were introduced, so installing (InsertInstalledModule)
	// any custom-source module - not just querying the registry cache -
	// failed with "violates check constraint installed_modules_source_check"
	// (23514). Only ever hit now (2026-07-18) because this was the first
	// custom-source module actually installed rather than just listed in the
	// store. Same idempotent drop-then-recreate pattern; 'direct' stays for
	// any existing row.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules DROP CONSTRAINT IF EXISTS installed_modules_source_check
	`); err != nil {
		return fmt.Errorf("db: drop installed_modules_source_check: %w", err)
	}
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD CONSTRAINT installed_modules_source_check
		    CHECK (source IN ('official', 'community', 'direct', 'custom'))
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules_source_check: %w", err)
	}

	// db_role_password_enc: the AES-GCM-encrypted (Core's master key)
	// password for this module's dedicated Postgres LOGIN role
	// (module_{name}_role - see modules.provisionSchema in migrations.go).
	// NULL until the role is first provisioned as a LOGIN role; also NULL
	// for modules installed before this column existed, until Core next
	// provisions their schema (on the next boot or module update) and
	// backfills it - see provisionSchema's "upgrade path" case. Read/written
	// exclusively via GetModuleDBRolePassword/SetModuleDBRolePassword below,
	// never exposed over any API.
	//
	// Added as part of closing H-1/H-2 from the 2026-08-02 security audit:
	// before this, every Tier 2/3 Deno worker connected to Postgres using
	// Core's own DB credentials (see cmd/core/main.go's dbURL construction
	// for workerPool), relying on a Postgres search_path setting alone to
	// keep modules inside their own schema - search_path is a resolution
	// default for unqualified names, not an access control boundary, so a
	// compromised or malicious module's SQL could simply schema-qualify its
	// way into any other table in the database, including users and
	// core_settings. A per-module LOGIN role with GRANT/REVOKE actually
	// enforced by Postgres closes that.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules
		    ADD COLUMN IF NOT EXISTS db_role_password_enc TEXT
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.db_role_password_enc: %w", err)
	}

	// pii_migrated_at: when this module's own PII data (if any) was last
	// re-encrypted under its per-module derived key (crypto.DeriveModuleKey)
	// instead of the one raw MODULAB_MODULE_PII_KEY every Tier 2/3 worker
	// used to receive verbatim (2026-08-02 security audit, M-1). NULL means
	// "not migrated yet" - WorkerPool.buildWorker then also grants the
	// worker the raw shared key (as MODULAB_MODULE_PII_LEGACY_KEY) alongside
	// its own derived one, so the module's own admin-triggered migration
	// handler can decrypt old data under the old key and re-encrypt it under
	// the new one. Set once, by the admin API endpoint that invokes that
	// handler and only then marks this column - never by the module itself,
	// which has no access to installed_modules. See
	// IsModulePIIMigrated/SetModulePIIMigrated below.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules
		    ADD COLUMN IF NOT EXISTS pii_migrated_at TIMESTAMPTZ
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.pii_migrated_at: %w", err)
	}

	// 'manual' addition (2026-07-23): manually uploaded module ZIPs
	// (InstallManual/UpdateManual, installer.go) have no registry entry and
	// no release URL to re-download from - a distinct source value from
	// 'custom' (which is still a registry-backed GitHub repo, just an
	// admin-added one) so the Store UI can tell "third-party but tracked"
	// apart from "opaque local upload" and show the right badge/warning.
	// Same idempotent drop-then-recreate pattern as the 'custom' addition
	// above.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules DROP CONSTRAINT IF EXISTS installed_modules_source_check
	`); err != nil {
		return fmt.Errorf("db: drop installed_modules_source_check (manual): %w", err)
	}
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD CONSTRAINT installed_modules_source_check
		    CHECK (source IN ('official', 'community', 'direct', 'custom', 'manual'))
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules_source_check (manual): %w", err)
	}

	// release_url: exact URL the module.zip was downloaded from.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS release_url TEXT NOT NULL DEFAULT ''
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.release_url: %w", err)
	}

	// sha256: verified checksum at install/update time.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS sha256 TEXT NOT NULL DEFAULT ''
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.sha256: %w", err)
	}

	// manifest: full manifest.yaml as JSONB for the detail endpoint.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS manifest JSONB NOT NULL DEFAULT '{}'
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.manifest: %w", err)
	}

	// pinned: when true, update suggestions are suppressed for this module.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS pinned BOOLEAN NOT NULL DEFAULT FALSE
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.pinned: %w", err)
	}

	// cached_zip_path: old ZIP kept during an in-progress update for rollback.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS cached_zip_path TEXT
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.cached_zip_path: %w", err)
	}

	// available_version: set by the update-check when a newer version exists.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS available_version TEXT
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.available_version: %w", err)
	}

	// last_update_check: timestamp of the most recent update check.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS last_update_check TIMESTAMPTZ
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.last_update_check: %w", err)
	}

	// updated_at: bumped on every status change, update, pin toggle, etc.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.updated_at: %w", err)
	}

	// cosign_verified: whether installer.go's Cosign check actually passed
	// for the currently-installed version. Added 2026-07-05 - the
	// verification itself has run on every install/update since Cosign
	// support was added, but the result was only ever logged, never
	// persisted, so there was no way for an admin to see it anywhere. false
	// covers both "verification failed" and "no signature to check" (source
	// != official, or no cosign_sig_url yet) - callers that need to tell
	// those apart already have that detail in the install log.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS cosign_verified BOOLEAN NOT NULL DEFAULT FALSE
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.cosign_verified: %w", err)
	}

	// logo_url: the module's logo, carried over from module_registry.logo_url
	// (store.Entry.LogoURL, resolved by build-module.sh for official modules
	// or from the community manifest's logo field - see github.go) at the
	// moment of install/update. Previously the Store's resolved logo URL was
	// discarded once a module was actually installed, so the Home page's
	// module tiles had no way to show it and always fell back to the ModuLab
	// mark. NULL means no logo was set for that module.
	if _, err := p.Exec(ctx, `
		ALTER TABLE installed_modules ADD COLUMN IF NOT EXISTS logo_url TEXT
	`); err != nil {
		return fmt.Errorf("db: ensure installed_modules.logo_url: %w", err)
	}

	// ── module_registry ───────────────────────────────────────────────────────

	// Local cache of official registry.json + modulab-community index.
	// No PII, no credentials → no GCM encryption needed (spec section 2.4).
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS module_registry (
		    name            TEXT        PRIMARY KEY,
		    source          TEXT        NOT NULL CHECK (source IN ('official', 'community')),
		    source_repo     TEXT        NOT NULL,
		    release_asset   TEXT        NOT NULL,
		    cosign_sig_url  TEXT,
		    category        TEXT        NOT NULL,
		    latest_version  TEXT,
		    description     JSONB,
		    manifest_cache  JSONB,
		    synced_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure module_registry: %w", err)
	}

	// source CHECK originally only allowed 'official'/'community'. Custom
	// module sources (admin-added arbitrary GitHub repos, see custom_sources
	// below) need a third value. Postgres names an inline, unnamed CHECK
	// constraint "<table>_<column>_check" by default - drop-then-recreate
	// under that conventional name is idempotent and safe to run on every
	// boot (a fresh install's CREATE TABLE above already omits this value on
	// purpose, so this ALTER is what actually admits 'custom').
	if _, err := p.Exec(ctx, `
		ALTER TABLE module_registry DROP CONSTRAINT IF EXISTS module_registry_source_check
	`); err != nil {
		return fmt.Errorf("db: drop module_registry_source_check: %w", err)
	}
	if _, err := p.Exec(ctx, `
		ALTER TABLE module_registry ADD CONSTRAINT module_registry_source_check
		    CHECK (source IN ('official', 'community', 'custom'))
	`); err != nil {
		return fmt.Errorf("db: ensure module_registry_source_check: %w", err)
	}

	// cosign_pubkey: the Cosign public key (PEM text) to verify a custom
	// source's release against, copied in from custom_sources.pubkey at sync
	// time (store.FetchCustomRepo). Empty for official/community entries,
	// which always verify against the embedded officialPublicKey (see
	// modules.VerifyCosign) - a public key is not sensitive data by
	// definition (it exists to be shared), so unlike custom_sources.repo_url/
	// name below, this column is intentionally left unencrypted.
	if _, err := p.Exec(ctx, `
		ALTER TABLE module_registry ADD COLUMN IF NOT EXISTS cosign_pubkey TEXT
	`); err != nil {
		return fmt.Errorf("db: ensure module_registry.cosign_pubkey: %w", err)
	}

	// ── custom_sources ─────────────────────────────────────────────────────
	// Admin-added third-party module sources (HACS-style "custom repositories"),
	// on top of the built-in official/community registries. Each row is one
	// GitHub repo an admin has explicitly chosen to trust; store.RunSync polls
	// it the same way it polls official/community, producing module_registry
	// rows with source='custom'.
	//
	// repo_url_enc/name_enc are GCM-encrypted (URLs/names are PII-adjacent
	// per spec section 2.4's classification - see
	// feedback-encrypt-at-implementation-time). pubkey is the admin's manually
	// entered Cosign public key (PEM text, optional) - not encrypted, see the
	// cosign_pubkey column comment above for why. token_enc is an optional
	// GitHub personal access token (fine-grained or classic) for private
	// repos - a real credential, always GCM-encrypted, and unlike pubkey
	// NEVER echoed back to the frontend once saved (see
	// store.CustomSourceResponse's has_token bool instead of the raw value).
	// added_by stores the OIDC subject (users.id), not an email/name, so it
	// needs no encryption of its own - same pattern as
	// admin_quick_links.created_by.
	if _, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS custom_sources (
		    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
		    repo_url_enc TEXT        NOT NULL,
		    name_enc     TEXT        NOT NULL,
		    pubkey       TEXT        NOT NULL DEFAULT '',
		    token_enc    TEXT        NOT NULL DEFAULT '',
		    added_by     TEXT        NOT NULL DEFAULT '',
		    added_at     TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("db: ensure custom_sources: %w", err)
	}

	// token_enc: added after the table's initial release, same backfill
	// pattern as module_registry's incremental columns above.
	if _, err := p.Exec(ctx, `
		ALTER TABLE custom_sources ADD COLUMN IF NOT EXISTS token_enc TEXT NOT NULL DEFAULT ''
	`); err != nil {
		return fmt.Errorf("db: ensure custom_sources.token_enc: %w", err)
	}

	// cosign_sig_url: added after the table's initial release. ADD COLUMN IF
	// NOT EXISTS so this is a no-op on fresh installs (already in the CREATE
	// TABLE above) and safely backfills existing installations on next boot.
	// Without this, store.Entry.CosignSigURL was silently dropped between
	// FetchOfficialRegistry and installer.go's Cosign check, so verification
	// was always skipped.
	if _, err := p.Exec(ctx, `
		ALTER TABLE module_registry ADD COLUMN IF NOT EXISTS cosign_sig_url TEXT
	`); err != nil {
		return fmt.Errorf("db: ensure module_registry.cosign_sig_url: %w", err)
	}

	// description: added after the table's initial release, same backfill
	// pattern as cosign_sig_url above. Sourced from each module's own
	// manifest.yaml (official via registry.json, community via a direct
	// manifest.yaml fetch - see github.go), shown on the Module Store cards.
	// JSONB (not TEXT) because store.Entry.Description is a map of language
	// code → blurb, same shape as manifest.yaml's display_name, so the
	// frontend can resolve the user's UI language with an en-fallback lookup.
	if _, err := p.Exec(ctx, `
		ALTER TABLE module_registry ADD COLUMN IF NOT EXISTS description JSONB
	`); err != nil {
		return fmt.Errorf("db: ensure module_registry.description: %w", err)
	}

	// The column briefly shipped as plain TEXT (single English string) before
	// switching to the JSONB language-map shape above. Convert any
	// already-created TEXT column in place so upgrades from that short-lived
	// version don't fail with a type-mismatch on every subsequent sync.
	// No-op (WHERE finds nothing) once already JSONB, so safe to run every boot.
	if _, err := p.Exec(ctx, `
		DO $$
		BEGIN
		    IF EXISTS (
		        SELECT 1 FROM information_schema.columns
		        WHERE table_name = 'module_registry' AND column_name = 'description' AND data_type = 'text'
		    ) THEN
		        ALTER TABLE module_registry ALTER COLUMN description TYPE JSONB USING NULL;
		    END IF;
		END $$;
	`); err != nil {
		return fmt.Errorf("db: convert module_registry.description to jsonb: %w", err)
	}

	// logo_url: added after the table's initial release, same backfill
	// pattern as cosign_sig_url/description above. Absolute URL to the
	// module's logo image (build-module.sh computes it for official modules,
	// FetchCommunityRegistry for community ones - see github.go); empty
	// means the module ships no logo and the frontend falls back to the
	// ModuLab mark.
	if _, err := p.Exec(ctx, `
		ALTER TABLE module_registry ADD COLUMN IF NOT EXISTS logo_url TEXT
	`); err != nil {
		return fmt.Errorf("db: ensure module_registry.logo_url: %w", err)
	}

	// display_name: added after the table's initial release, same backfill
	// pattern as the columns above. Map of language code → human-readable
	// module name, same shape/source as description (manifest.yaml's own
	// display_name field) - the Module Store shows this instead of the raw
	// module identifier once present.
	if _, err := p.Exec(ctx, `
		ALTER TABLE module_registry ADD COLUMN IF NOT EXISTS display_name JSONB
	`); err != nil {
		return fmt.Errorf("db: ensure module_registry.display_name: %w", err)
	}

	// browse_url: added after the table's initial release, same backfill
	// pattern as the columns above. "View on GitHub" link target - for
	// official modules this is the module's own subdirectory in the
	// monorepo (build-module.sh computes it), not just the repo root.
	if _, err := p.Exec(ctx, `
		ALTER TABLE module_registry ADD COLUMN IF NOT EXISTS browse_url TEXT
	`); err != nil {
		return fmt.Errorf("db: ensure module_registry.browse_url: %w", err)
	}

	// store.ListEntries (internal/store/registry.go) filters
	// "WHERE ($1 = '' OR source = $1) AND ($2 = '' OR category = $2)" for
	// the Module Store's source/category filter UI. In practice this table
	// stays small (a handful to a few dozen modules), so this index is more
	// about correctness than a real performance need at today's scale - but
	// free to keep, and correct if the registry ever grows past a trivial
	// size (e.g. once a larger community index exists).
	if _, err := p.Exec(ctx, `
		CREATE INDEX IF NOT EXISTS idx_module_registry_source_category ON module_registry (source, category)
	`); err != nil {
		return fmt.Errorf("db: ensure idx_module_registry_source_category: %w", err)
	}

	return nil
}

// ---- Custom Module Sources ---------------------------------------------------

// CustomSourceRow is one row of custom_sources, decrypted and ready for
// internal use. Token is the decrypted GitHub PAT (empty for a public repo
// source) - callers exposing this over the API must NOT put it in a
// response; see store.CustomSourceResponse's has_token bool instead.
type CustomSourceRow struct {
	ID      string
	RepoURL string
	Name    string
	PubKey  string
	Token   string
	AddedBy string
	AddedAt time.Time
}

// CreateCustomSource inserts a new custom module source. repoURL, name, and
// token are encrypted at rest (see custom_sources' table comment); pubKeyPEM
// is stored as plaintext (see the cosign_pubkey column comment). Both
// pubKeyPEM and token may be empty - an empty token means a public repo, an
// empty pubKeyPEM falls back to unsigned/unverified installs (see
// modules.VerifyCosign).
func (p *Pool) CreateCustomSource(ctx context.Context, repoURL, name, pubKeyPEM, token, addedBy string) (CustomSourceRow, error) {
	encURL, err := crypto.Encrypt(p.masterKey, repoURL)
	if err != nil {
		return CustomSourceRow{}, fmt.Errorf("db: encrypt custom source repo_url: %w", err)
	}
	encName, err := crypto.Encrypt(p.masterKey, name)
	if err != nil {
		return CustomSourceRow{}, fmt.Errorf("db: encrypt custom source name: %w", err)
	}
	encToken, err := crypto.EncryptIfNotEmpty(p.masterKey, token)
	if err != nil {
		return CustomSourceRow{}, fmt.Errorf("db: encrypt custom source token: %w", err)
	}
	r := CustomSourceRow{RepoURL: repoURL, Name: name, PubKey: pubKeyPEM, Token: token, AddedBy: addedBy}
	err = p.QueryRow(ctx, `
		INSERT INTO custom_sources (repo_url_enc, name_enc, pubkey, token_enc, added_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, added_at
	`, encURL, encName, pubKeyPEM, encToken, addedBy).Scan(&r.ID, &r.AddedAt)
	if err != nil {
		return CustomSourceRow{}, fmt.Errorf("db: create custom_source: %w", err)
	}
	return r, nil
}

// ListCustomSources returns all custom sources, oldest first, decrypted
// (including Token - see CustomSourceRow's doc comment on why callers must
// be careful not to leak it back out over the API).
func (p *Pool) ListCustomSources(ctx context.Context) ([]CustomSourceRow, error) {
	rows, err := p.Query(ctx, `
		SELECT id, repo_url_enc, name_enc, pubkey, token_enc, added_by, added_at
		FROM custom_sources
		ORDER BY added_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("db: list custom_sources: %w", err)
	}
	defer rows.Close()

	var out []CustomSourceRow
	for rows.Next() {
		var r CustomSourceRow
		if err := rows.Scan(&r.ID, &r.RepoURL, &r.Name, &r.PubKey, &r.Token, &r.AddedBy, &r.AddedAt); err != nil {
			return nil, fmt.Errorf("db: scan custom_source: %w", err)
		}
		var decErr error
		if r.RepoURL, decErr = crypto.DecryptIfNotEmpty(p.masterKey, r.RepoURL); decErr != nil {
			return nil, fmt.Errorf("db: decrypt custom_source repo_url %q: %w", r.ID, decErr)
		}
		if r.Name, decErr = crypto.DecryptIfNotEmpty(p.masterKey, r.Name); decErr != nil {
			return nil, fmt.Errorf("db: decrypt custom_source name %q: %w", r.ID, decErr)
		}
		if r.Token, decErr = crypto.DecryptIfNotEmpty(p.masterKey, r.Token); decErr != nil {
			return nil, fmt.Errorf("db: decrypt custom_source token %q: %w", r.ID, decErr)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateCustomSource patches an existing custom source's display name,
// Cosign public key, and/or GitHub token. repo_url is intentionally not
// editable here - changing it would silently orphan whatever
// module_registry rows were fetched under the old URL (see
// DeleteEntriesBySourceRepo, which keys on exactly that repo_url); the
// correct path for a genuine URL change is delete-and-re-add.
//
// name/pubKeyPEM/token are *string, not string: nil means "leave this
// field unchanged", any non-nil value (including "") means "set it to
// exactly this". This is what lets an admin explicitly clear pubKeyPEM
// back to unsigned/unverified (added 2026-07-22 so a maintainer rotating
// or dropping their Cosign key doesn't require deleting and re-adding the
// whole source, losing added_by/added_at and re-triggering a full initial
// fetch) while a nil token from the caller leaves whatever is already on
// file untouched - the same "blank means keep existing secret" UX as the
// SMTP/OIDC secret fields, since token is the one truly sensitive field
// among these three.
func (p *Pool) UpdateCustomSource(ctx context.Context, id string, name, pubKeyPEM, token *string) (CustomSourceRow, bool, error) {
	var encName *string
	if name != nil {
		enc, err := crypto.Encrypt(p.masterKey, *name)
		if err != nil {
			return CustomSourceRow{}, false, fmt.Errorf("db: encrypt custom source name: %w", err)
		}
		encName = &enc
	}
	var encToken *string
	if token != nil {
		enc, err := crypto.EncryptIfNotEmpty(p.masterKey, *token)
		if err != nil {
			return CustomSourceRow{}, false, fmt.Errorf("db: encrypt custom source token: %w", err)
		}
		encToken = &enc
	}
	tag, err := p.Exec(ctx, `
		UPDATE custom_sources SET
		  name_enc  = COALESCE($2, name_enc),
		  pubkey    = COALESCE($3, pubkey),
		  token_enc = COALESCE($4, token_enc)
		WHERE id = $1
	`, id, encName, pubKeyPEM, encToken)
	if err != nil {
		return CustomSourceRow{}, false, fmt.Errorf("db: update custom_source %q: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return CustomSourceRow{}, false, nil
	}
	rows, err := p.ListCustomSources(ctx)
	if err != nil {
		return CustomSourceRow{}, false, err
	}
	for _, r := range rows {
		if r.ID == id {
			return r, true, nil
		}
	}
	return CustomSourceRow{}, false, nil
}

// GetCustomSourceByRepoURL finds a custom source by its (plaintext) repo
// URL. repo_url_enc can't be queried directly (GCM ciphertext is
// non-deterministic per encryption, see crypto.Encrypt's random nonce), so
// this decrypts-and-scans via ListCustomSources - fine at this table's scale
// (an admin homelab has a handful of custom sources, not thousands). Used at
// install/update time (modules.Install/Update) to resolve a private repo's
// token fresh from the DB, since Entry/module_registry deliberately never
// carry the token (see CustomSourceRow's doc comment).
func (p *Pool) GetCustomSourceByRepoURL(ctx context.Context, repoURL string) (CustomSourceRow, bool, error) {
	rows, err := p.ListCustomSources(ctx)
	if err != nil {
		return CustomSourceRow{}, false, err
	}
	for _, r := range rows {
		if r.RepoURL == repoURL {
			return r, true, nil
		}
	}
	return CustomSourceRow{}, false, nil
}

// DeleteCustomSource removes a custom source by id. Does not remove the
// module_registry rows it produced - store's next sync prunes those the
// normal "no longer seen" way (see store.pruneStaleEntries), unless the
// module is currently installed, in which case its registry metadata is kept
// exactly like any other pruned-but-installed module.
func (p *Pool) DeleteCustomSource(ctx context.Context, id string) (bool, error) {
	tag, err := p.Exec(ctx, `DELETE FROM custom_sources WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("db: delete custom_source %q: %w", id, err)
	}
	return tag.RowsAffected() > 0, nil
}

// ---- Installed Modules CRUD -------------------------------------------------

// ModuleStatus constants mirror the CHECK constraint on installed_modules.status.
const (
	ModuleStatusInstalling = "installing"
	ModuleStatusActive     = "active"
	ModuleStatusDegraded   = "degraded"
	ModuleStatusFailed     = "failed"
	ModuleStatusIsolated   = "isolated"
)

// InstalledModuleRow is a full row from installed_modules.
type InstalledModuleRow struct {
	Name             string          `json:"name"`
	Version          string          `json:"version"`
	Tier             int             `json:"tier"`
	Source           string          `json:"source"`
	ReleaseURL       string          `json:"release_url"`
	SHA256           string          `json:"sha256"`
	Manifest         json.RawMessage `json:"manifest,omitempty"` // raw JSONB — RawMessage serialises as-is, not base64
	Status           string          `json:"status"`
	Pinned           bool            `json:"pinned"`
	CosignVerified   bool            `json:"cosign_verified"`
	CachedZipPath    *string         `json:"cached_zip_path,omitempty"`
	AvailableVersion *string         `json:"available_version,omitempty"`
	LastUpdateCheck  *time.Time      `json:"last_update_check,omitempty"`
	LogoURL          *string         `json:"logo_url,omitempty"`
	InstalledAt      time.Time       `json:"installed_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
	// PIIMigratedAt is nil for a Tier 2/3 module that still needs its
	// migrate-pii-key handler run (see docs/Modul-DB-Sandbox_Plan_2026-08-02.md
	// Part B) - the frontend's ModulesPage uses this to show the "Migrate PII
	// key" action button. Always nil for a Tier 1 module (no worker, nothing
	// to migrate).
	PIIMigratedAt *time.Time `json:"pii_migrated_at,omitempty"`
}

// InsertInstalledModule writes a new module row with status "installing".
// Called at the start of the install transaction so the UI can show progress
// via the modul.state_change SSE event before migrations finish.
// cosignVerified is the result of installer.go's Cosign check for this
// specific install (added 2026-07-05 - previously computed and logged but
// discarded, never persisted anywhere an admin could see it).
// logoURL is carried over from the store.Entry the module was installed
// from (empty string if the module has no logo) - see the logo_url column
// comment in EnsureCoreSchema for why this is persisted at all.
func (p *Pool) InsertInstalledModule(ctx context.Context, name, version string, tier int, source, releaseURL, sha256 string, manifest []byte, cosignVerified bool, logoURL string) error {
	var logoURLArg any
	if logoURL != "" {
		logoURLArg = logoURL
	}
	_, err := p.Exec(ctx, `
		INSERT INTO installed_modules
		    (name, version, tier, source, release_url, sha256, manifest, status, cosign_verified, logo_url, installed_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'installing', $8, $9, now(), now())
	`, name, version, tier, source, releaseURL, sha256, manifest, cosignVerified, logoURLArg)
	if err != nil {
		return fmt.Errorf("db: insert installed_module %q: %w", name, err)
	}
	return nil
}

// UpdateModuleStatus sets the status (and bumps updated_at) for the named module.
// Returns false when no such module exists.
func (p *Pool) UpdateModuleStatus(ctx context.Context, name, status string) (bool, error) {
	tag, err := p.Exec(ctx, `
		UPDATE installed_modules SET status = $2, updated_at = now() WHERE name = $1
	`, name, status)
	if err != nil {
		return false, fmt.Errorf("db: update module status %q → %q: %w", name, status, err)
	}
	return tag.RowsAffected() > 0, nil
}

// GetInstalledModule returns the row for name, or (row{}, false, nil) if absent.
func (p *Pool) GetInstalledModule(ctx context.Context, name string) (InstalledModuleRow, bool, error) {
	var r InstalledModuleRow
	err := p.QueryRow(ctx, `
		SELECT name, version, tier, source, release_url, sha256, manifest,
		       status, pinned, cosign_verified, cached_zip_path, available_version, last_update_check,
		       logo_url, installed_at, updated_at, pii_migrated_at
		FROM installed_modules WHERE name = $1
	`, name).Scan(
		&r.Name, &r.Version, &r.Tier, &r.Source, &r.ReleaseURL, &r.SHA256, &r.Manifest,
		&r.Status, &r.Pinned, &r.CosignVerified, &r.CachedZipPath, &r.AvailableVersion, &r.LastUpdateCheck,
		&r.LogoURL, &r.InstalledAt, &r.UpdatedAt, &r.PIIMigratedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return InstalledModuleRow{}, false, nil
		}
		return InstalledModuleRow{}, false, fmt.Errorf("db: get installed_module %q: %w", name, err)
	}
	return r, true, nil
}

// ListInstalledModules returns all installed module rows, ordered by name.
func (p *Pool) ListInstalledModules(ctx context.Context) ([]InstalledModuleRow, error) {
	rows, err := p.Query(ctx, `
		SELECT name, version, tier, source, release_url, sha256, manifest,
		       status, pinned, cosign_verified, cached_zip_path, available_version, last_update_check,
		       logo_url, installed_at, updated_at, pii_migrated_at
		FROM installed_modules ORDER BY name ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("db: list installed_modules: %w", err)
	}
	defer rows.Close()

	var out []InstalledModuleRow
	for rows.Next() {
		var r InstalledModuleRow
		if err := rows.Scan(
			&r.Name, &r.Version, &r.Tier, &r.Source, &r.ReleaseURL, &r.SHA256, &r.Manifest,
			&r.Status, &r.Pinned, &r.CosignVerified, &r.CachedZipPath, &r.AvailableVersion, &r.LastUpdateCheck,
			&r.LogoURL,
			&r.InstalledAt, &r.UpdatedAt, &r.PIIMigratedAt,
		); err != nil {
			return nil, fmt.Errorf("db: scan installed_module: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteInstalledModule removes the module row. Schema/storage cleanup is
// handled separately by the uninstaller (internal/modules/uninstaller.go).
func (p *Pool) DeleteInstalledModule(ctx context.Context, name string) (bool, error) {
	tag, err := p.Exec(ctx, `DELETE FROM installed_modules WHERE name = $1`, name)
	if err != nil {
		return false, fmt.Errorf("db: delete installed_module %q: %w", name, err)
	}
	return tag.RowsAffected() > 0, nil
}

// SetModuleCachedZip stores the rollback ZIP path during an in-progress update.
func (p *Pool) SetModuleCachedZip(ctx context.Context, name, path string) error {
	_, err := p.Exec(ctx, `
		UPDATE installed_modules SET cached_zip_path = $2, updated_at = now() WHERE name = $1
	`, name, path)
	return err
}

// ClearModuleCachedZip removes the rollback ZIP path after a successful update.
func (p *Pool) ClearModuleCachedZip(ctx context.Context, name string) error {
	_, err := p.Exec(ctx, `
		UPDATE installed_modules SET cached_zip_path = NULL, updated_at = now() WHERE name = $1
	`, name)
	return err
}

// SetModuleAvailableVersion records that a newer version is available.
// Pass "" to clear after an update.
func (p *Pool) SetModuleAvailableVersion(ctx context.Context, name, version string) error {
	var v any
	if version != "" {
		v = version
	}
	_, err := p.Exec(ctx, `
		UPDATE installed_modules
		SET available_version = $2, last_update_check = now(), updated_at = now()
		WHERE name = $1
	`, name, v)
	return err
}

// SetModulePinned sets or clears the pinned flag for the named module.
func (p *Pool) SetModulePinned(ctx context.Context, name string, pinned bool) (bool, error) {
	tag, err := p.Exec(ctx, `
		UPDATE installed_modules SET pinned = $2, updated_at = now() WHERE name = $1
	`, name, pinned)
	if err != nil {
		return false, fmt.Errorf("db: set module pinned %q: %w", name, err)
	}
	return tag.RowsAffected() > 0, nil
}

// ---- Module DB role password (per-module Postgres LOGIN role) --------------
//
// See installed_modules.db_role_password_enc's column comment (above, in
// EnsureModuleStoreSchema) for why this exists. Both methods assume the
// installed_modules row for name already exists - true for every real
// caller, since modules.provisionSchema (migrations.go) only ever runs
// after modules.Deps.DB.InsertInstalledModule during Install/Update.

// SetModuleDBRolePassword stores password (plaintext in memory only for the
// duration of this call) AES-GCM-encrypted with Core's master key, for the
// named module's dedicated Postgres LOGIN role. Called exactly once per
// role - the first time modules.provisionSchema creates or upgrades it -
// never to rotate an existing password (a live Deno worker already holds a
// connection string built from the old one; rotating here without also
// restarting every worker for this module would just break its DB access).
func (p *Pool) SetModuleDBRolePassword(ctx context.Context, moduleName, password string) error {
	enc, err := crypto.Encrypt(p.masterKey, password)
	if err != nil {
		return fmt.Errorf("db: encrypt module db role password for %q: %w", moduleName, err)
	}
	if _, err := p.Exec(ctx, `
		UPDATE installed_modules SET db_role_password_enc = $2 WHERE name = $1
	`, moduleName, enc); err != nil {
		return fmt.Errorf("db: set module db role password for %q: %w", moduleName, err)
	}
	return nil
}

// GetModuleDBRolePassword returns the decrypted Postgres role password for
// moduleName. ok is false if no password has been set yet - either the
// module predates the per-module DB role feature and provisionSchema
// hasn't run for it since (upgrade path, see provisionSchema), or the
// installed_modules row doesn't exist yet (caller error - see this
// section's doc comment above).
func (p *Pool) GetModuleDBRolePassword(ctx context.Context, moduleName string) (password string, ok bool, err error) {
	var enc *string
	if err := p.QueryRow(ctx, `
		SELECT db_role_password_enc FROM installed_modules WHERE name = $1
	`, moduleName).Scan(&enc); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("db: get module db role password for %q: %w", moduleName, err)
	}
	if enc == nil || *enc == "" {
		return "", false, nil
	}
	plain, err := crypto.Decrypt(p.masterKey, *enc)
	if err != nil {
		return "", false, fmt.Errorf("db: decrypt module db role password for %q: %w", moduleName, err)
	}
	return plain, true, nil
}

// ClearModuleDBRolePassword sets db_role_password_enc back to SQL NULL for
// moduleName - called when the role itself is dropped (modules.
// dropModuleSchema), so a stale encrypted password can never linger for a
// role that no longer exists. Deliberately a separate method from
// SetModuleDBRolePassword rather than SetModuleDBRolePassword(ctx, name,
// ""): encrypting the empty string still produces a non-NULL ciphertext,
// which GetModuleDBRolePassword would then decrypt back to ("", true, nil)
// - "there is a password and it's empty" - instead of the ("", false, nil)
// "no password on file" that a caller re-provisioning this module name
// needs to see in order to generate a fresh one.
func (p *Pool) ClearModuleDBRolePassword(ctx context.Context, moduleName string) error {
	if _, err := p.Exec(ctx, `
		UPDATE installed_modules SET db_role_password_enc = NULL WHERE name = $1
	`, moduleName); err != nil {
		return fmt.Errorf("db: clear module db role password for %q: %w", moduleName, err)
	}
	return nil
}

// ---- Module PII key migration (per-module derived key, M-1) ----------------
//
// See installed_modules.pii_migrated_at's column comment above for the
// full picture. IsModulePIIMigrated is deliberately fail-safe on error:
// callers (WorkerPool.buildWorker, via modules.modulePIIMigrated) treat any
// failure to determine the true state as "not migrated", which means the
// worker still receives the legacy key alongside its derived one - the
// safe direction to be wrong in is "grant the old key one boot longer than
// strictly necessary", not "assume migrated and let a module's own
// decrypt-under-the-old-key calls start failing".

// IsModulePIIMigrated reports whether moduleName's pii_migrated_at is set.
func (p *Pool) IsModulePIIMigrated(ctx context.Context, moduleName string) (bool, error) {
	var migratedAt *time.Time
	if err := p.QueryRow(ctx, `
		SELECT pii_migrated_at FROM installed_modules WHERE name = $1
	`, moduleName).Scan(&migratedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("db: check module pii migrated for %q: %w", moduleName, err)
	}
	return migratedAt != nil, nil
}

// SetModulePIIMigrated marks moduleName's PII migration as complete (sets
// pii_migrated_at to now()). Called by the admin API handler that invokes
// the module's own migrate-pii-key handler, only after that call reports
// success - never by the module itself.
func (p *Pool) SetModulePIIMigrated(ctx context.Context, moduleName string) error {
	if _, err := p.Exec(ctx, `
		UPDATE installed_modules SET pii_migrated_at = now() WHERE name = $1
	`, moduleName); err != nil {
		return fmt.Errorf("db: set module pii migrated for %q: %w", moduleName, err)
	}
	return nil
}
