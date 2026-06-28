-- Module Store: extends the installed_modules stub (created in
-- EnsureCoreSchema) with the full column set needed for the install/update/
-- uninstall pipeline (spec section 4.3/4.9/4.10), and adds module_registry
-- as the local cache for the official + community registry sync (spec 4.10).
--
-- installed_modules already has: name, version, tier, scope, status,
-- installed_at — all other columns are added via idempotent ALTERs below,
-- mirroring the same pattern used for users.approved / users.name / users.locked.
--
-- module_registry holds no PII and no credentials — only public GitHub
-- metadata — so no GCM encryption is needed (spec section 2.4 "unkritisch").

-- ── installed_modules: new columns ──────────────────────────────────────────

-- source: where the module came from.
ALTER TABLE installed_modules
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'direct'
    CHECK (source IN ('official', 'community', 'direct'));

-- release_url: the exact URL the module.zip was downloaded from.
-- Stored as plaintext — it is a public GitHub URL, not a credential.
ALTER TABLE installed_modules
    ADD COLUMN IF NOT EXISTS release_url TEXT NOT NULL DEFAULT '';

-- sha256: hex-encoded SHA-256 checksum that was verified at install/update time.
ALTER TABLE installed_modules
    ADD COLUMN IF NOT EXISTS sha256 TEXT NOT NULL DEFAULT '';

-- manifest: full parsed manifest.yaml stored as JSONB for quick access
-- without re-reading the ZIP (used by /v1/modules/{id} detail endpoint).
ALTER TABLE installed_modules
    ADD COLUMN IF NOT EXISTS manifest JSONB NOT NULL DEFAULT '{}';

-- pinned: when true, Core never offers or applies automatic update suggestions
-- for this module. Set/cleared via POST|DELETE /v1/modules/{id}/pin.
ALTER TABLE installed_modules
    ADD COLUMN IF NOT EXISTS pinned BOOLEAN NOT NULL DEFAULT FALSE;

-- cached_zip_path: filesystem path to the previously installed ZIP kept during
-- an in-progress update for rollback purposes. NULL when no update is running.
-- Cleared on successful update completion.
ALTER TABLE installed_modules
    ADD COLUMN IF NOT EXISTS cached_zip_path TEXT;

-- available_version: set by the daily update-check when a newer version exists
-- in the registry. NULL when up to date or not yet checked. Cleared after update.
ALTER TABLE installed_modules
    ADD COLUMN IF NOT EXISTS available_version TEXT;

-- last_update_check: timestamp of the most recent update check for this module.
-- Allows the UI to show "last checked N minutes ago" and lets the scheduler
-- skip modules that were checked recently during the daily run.
ALTER TABLE installed_modules
    ADD COLUMN IF NOT EXISTS last_update_check TIMESTAMPTZ;

-- updated_at: bumped on every status change, update, pin toggle, etc.
-- Separate from installed_at so the UI can show both "installed" and "last changed".
ALTER TABLE installed_modules
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- ── module_registry ──────────────────────────────────────────────────────────

-- Local cache of the official registry.json and modulab-community index.
-- Populated by the daily sync goroutine (internal/store/sync.go) and by
-- POST /v1/store/sync. Browsable offline using cached data.
CREATE TABLE IF NOT EXISTS module_registry (
    name            TEXT        PRIMARY KEY,
    source          TEXT        NOT NULL CHECK (source IN ('official', 'community')),
    -- source_repo: GitHub repo URL for this module.
    -- For official modules: https://github.com/modulab-project/modulab-modules
    -- For community: the developer's own repo.
    source_repo     TEXT        NOT NULL,
    -- release_asset: filename of the ZIP asset in GitHub Releases,
    -- e.g. "rezepte.zip". Core constructs the full release_url from
    -- source_repo + GitHub Releases API + release_asset at install time.
    release_asset   TEXT        NOT NULL,
    category        TEXT        NOT NULL,
    -- latest_version: populated from registry.json (official) or GitHub
    -- Releases API (community) during the daily sync.
    latest_version  TEXT,
    -- manifest_cache: last known manifest.yaml content as JSONB, so the Store
    -- browse page can show full metadata without a live GitHub fetch.
    manifest_cache  JSONB,
    synced_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
