-- Adds the users table: one row per person who has ever logged in via
-- OIDC. Rows are created/updated by JIT provisioning on login (spec
-- section 3.3), never by a separate "create account" step - there is no
-- registration flow, only "log in with your IdP account for the first
-- time".
--
-- id is the OIDC "sub" claim, not a generated UUID: it is already globally
-- unique per issuer, and using it directly avoids a separate lookup table
-- mapping IdP identities to internal ids.
--
-- name, approved, locked, and ui_language were added after this table's
-- initial release via idempotent ALTER TABLE ... ADD COLUMN IF NOT EXISTS
-- statements in EnsureCoreSchema (backend/internal/db/db.go), which is the
-- mechanism actually applied against a running instance - golang-migrate
-- itself is not invoked anywhere in this repo's Docker image or deploy
-- scripts. They are included directly here so this file (read as
-- documentation of the schema's history) matches what EnsureCoreSchema
-- actually produces, rather than only reflecting the table's first release.
CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    role          TEXT NOT NULL CHECK (role IN ('super-admin', 'org-admin', 'user', 'pending')),
    approved      BOOLEAN NOT NULL DEFAULT false,
    locked        BOOLEAN NOT NULL DEFAULT false,
    ui_language   TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
