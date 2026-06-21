-- Adds the users table: one row per person who has ever logged in via
-- OIDC. Rows are created/updated by JIT provisioning on login (spec
-- section 3.3), never by a separate "create account" step - there is no
-- registration flow, only "log in with your IdP account for the first
-- time".
--
-- id is the OIDC "sub" claim, not a generated UUID: it is already globally
-- unique per issuer, and using it directly avoids a separate lookup table
-- mapping IdP identities to internal ids.
CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('super-admin', 'org-admin', 'user', 'pending')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
