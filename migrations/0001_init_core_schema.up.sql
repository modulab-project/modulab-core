-- Core's own bootstrap state. golang-migrate tracks its own version table
-- separately; this migration only creates Core's application tables.

CREATE TABLE core_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per installed module (spec section 4). The actual per-module
-- PostgreSQL schemas are created separately at install time, scoped to a
-- dedicated role per module (spec section 4.3) - this table only tracks
-- Core's view of what is installed.
CREATE TABLE installed_modules (
    name         TEXT PRIMARY KEY,
    version      TEXT NOT NULL,
    tier         SMALLINT NOT NULL CHECK (tier IN (1, 2, 3)),
    scope        TEXT NOT NULL CHECK (scope IN ('per-location', 'cross-location')),
    status       TEXT NOT NULL DEFAULT 'installing',
    installed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
