-- Reverses 0004_add_module_store.up.sql.
-- Drops module_registry entirely and removes the columns added to
-- installed_modules. The original stub columns (name, version, tier, scope,
-- status, installed_at) are left in place — they were created by
-- EnsureCoreSchema, not this migration.

DROP TABLE IF EXISTS module_registry;

ALTER TABLE installed_modules DROP COLUMN IF EXISTS source;
ALTER TABLE installed_modules DROP COLUMN IF EXISTS release_url;
ALTER TABLE installed_modules DROP COLUMN IF EXISTS sha256;
ALTER TABLE installed_modules DROP COLUMN IF EXISTS manifest;
ALTER TABLE installed_modules DROP COLUMN IF EXISTS pinned;
ALTER TABLE installed_modules DROP COLUMN IF EXISTS cached_zip_path;
ALTER TABLE installed_modules DROP COLUMN IF EXISTS available_version;
ALTER TABLE installed_modules DROP COLUMN IF EXISTS last_update_check;
ALTER TABLE installed_modules DROP COLUMN IF EXISTS updated_at;
