-- Reverses 0006_add_cosign_sig_url.up.sql.

ALTER TABLE module_registry
    DROP COLUMN IF EXISTS cosign_sig_url;
