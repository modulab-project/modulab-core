-- Audit log: append-only record of every security-relevant action in Core.
-- Made technically immutable at the DB layer via two mechanisms:
--   1. A BEFORE trigger that raises an exception on any UPDATE or DELETE.
--      Even a direct psql session cannot modify rows without first DROPping
--      the trigger - which requires the DB superuser, not the app role.
--   2. A HMAC-SHA256 chain hash (prev_hash / hash columns) so any tampering
--      is cryptographically detectable even if someone manages to bypass the
--      trigger (spec section 10.5).
--
-- actor_email_enc and target_email_enc are AES-256-GCM ciphertext so a DB
-- dump does not leak PII. details_enc is the same: arbitrary JSON payload
-- encrypted at rest (spec section 2.4 class B).

CREATE TABLE audit_log (
    id              BIGSERIAL   PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type      TEXT        NOT NULL,   -- e.g. "user.approved", "config.smtp"
    actor_id        TEXT        NOT NULL,   -- OIDC sub of the admin who acted
    actor_email_enc TEXT        NOT NULL,   -- GCM-encrypted email, for display
    target_id       TEXT        NOT NULL DEFAULT '',  -- subject acted on ('' if none)
    target_email_enc TEXT       NOT NULL DEFAULT '',  -- GCM-encrypted target email
    details_enc     TEXT        NOT NULL DEFAULT '',  -- GCM-encrypted JSON extras
    prev_hash       TEXT        NOT NULL DEFAULT '',  -- HMAC-SHA256 of previous row
    hash            TEXT        NOT NULL DEFAULT ''   -- HMAC-SHA256 of this row
);

-- Trigger function: raises an exception on any attempt to UPDATE or DELETE.
-- The trigger body never reaches a RETURN NEW / RETURN OLD - it always aborts.
CREATE OR REPLACE FUNCTION audit_log_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log rows are immutable and cannot be modified or deleted';
END;
$$;

CREATE TRIGGER audit_log_before_change
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
