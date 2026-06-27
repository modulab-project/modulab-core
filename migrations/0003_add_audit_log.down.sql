-- Drops the trigger first (must precede table drop or it would error trying
-- to drop a trigger on a non-existent table in some Postgres versions).
DROP TRIGGER IF EXISTS audit_log_before_change ON audit_log;
DROP FUNCTION IF EXISTS audit_log_immutable();
DROP TABLE IF EXISTS audit_log;
