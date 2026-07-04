-- Reverses 0005_remove_dns_challenge_settings.up.sql.
-- There is nothing meaningful to restore: the deleted rows held encrypted
-- provider/credential values that are gone once the row is gone, and the
-- feature they configured no longer exists in the code. This is a no-op
-- down migration kept only so the migration chain stays reversible.

-- no-op
