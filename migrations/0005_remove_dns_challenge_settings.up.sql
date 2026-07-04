-- The DNS-challenge setup-wizard step / admin panel was a configuration-only
-- placeholder: nothing in Core ever actually talked to the stored provider
-- (no Traefik integration, no certificate issuance), and the feature has
-- been removed entirely from the backend and frontend. This drops whatever
-- was persisted for it so no orphaned settings remain in core_settings.
--
-- Note: this is unrelated to Traefik's own Let's Encrypt DNS-01 challenge
-- (deploy/docker-compose.yml, CF_DNS_API_TOKEN in .env) which is still in
-- active use and is not touched by this migration.

DELETE FROM core_settings WHERE key IN ('dns_challenge_provider', 'dns_challenge_credentials_enc');
