#!/bin/bash
# Re-set the application user's password using MD5 so PgBouncer (auth_type=md5)
# can authenticate against it. Postgres 16 defaults to scram-sha-256 even when
# password_encryption=md5 is set at the server level, because the initdb user
# creation runs before the postgresql.conf flag takes effect.
#
# This script runs once on first container start (docker-entrypoint-initdb.d).
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    ALTER USER "${POSTGRES_USER}" WITH PASSWORD '${POSTGRES_PASSWORD}';
EOSQL
