#!/usr/bin/env bash
#
# backup.sh — creates a compressed pg_dump backup of ModuLab Core's Postgres
# database via `docker exec` against the running postgres container from
# deploy/docker-compose.yml.
#
# IMPORTANT — MODULAB_MASTER_KEY IS NOT PART OF THIS BACKUP.
# Every credential, secret, and piece of PII in the database (OIDC client
# secret, SMTP credentials, AI provider keys, module gateway credentials,
# audit log PII, user email/name, ...) is stored encrypted at rest with
# AES-256-GCM under MODULAB_MASTER_KEY (see .env.example and
# backend/internal/crypto). A pg_dump of the encrypted columns is worthless
# without that same key: restoring this backup to a fresh instance with a
# different or missing MODULAB_MASTER_KEY leaves every encrypted field
# permanently undecryptable - there is no way to recover it after the fact,
# by design (that's the whole point of the encryption).
#
# This script deliberately does NOT read, copy, print, or otherwise touch
# MODULAB_MASTER_KEY. Back it up yourself, separately, out-of-band (e.g. a
# password manager or a physically separate secret store) - never in the
# same place as the database backup this script produces.
#
# Usage:
#   ./scripts/backup.sh
#
# Configuration (environment variables, all optional):
#   POSTGRES_CONTAINER   Name of the running postgres container.
#                         Default: deploy-postgres-1 (docker compose's
#                         default naming for the "postgres" service defined
#                         in deploy/docker-compose.yml, project dir "deploy").
#                         Override if you run with --project-name or a
#                         different directory name, e.g.:
#                           POSTGRES_CONTAINER=modulab-postgres-1 ./scripts/backup.sh
#   POSTGRES_DB           Database name to dump. Default: modulab
#                         (matches deploy/.env's POSTGRES_DB in the common
#                         case; override if you changed it).
#   POSTGRES_USER         Role to connect as for the dump. Default: modulab
#                         (matches deploy/.env's POSTGRES_USER).
#   BACKUP_DIR            Where to write the resulting .dump file.
#                         Default: ./backups (relative to repo root).
#
# Output: BACKUP_DIR/modulab-<POSTGRES_DB>-<UTC timestamp>.dump
# Restore with:
#   docker exec -i <container> pg_restore -U <user> -d <db> --clean --if-exists < backup.dump
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-deploy-postgres-1}"
POSTGRES_DB="${POSTGRES_DB:-modulab}"
POSTGRES_USER="${POSTGRES_USER:-modulab}"
BACKUP_DIR="${BACKUP_DIR:-${ROOT}/backups}"

echo "============================================================"
echo " ModuLab Core - PostgreSQL backup"
echo "============================================================"
echo
echo "WARNING: This backup contains only encrypted PII/secrets."
echo "It is WORTHLESS without MODULAB_MASTER_KEY, which is NOT"
echo "included in this backup or touched by this script in any way."
echo "Back up MODULAB_MASTER_KEY separately, out-of-band, and keep"
echo "it away from wherever this backup file ends up - losing the"
echo "key means every encrypted column in this dump is permanently"
echo "unrecoverable, even with a perfect database restore."
echo
echo "============================================================"
echo

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker is not installed or not on PATH" >&2
  exit 1
fi

if ! docker inspect "${POSTGRES_CONTAINER}" >/dev/null 2>&1; then
  echo "error: container '${POSTGRES_CONTAINER}' not found." >&2
  echo "       Set POSTGRES_CONTAINER to the actual running postgres" >&2
  echo "       container name (check with: docker ps)." >&2
  exit 1
fi

mkdir -p "${BACKUP_DIR}"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_FILE="${BACKUP_DIR}/modulab-${POSTGRES_DB}-${TIMESTAMP}.dump"

echo "Container: ${POSTGRES_CONTAINER}"
echo "Database:  ${POSTGRES_DB}"
echo "User:      ${POSTGRES_USER}"
echo "Output:    ${OUT_FILE}"
echo

docker exec "${POSTGRES_CONTAINER}" \
  pg_dump -Fc -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" > "${OUT_FILE}"

echo "Backup written: ${OUT_FILE} ($(du -h "${OUT_FILE}" | cut -f1))"
echo
echo "Reminder: MODULAB_MASTER_KEY was NOT backed up by this script."
echo "Restore with:"
echo "  docker exec -i ${POSTGRES_CONTAINER} pg_restore -U ${POSTGRES_USER} -d ${POSTGRES_DB} --clean --if-exists < ${OUT_FILE}"
