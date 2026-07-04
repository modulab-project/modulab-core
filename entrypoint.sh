#!/bin/sh
# Container entrypoint, runs as root (see Dockerfile - USER is intentionally
# NOT set there anymore) so this script can fix ownership before dropping
# privileges. Needed because MODULAB_MODULE_DATA_DIR is normally a
# persistent named volume (deploy/docker-compose.yml's modulab-modules-data)
# that predates the non-root migration: Docker only seeds a *brand-new*
# volume's initial ownership from the image, so any volume that already had
# content (installed modules, uploaded files) keeps its old root ownership
# forever unless something chowns it after the mount happens - which can
# only be done at container start, not at image build time. This runs on
# every start; it's a cheap no-op once ownership is already correct.
set -e

if [ -d "$MODULAB_MODULE_DATA_DIR" ]; then
    chown -R modulab:modulab "$MODULAB_MODULE_DATA_DIR"
fi

# gosu (not su/sudo - no shell, no PID juggling, signals pass straight
# through to modulab-core) drops from root to the unprivileged "modulab"
# user for the actual, long-running process.
exec gosu modulab "$@"
