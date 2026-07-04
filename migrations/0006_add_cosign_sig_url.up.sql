-- Fixes a bug where the Cosign signature URL was parsed from registry.json /
-- the community index (internal/store/github.go) into Entry.CosignSigURL,
-- but module_registry had no column to persist it and UpsertEntry/ListEntries/
-- GetEntry never read or wrote it. As a result entry.CosignSigURL was always
-- empty by the time internal/modules/installer.go checked it, so Cosign
-- verification was skipped for every module ("cosign skipped (no sig URL in
-- registry)"), even officially signed ones.

ALTER TABLE module_registry
    ADD COLUMN IF NOT EXISTS cosign_sig_url TEXT;
