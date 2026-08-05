#!/usr/bin/env bash
#
# check-and-push.sh — pre-flight check before "git add -A && git commit && git push".
#
# Runs the same checks CI/a reviewer would expect to already pass, catches
# them locally first, and only then walks you through add -> commit -> push.
# Nothing here runs "git add" or touches git at all until every check has
# passed.
#
# OPTIONAL developer convenience — nothing in CI, the Dockerfile or the
# release process invokes this. It is tracked in the repo (rather than kept
# as a local-only file) so that it sits next to .github/workflows/ci.yml: the
# tool versions it pins have to match the workflow's, and a bump to one that
# forgets the other now shows up as a diff instead of as a local run that
# quietly checks something else than the gate it's imitating.
#
# Usage:
#   ./scripts/check-and-push.sh                 # full flow: checks, then commit + push
#   ./scripts/check-and-push.sh --no-push       # checks + commit, skip the push
#   ./scripts/check-and-push.sh --check-only    # just run the checks, no git actions
#   ./scripts/check-and-push.sh --help          # all flags
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

# --- pinned tool versions -------------------------------------------------
# Kept in lockstep with .github/workflows/ci.yml on purpose: a local run that
# uses a different linter/scanner version than CI is worse than no local run,
# because it produces a green light CI then contradicts.
#   ci.yml "Lint":        golangci-lint-action with version: v2.12
#   ci.yml "govulncheck": go run golang.org/x/vuln/cmd/govulncheck@v1.6.0
# These two constants are not trusted to stay in sync by hand — the
# ci_parity_check step below reads ci.yml on every run and says so when they
# drift apart. Bump them here whenever ci.yml is bumped.
GOLANGCI_VERSION="v2.12"
GOVULNCHECK_VERSION="v1.6.0"
CI_WORKFLOW=".github/workflows/ci.yml"

# --- flags ----------------------------------------------------------------
DO_PUSH=1
DO_GIT=1
DO_BACKEND=1
DO_FRONTEND=1
DO_DOCKER=0
FAST=0
KEEP_GOING=0
NO_FIX=0
PARALLEL=0
COMMIT_MSG_ARG=""
SCOPE_SET=0

usage() {
  cat <<'EOF'
check-and-push.sh — local pre-flight checks, then add/commit/push.

Flags:
  --no-push        Run checks and commit, but do not push.
  --check-only     Run checks only. No staging, no commit, no push, no file
                   rewrites (implies --no-fix).
  --backend        Run backend checks only.
  --frontend       Run frontend checks only.
                   (--backend and --frontend together = both, i.e. the default)
  --docker         Additionally build the root Dockerfile, like CI's
                   "docker-build-check" job. Slow; off by default.
  --fast           Skip the two network-bound checks (govulncheck, npm audit).
  --keep-going     Run every check even after one fails, instead of stopping
                   at the first failure. Git actions are still skipped if
                   anything failed.
  --no-fix         Never modify files: report unformatted Go files instead of
                   running "gofmt -w" on them.
  --parallel       Run the backend and frontend suites concurrently. Output is
                   buffered per suite and printed in order once both finish,
                   so you lose live progress but roughly halve the wall time.
  -m, --message M  Use M as the commit message instead of prompting. Makes the
                   whole script non-interactive.
  -h, --help       This text.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --no-push)    DO_PUSH=0 ;;
    --check-only) DO_GIT=0; DO_PUSH=0; NO_FIX=1 ;;
    --backend)    DO_BACKEND=1; [ $SCOPE_SET -eq 0 ] && DO_FRONTEND=0; SCOPE_SET=1 ;;
    --frontend)   DO_FRONTEND=1; [ $SCOPE_SET -eq 0 ] && DO_BACKEND=0; SCOPE_SET=1 ;;
    --docker)     DO_DOCKER=1 ;;
    --fast)       FAST=1 ;;
    --keep-going) KEEP_GOING=1 ;;
    --no-fix)     NO_FIX=1 ;;
    --parallel)   PARALLEL=1 ;;
    -m|--message)
      shift
      if [ $# -eq 0 ]; then echo "--message needs an argument" >&2; exit 1; fi
      COMMIT_MSG_ARG="$1"
      ;;
    --message=*)  COMMIT_MSG_ARG="${1#--message=}" ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; echo "Try --help." >&2; exit 1 ;;
  esac
  shift
done

# --- output helpers -------------------------------------------------------
# Colour only when stdout is a terminal: with --parallel the suites write to
# temp files, and escape codes in a log that later gets cat'd are fine, but
# piping the script into a file or a pager should stay readable.
if [ -t 1 ]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
  BOLD=""; RED=""; GREEN=""; YELLOW=""; DIM=""; RESET=""
fi
step()  { printf "\n%s==> %s%s\n" "$BOLD" "$1" "$RESET"; }
ok()    { printf "%s✓ %s%s\n" "$GREEN" "$1" "$RESET"; }
warn()  { printf "%s! %s%s\n" "$YELLOW" "$1" "$RESET"; }
fail()  { printf "%s✗ %s%s\n" "$RED" "$1" "$RESET"; }
note()  { printf "%s  %s%s\n" "$DIM" "$1" "$RESET"; }

FAILED=0
START_TS=$SECONDS

# Per-step results are appended to files rather than bash arrays, so they
# survive the subshells the suites run in (--parallel) and can be merged into
# one summary at the end. Format: STATUS<TAB>SECONDS<TAB>LABEL
RUNDIR="$(mktemp -d "${TMPDIR:-/tmp}/check-and-push.XXXXXX")"
SUITE="main"

# --- cleanup / interruption safety ----------------------------------------
# Without this, a Ctrl-C at the commit prompt (or any hard failure after
# "git add -A") leaves a fully staged working tree behind with no indication
# that it happened — the next unrelated "git commit" would then sweep it all
# up silently.
STAGED=0
COMMITTED=0
cleanup() {
  local rc=$?
  if [ "$STAGED" -eq 1 ] && [ "$COMMITTED" -eq 0 ]; then
    printf "\n%s! Changes are still STAGED but not committed.%s\n" "$YELLOW" "$RESET" >&2
    printf "%s  Undo with: git reset%s\n" "$YELLOW" "$RESET" >&2
  fi
  rm -rf "$RUNDIR"
  return $rc
}
trap cleanup EXIT
trap 'echo; fail "Interrupted."; exit 130' INT TERM

# --- step runner ----------------------------------------------------------
# Replaces the copy-pasted "( cd X && cmd ); if [ $? -eq 0 ]" block that used
# to be repeated for every check. Also records timing, and honours the
# fail-fast / --keep-going logic in one place.
#
#   run_step      LABEL DIR CMD...   -> failure sets FAILED
#   run_step_warn LABEL DIR CMD...   -> failure only warns, never blocks
record_step() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$RUNDIR/$SUITE.tsv"; }

_run_step() {
  local warn_only="$1"; shift
  local label="$1"; shift
  local dir="$1"; shift

  if [ "$FAILED" -ne 0 ] && [ "$KEEP_GOING" -eq 0 ]; then
    record_step "skip" 0 "$label"
    return 0
  fi

  step "$label"
  local t0=$SECONDS rc=0
  ( cd "$dir" && "$@" ) || rc=$?
  local dt=$(( SECONDS - t0 ))

  if [ $rc -eq 0 ]; then
    ok "$label — ok (${dt}s)"
    record_step "ok" "$dt" "$label"
  elif [ "$warn_only" -eq 1 ]; then
    warn "$label — reported findings (not blocking)"
    record_step "warn" "$dt" "$label"
  else
    fail "$label — FAILED (${dt}s)"
    record_step "fail" "$dt" "$label"
    FAILED=1
  fi
  return 0
}
run_step()      { _run_step 0 "$@"; }
run_step_warn() { _run_step 1 "$@"; }

skip_step() { record_step "skip" 0 "$1"; note "skipped: $1"; }

# --- shared small helpers -------------------------------------------------
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
  else
    # No hasher available — return empty so the caller falls back to
    # "reinstall to be safe" rather than to "assume up to date".
    echo ""
  fi
}

# version_lt A B -> true when dotted-numeric version A is older than B.
# Pure bash (no sort -V: BSD sort on macOS didn't get -V until recently).
version_lt() {
  local a="$1" b="$2" i ai bi
  local -a A B
  IFS=. read -r -a A <<< "$a"
  IFS=. read -r -a B <<< "$b"
  for i in 0 1 2; do
    ai="${A[$i]:-0}"; bi="${B[$i]:-0}"
    ai="${ai//[!0-9]/}"; bi="${bi//[!0-9]/}"
    ai="${ai:-0}"; bi="${bi:-0}"
    if [ "$ai" -lt "$bi" ]; then return 0; fi
    if [ "$ai" -gt "$bi" ]; then return 1; fi
  done
  return 1
}

# --- file-scanning helpers (used by the git step near the bottom) ---------
# Deliberately not using mapfile/readarray or associative arrays anywhere in
# this script: macOS ships bash 3.2 by default (GPL licensing), and those
# are bash-4-only. Plain arrays + while/read loops work on both.

# collect_changed_files fills the CHANGED_FILES array with every path git
# status reports as added/modified (renames resolved to their new path).
# Deletions are naturally skipped later since each consumer checks [ -f ].
#
# -z + core.quotePath=false: without -z, git *quotes* any path containing a
# space, a quote or a non-ASCII byte ("frontend/src/gr\303\274n.ts"), and the
# old "${line:3}" slice then handed the scanners a filename that doesn't
# exist on disk — so those files were silently never scanned.
# -uall: without it an entirely new directory is reported as one "?? dir/"
# entry. Every scanner below tests [ -f ], so a directory was skipped whole,
# and secrets in a newly added folder went unchecked.
collect_changed_files() {
  CHANGED_FILES=()
  local line rest src
  while IFS= read -r -d '' line; do
    [ -z "$line" ] && continue
    rest="${line:3}"
    case "${line:0:2}" in
      R*|C*)
        # In -z mode a rename/copy emits the original path as its own
        # NUL-terminated record right after this one; consume it so it isn't
        # mistaken for a status line on the next iteration.
        IFS= read -r -d '' src || true
        ;;
    esac
    CHANGED_FILES+=("$rest")
  done < <(git -c core.quotePath=false status --porcelain=v1 -z -uall)
}

# scan_for_conflict_markers: unresolved "<<<<<<<"/"|||||||"/"======="/">>>>>>>"
# left in a file almost always means a merge/rebase was left half-finished
# and someone is about to commit broken code by accident. The "|||||||" form
# only appears with merge.conflictStyle=diff3/zdiff3, which is exactly the
# setting most likely to be turned on in a repo that hits conflicts often.
scan_for_conflict_markers() {
  local hit=0 f
  for f in "$@"; do
    [ -f "$f" ] || continue
    if grep -qIE '^(<{7}|\|{7}|={7}|>{7})( |$)' -- "$f" 2>/dev/null; then
      fail "Unresolved merge-conflict markers in: $f"
      hit=1
    fi
  done
  return $hit
}

# scan_for_secrets: narrow, well-known credential formats only (AWS keys,
# PEM private key headers, Slack/GitHub/Anthropic/Google API key shapes) -
# deliberately NOT a generic "key\s*=\s*.+" pattern, since this codebase's
# own source is full of legitimate matches for that (field names like
# admin_key/api_key, placeholder strings, etc.) that would just train you to
# ignore the warning.
#
# All patterns are one alternation in a single grep pass instead of one grep
# per pattern per file (was 6x the process spawns for the same answer), and
# -I skips binaries, which can never usefully match these anyway.
SECRET_PATTERN='AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----|xox[baprs]-[0-9A-Za-z-]{10,}|gh[pousr]_[A-Za-z0-9]{36,}|sk-ant-[A-Za-z0-9_-]{20,}|AIzaSy[0-9A-Za-z_-]{33}'
scan_for_secrets() {
  local hit=0 f
  for f in "$@"; do
    [ -f "$f" ] || continue
    if grep -qIE "$SECRET_PATTERN" -- "$f" 2>/dev/null; then
      fail "Possible credential in: $f (matches a known secret format — double-check before committing)"
      hit=1
    fi
  done
  return $hit
}

# scan_for_secret_filenames: content matching can't catch an env file whose
# values happen to look ordinary, so the *name* is worth a look too. Warns
# rather than blocks, because this repo legitimately tracks several
# near-misses (.env.example, backend/internal/modules/cosign_pubkey.pem —
# a public key), and a check that cries wolf on every commit gets ignored.
scan_for_secret_filenames() {
  local f base
  for f in "$@"; do
    [ -f "$f" ] || continue
    base="$(basename "$f")"
    case "$base" in
      *.example|*.sample|*.template|*.dist|*.pub|*pubkey*) continue ;;
    esac
    case "$base" in
      .env|.env.*|id_rsa|id_dsa|id_ecdsa|id_ed25519|*.pem|*.p12|*.pfx|*.jks|*.keystore|credentials|*.kubeconfig)
        warn "Secret-ish filename staged: $f — confirm this belongs in the repo."
        ;;
    esac
  done
}

# scan_for_large_files: warns only (never blocks) - a large file staged by
# accident (a build artifact, a debug dump) is usually a mistake, but
# occasionally intentional (a real asset), so this doesn't stop the flow.
scan_for_large_files() {
  local f size max_bytes=$((5 * 1024 * 1024))
  for f in "$@"; do
    [ -f "$f" ] || continue
    size=$(wc -c < "$f" 2>/dev/null | tr -d ' ')
    if [ -n "$size" ] && [ "$size" -gt "$max_bytes" ] 2>/dev/null; then
      warn "Large file staged: $f ($((size / 1024 / 1024)) MB) — make sure that's intentional."
    fi
  done
}

# --- 0. Git sanity: stale lock files + genuinely-in-progress states -------
#
# "fatal: Unable to create '.../.git/index.lock': File exists" happens when
# a previous git process (or, in this project's case, iCloud sync / a
# sandboxed tool poking the repo concurrently) died mid-operation and left
# its lock file behind. It's always safe to remove *if no git process is
# actually running right now* - the lock's only job is to stop two git
# processes writing at once, and if there's genuinely a live one, deleting
# out from under it would corrupt the repo.
#
# Two guards, because either one alone is racy: (a) no git process of *this
# user* is running, and (b) the lock file is at least a minute old. A git
# process that is between fork and exec, or one whose name is a helper like
# git-remote-https rather than plain "git", slips past (a); (b) catches it,
# since a lock a live operation is using was created seconds ago.
#
# Lock files are separate from *state* (an in-progress merge/rebase/
# cherry-pick/bisect) - those aren't stale locks, they're real unfinished
# work, and blowing them away would lose it. For those this stops and tells
# you to resolve it yourself instead of touching anything.
git_sanity_check() {
  local git_running=0
  if pgrep -x git -u "$(id -u)" >/dev/null 2>&1; then
    git_running=1
  fi

  local lock_files=(
    "$ROOT/.git/index.lock"
    "$ROOT/.git/HEAD.lock"
    "$ROOT/.git/config.lock"
    "$ROOT/.git/shallow.lock"
    "$ROOT/.git/packed-refs.lock"
    "$ROOT/.git/COMMIT_EDITMSG.lock"
    "$ROOT/.git/FETCH_HEAD.lock"
    "$ROOT/.git/gc.pid"
  )
  # Per-branch ref locks, e.g. .git/refs/heads/main.lock - path depends on
  # the branch name, so these have to be found rather than listed.
  if [ -d "$ROOT/.git/refs" ]; then
    while IFS= read -r -d '' f; do
      lock_files+=("$f")
    done < <(find "$ROOT/.git/refs" -name "*.lock" -print0 2>/dev/null)
  fi

  local found_lock=0 f
  for f in "${lock_files[@]}"; do
    if [ -e "$f" ]; then
      found_lock=1
      if [ $git_running -eq 1 ]; then
        fail "Found $f, and a git process is currently running — not touching it. Wait for it to finish (or check 'ps aux | grep git') and re-run."
        return 1
      fi
      if [ -z "$(find "$f" -mmin +1 -print 2>/dev/null)" ]; then
        fail "Found $f, created less than a minute ago — too fresh to assume it's stale. Wait a moment and re-run."
        return 1
      fi
      warn "Removing stale lock file: $f"
      rm -f "$f"
    fi
  done
  [ $found_lock -eq 1 ] && ok "Stale git lock file(s) cleared."

  # Genuinely in-progress states — never auto-resolved, just reported.
  if [ -d "$ROOT/.git/rebase-merge" ] || [ -d "$ROOT/.git/rebase-apply" ]; then
    fail "A rebase is in progress. Resolve it yourself first: 'git rebase --continue' or 'git rebase --abort'."
    return 1
  fi
  if [ -f "$ROOT/.git/MERGE_HEAD" ]; then
    fail "A merge is in progress. Resolve it yourself first: finish the merge or 'git merge --abort'."
    return 1
  fi
  if [ -f "$ROOT/.git/CHERRY_PICK_HEAD" ]; then
    fail "A cherry-pick is in progress. Resolve it yourself first: 'git cherry-pick --continue' or '--abort'."
    return 1
  fi
  if [ -f "$ROOT/.git/BISECT_LOG" ]; then
    fail "A bisect is in progress ('git bisect reset' when you're done with it)."
    return 1
  fi

  return 0
}

# ==========================================================================
# Backend checks
# ==========================================================================

# CI parity: the whole point of GOLANGCI_VERSION/GOVULNCHECK_VERSION above is
# that they equal what ci.yml pins. Nothing enforced that — bump ci.yml, forget
# this file, and every local run from then on lints with a different version
# than the gate it's meant to pre-empt, silently and indefinitely. So read the
# workflow and compare.
#
# Warn, never fail: the commit that bumps ci.yml would otherwise be blocked by
# a drift the commit itself is introducing.
#
# Comment lines are stripped before parsing, because ci.yml's own comment block
# above the govulncheck step mentions "govulncheck@latest" (describing how the
# pin was verified) and appears *before* the real run: line.
ci_parity_check() {
  local ci="$ROOT/$CI_WORKFLOW"
  if [ ! -f "$ci" ]; then
    note "$CI_WORKFLOW not found — skipping CI parity check."
    return 0
  fi

  local body ci_lint ci_vuln drift=0
  body="$(grep -v '^[[:space:]]*#' "$ci")"

  # golangci-lint: the "version:" key belongs to golangci-lint-action's "with:"
  # block, so anchor on the action name and take the first version: after it.
  ci_lint="$(printf '%s\n' "$body" | awk '
    /golangci-lint-action/ { seen = 1 }
    seen && /^[[:space:]]*version:[[:space:]]*v?[0-9]/ {
      sub(/^[[:space:]]*version:[[:space:]]*/, "")
      gsub(/[[:space:]"\x27]/, "")
      print; exit
    }')"

  ci_vuln="$(printf '%s\n' "$body" | sed -n 's|.*golang\.org/x/vuln/cmd/govulncheck@\([A-Za-z0-9._+-]*\).*|\1|p' | head -1)"

  if [ -z "$ci_lint" ]; then
    warn "Could not read the golangci-lint version out of $CI_WORKFLOW — check the parser in ci_parity_check()."
    drift=1
  elif [ "$ci_lint" != "$GOLANGCI_VERSION" ]; then
    warn "golangci-lint drift: $CI_WORKFLOW pins $ci_lint, this script pins $GOLANGCI_VERSION."
    note "Fix: set GOLANGCI_VERSION=\"$ci_lint\" at the top of scripts/check-and-push.sh."
    drift=1
  fi

  if [ -z "$ci_vuln" ]; then
    warn "Could not read the govulncheck version out of $CI_WORKFLOW — check the parser in ci_parity_check()."
    drift=1
  elif [ "$ci_vuln" != "$GOVULNCHECK_VERSION" ]; then
    warn "govulncheck drift: $CI_WORKFLOW pins $ci_vuln, this script pins $GOVULNCHECK_VERSION."
    note "Fix: set GOVULNCHECK_VERSION=\"$ci_vuln\" at the top of scripts/check-and-push.sh."
    drift=1
  fi

  if [ $drift -eq 0 ]; then
    note "golangci-lint $GOLANGCI_VERSION, govulncheck $GOVULNCHECK_VERSION — both match $CI_WORKFLOW ✓"
  fi
  return $drift
}

# Toolchain drift: backend/go.mod pins the language version CI installs via
# setup-go's go-version-file. A local toolchain older than that produces
# confusing "invalid go version" / unsupported-syntax errors far away from
# the real cause, so name it up front. Warn, not fail — a newer local Go is
# perfectly fine.
backend_toolchain_check() {
  local required have
  required="$(awk '/^go[ \t]+[0-9]/ {print $2; exit}' go.mod 2>/dev/null)"
  have="$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')"
  if [ -z "$required" ] || [ -z "$have" ]; then
    warn "Could not determine Go versions (go.mod: '${required:-?}', local: '${have:-?}')."
    return 0
  fi
  if version_lt "$have" "$required"; then
    warn "Local Go is $have but backend/go.mod requires $required — CI builds with $required. Upgrade before trusting a green run here."
  else
    note "Go $have (go.mod requires $required) ✓"
  fi
  return 0
}

# go mod tidy -diff (Go 1.23+) reports what "go mod tidy" *would* change and
# exits non-zero if anything, without writing to go.mod/go.sum. Running the
# mutating "go mod tidy" here instead would edit dependency files in the
# middle of a check run — exactly the kind of surprise this script exists to
# prevent. go mod verify then confirms the module cache contents still hash
# to what go.sum says.
backend_mod_check() {
  local rc=0
  if ! go mod tidy -diff; then
    fail "go.mod/go.sum are not tidy — run 'go mod tidy' in backend/ and review the diff."
    rc=1
  fi
  if ! go mod verify; then
    fail "go mod verify failed — a cached module's contents don't match go.sum."
    rc=1
  fi
  return $rc
}

backend_gofmt() {
  local unformatted
  unformatted="$(gofmt -l .)"
  if [ -z "$unformatted" ]; then
    ok "all files gofmt-clean"
    return 0
  fi
  if [ "$NO_FIX" -eq 1 ]; then
    fail "these files are not gofmt-clean (not fixing, --no-fix/--check-only):"
    echo "$unformatted" | sed 's/^/    /'
    return 1
  fi
  warn "auto-formatting these files with 'gofmt -w':"
  echo "$unformatted" | sed 's/^/    /'
  gofmt -w .
  ok "formatted — they'll show up as modified in 'git status' below"
  return 0
}

# Prefer a golangci-lint already on PATH (much faster than "go run", which
# recompiles the linter on a cold module cache), but only when its version
# actually matches the one CI pins. A mismatched local binary is the worst
# case: it reports a different set of findings than the gate you're trying
# to pre-empt, in either direction.
backend_golangci() {
  local want="${GOLANGCI_VERSION#v}" have=""
  if command -v golangci-lint >/dev/null 2>&1; then
    have="$(golangci-lint version 2>&1 | sed -n 's/.*version v\{0,1\}\([0-9][0-9.]*\).*/\1/p' | head -1)"
    case "$have" in
      "$want"|"$want".*)
        note "using golangci-lint $have from PATH (matches CI)"
        golangci-lint run
        return $?
        ;;
      *)
        warn "golangci-lint on PATH is '${have:-unknown}', CI pins $GOLANGCI_VERSION — ignoring it and using the pinned version instead."
        ;;
    esac
  fi
  note "running pinned golangci-lint $GOLANGCI_VERSION via 'go run'"
  go run "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_VERSION}.0" run
}

# govulncheck's default symbol scan answers "does code in this repo *call* a
# known-vulnerable function?" — that's the hard gate, identical to CI's
# govulncheck step. But its summary also mentions a second number that the
# exit code deliberately ignores:
#
#   This scan also found 0 vulnerabilities in packages you import and 1
#   vulnerability in modules you require, but your code doesn't appear to
#   call these vulnerabilities.
#
# Those module-level advisories exit 0, so they used to be printed and then
# forgotten. They matter because "not currently reachable" is a property of
# today's call graph: the next refactor that starts calling into that
# dependency silently turns that line of output into a live CVE.
#
# Getting at them separately turned out not to be worth it. The obvious
# route, a second `govulncheck -scan module` pass, does not work in this
# repo: -scan module rejects package patterns (internal/scan/flags.go,
# "patterns are not accepted for module only scanning"), but runSource then
# still calls packages.Load with the empty pattern list, which the go command
# resolves to "." — and backend/ has no .go files at its root, only
# subdirectories. Result: "no Go files in .../backend", exit 1. (Note also
# that -mode and -scan are unrelated: -mode picks the input — source, binary,
# extract — while -scan picks the depth.)
#
# So instead of a second full scan over the network, the count is read back
# out of the scan that already ran. Cheaper, and it can't disagree with the
# gate. Warn-only: blocking on an unreachable CVE that may have no fixed
# release yet would wedge every commit.
# Set here, not inside the function: run_step executes every check in a
# subshell, so an assignment made in backend_govulncheck_symbol would not be
# visible to backend_govulncheck_advisory. The file itself survives, being on
# disk under RUNDIR.
GOVULNCHECK_OUT="$RUNDIR/govulncheck-symbol.txt"

backend_govulncheck_symbol() {
  go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ./... 2>&1 | tee "$GOVULNCHECK_OUT"
  return "${PIPESTATUS[0]}"
}

# The summary sentence is hard-wrapped at ~80 columns, so the number and the
# phrase it belongs to routinely land on different lines ("...and 1\n
# vulnerability in modules you require..."). Newlines are folded to spaces
# before matching, otherwise a line-based grep misses exactly the cases that
# matter.
backend_govulncheck_advisory() {
  if [ -z "$GOVULNCHECK_OUT" ] || [ ! -s "$GOVULNCHECK_OUT" ]; then
    note "No govulncheck output captured (scan skipped or failed) — nothing to report."
    return 0
  fi

  local joined n
  joined="$(tr '\n' ' ' < "$GOVULNCHECK_OUT" | tr -s ' ')"
  n="$(printf '%s' "$joined" | sed -nE 's/.*[^0-9]([0-9]+) vulnerabilit(y|ies) in modules you require.*/\1/p')"

  if [ -z "$n" ]; then
    # Either genuinely nothing to report, or the wording changed in a newer
    # govulncheck. Say which, rather than implying a clean result.
    if printf '%s' "$joined" | grep -q "No vulnerabilities found"; then
      note "No module-level advisories."
    else
      warn "Could not find the 'in modules you require' summary in govulncheck's output — the wording may have changed in $GOVULNCHECK_VERSION. Check backend_govulncheck_advisory()."
    fi
    return 0
  fi

  if [ "$n" -eq 0 ]; then
    note "No module-level advisories."
    return 0
  fi

  warn "$n vulnerabilit$([ "$n" -eq 1 ] && echo y || echo ies) in modules you require, not reachable from this repo's call graph today — not blocking."
  note "Details: (cd backend && go run golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION} -show verbose ./...)"
  return 1
}

run_backend() {
  SUITE="backend"
  local dir="$ROOT/backend"
  if [ ! -d "$dir" ]; then
    warn "backend/ not found, skipping"
    return 0
  fi

  run_step_warn "CI parity: pinned tool versions vs $CI_WORKFLOW" "$ROOT" ci_parity_check
  run_step      "Backend: toolchain version"          "$dir" backend_toolchain_check
  run_step      "Backend: go mod tidy -diff + verify" "$dir" backend_mod_check
  # No separate "go build ./..." step: go vet and go test each compile the
  # whole module (test files included, which go build skips), so a build-only
  # pass was a third full compile that could not fail on its own.
  run_step      "Backend: go vet ./..."               "$dir" go vet ./...
  run_step      "Backend: gofmt"                      "$dir" backend_gofmt
  run_step      "Backend: golangci-lint ($GOLANGCI_VERSION, same as CI)" "$dir" backend_golangci
  run_step      "Backend: go test ./..."              "$dir" go test ./...
  if [ "$FAST" -eq 1 ]; then
    skip_step "Backend: govulncheck (--fast)"
  else
    run_step      "Backend: govulncheck ./... ($GOVULNCHECK_VERSION, same as CI)" "$dir" backend_govulncheck_symbol
    run_step_warn "Backend: module-level advisories (from the scan above)"        "$dir" backend_govulncheck_advisory
  fi
  return $FAILED
}

# ==========================================================================
# Frontend checks
# ==========================================================================

# npm ci deletes and reinstalls node_modules from scratch every time, so it's
# worth skipping when nothing changed. The previous heuristic compared
# package-lock.json's mtime against node_modules/ — unreliable in both
# directions: npm doesn't reliably bump the directory's mtime after an
# install, and a plain "git checkout" of an unrelated branch rewrites the
# lockfile's mtime without changing a byte of it. Hashing the lockfile and
# stashing the hash inside node_modules answers the actual question ("was
# node_modules built from *this* lockfile?").
frontend_install() {
  local lock="package-lock.json" stamp="node_modules/.modulab-lockhash"
  local want="" have=""

  if [ -f "$lock" ]; then want="$(sha256_of "$lock")"; fi
  if [ -f "$stamp" ]; then have="$(cat "$stamp" 2>/dev/null)"; fi

  if [ -d node_modules ] && [ -n "$want" ] && [ "$want" = "$have" ]; then
    ok "node_modules already matches package-lock.json — skipping npm ci"
    return 0
  fi

  npm ci || return 1
  if [ -n "$want" ] && [ -d node_modules ]; then
    printf '%s' "$want" > "$stamp"
  fi
  return 0
}

run_frontend() {
  SUITE="frontend"
  local dir="$ROOT/frontend"
  if [ ! -d "$dir" ]; then
    warn "frontend/ not found, skipping"
    return 0
  fi

  run_step "Frontend: npm ci (same as CI)"      "$dir" frontend_install
  run_step "Frontend: npm run lint"             "$dir" npm run lint
  run_step "Frontend: npm run build (tsc -b && vite build)" "$dir" npm run build
  if [ "$FAST" -eq 1 ]; then
    skip_step "Frontend: npm audit (--fast)"
  else
    run_step "Frontend: npm audit --audit-level=high" "$dir" npm audit --audit-level=high
  fi
  return $FAILED
}

# ==========================================================================
# Optional: Docker image build (CI's "docker-build-check" job)
# ==========================================================================
# Same thing that job does — root Dockerfile, amd64, no push. Off by default
# because it's by far the slowest check here; worth running before a release
# or after touching the Dockerfile or either build stage's dependencies.
run_docker() {
  SUITE="docker"
  if [ ! -f "$ROOT/Dockerfile" ]; then
    warn "Dockerfile not found, skipping"
    return 0
  fi
  if ! command -v docker >/dev/null 2>&1; then
    warn "docker not installed — skipping the image build."
    return 0
  fi
  run_step "Docker: build root Dockerfile (no push, like CI)" "$ROOT" \
    docker build --platform linux/amd64 -f ./Dockerfile -t modulab-core:local-check .
  return $FAILED
}

# ==========================================================================
# Run
# ==========================================================================

step "Git: checking for stale locks / in-progress operations"
if [ -d "$ROOT/.git" ]; then
  if git_sanity_check; then
    ok "git state clean"
  else
    exit 1
  fi
else
  warn "$ROOT/.git not found, skipping"
fi

if [ "$PARALLEL" -eq 1 ] && [ "$DO_BACKEND" -eq 1 ] && [ "$DO_FRONTEND" -eq 1 ]; then
  step "Running backend and frontend suites in parallel (output appears when each finishes)"
  ( run_backend  > "$RUNDIR/backend.log"  2>&1 ) & BE_PID=$!
  ( run_frontend > "$RUNDIR/frontend.log" 2>&1 ) & FE_PID=$!
  BE_RC=0; FE_RC=0
  wait $BE_PID || BE_RC=$?
  wait $FE_PID || FE_RC=$?
  [ -f "$RUNDIR/backend.log" ]  && cat "$RUNDIR/backend.log"
  [ -f "$RUNDIR/frontend.log" ] && cat "$RUNDIR/frontend.log"
  [ $BE_RC -ne 0 ] && FAILED=1
  [ $FE_RC -ne 0 ] && FAILED=1
else
  if [ "$DO_BACKEND" -eq 1 ]; then
    run_backend || FAILED=1
  fi
  if [ "$DO_FRONTEND" -eq 1 ]; then
    if [ "$FAILED" -ne 0 ] && [ "$KEEP_GOING" -eq 0 ]; then
      note "skipping frontend suite (backend failed; use --keep-going to run everything)"
    else
      run_frontend || FAILED=1
    fi
  fi
fi

if [ "$DO_DOCKER" -eq 1 ]; then
  if [ "$FAILED" -ne 0 ] && [ "$KEEP_GOING" -eq 0 ]; then
    note "skipping docker build (earlier failure)"
  else
    run_docker || FAILED=1
  fi
fi

SUITE="main"

# --- summary --------------------------------------------------------------
# One table at the end so it's obvious both what failed and where the wall
# time actually went — useful for deciding what belongs behind --fast.
step "Summary"
TOTAL=$(( SECONDS - START_TS ))
for f in "$RUNDIR"/backend.tsv "$RUNDIR"/frontend.tsv "$RUNDIR"/docker.tsv; do
  [ -f "$f" ] || continue
  while IFS=$'\t' read -r status secs label; do
    case "$status" in
      ok)   printf "  %s✓%s %5ss  %s\n" "$GREEN" "$RESET" "$secs" "$label" ;;
      warn) printf "  %s!%s %5ss  %s\n" "$YELLOW" "$RESET" "$secs" "$label" ;;
      fail) printf "  %s✗%s %5ss  %s\n" "$RED" "$RESET" "$secs" "$label" ;;
      skip) printf "  %s-%s     -  %s (skipped)\n" "$DIM" "$RESET" "$label" ;;
    esac
  done < "$f"
done
printf "  %s%ss total%s\n" "$DIM" "$TOTAL" "$RESET"

if [ "$FAILED" -ne 0 ]; then
  fail "One or more checks failed — nothing was staged, committed, or pushed."
  exit 1
fi
ok "All checks passed."

if [ "$DO_GIT" -eq 0 ]; then
  exit 0
fi

# --- git: add / commit / push --------------------------------------------
# Re-checked here, not just at the top: the build/lint steps above can take
# a while, long enough for iCloud sync or another tool to grab a lock in the
# meantime.
step "Git: re-checking for stale locks / in-progress operations"
if ! git_sanity_check; then
  exit 1
fi
ok "git state clean"

# --- remote sync check -----------------------------------------------------
# Fetches origin and compares against it *before* anything is committed, so
# a diverged/behind branch is caught here instead of surfacing as a
# rejected push after you've already written a commit message.
step "Git: checking sync status with origin"
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")"
AHEAD=0
UPSTREAM_EXISTS=0
if [ -z "$BRANCH" ] || [ "$BRANCH" = "HEAD" ]; then
  warn "Detached HEAD — skipping remote sync check."
elif ! git remote get-url origin >/dev/null 2>&1; then
  warn "No 'origin' remote configured — skipping remote sync check."
else
  if git fetch origin "$BRANCH" --quiet 2>/dev/null; then
    if git rev-parse --verify "origin/$BRANCH" >/dev/null 2>&1; then
      UPSTREAM_EXISTS=1
      AHEAD=$(git rev-list --count "origin/$BRANCH..HEAD" 2>/dev/null || echo 0)
      BEHIND=$(git rev-list --count "HEAD..origin/$BRANCH" 2>/dev/null || echo 0)
      if [ "$BEHIND" -gt 0 ] && [ "$AHEAD" -gt 0 ]; then
        fail "Local branch has diverged from origin/$BRANCH ($AHEAD ahead, $BEHIND behind) — pull/rebase first, not proceeding automatically."
        exit 1
      elif [ "$BEHIND" -gt 0 ]; then
        fail "Local branch is $BEHIND commit(s) behind origin/$BRANCH — run 'git pull' first."
        exit 1
      else
        ok "In sync with origin/$BRANCH ($AHEAD commit(s) ahead locally, not yet pushed)."
      fi
    else
      warn "origin/$BRANCH doesn't exist yet — this will be the first push of this branch."
    fi
  else
    warn "Could not reach origin (offline?) — skipping remote sync check."
  fi
fi

# --- working tree: nothing to commit but maybe something to push ---------
if [ -z "$(git status --porcelain)" ]; then
  if [ "$AHEAD" -gt 0 ] && [ $DO_PUSH -eq 1 ]; then
    warn "Working tree is clean, but $AHEAD local commit(s) haven't been pushed yet — pushing those now."
  else
    warn "Working tree is clean — nothing to commit or push."
    exit 0
  fi
else
  step "git status"
  git status --short

  collect_changed_files
  SCAN_FAILED=0
  scan_for_conflict_markers "${CHANGED_FILES[@]}" || SCAN_FAILED=1
  scan_for_secrets "${CHANGED_FILES[@]}" || SCAN_FAILED=1
  if [ $SCAN_FAILED -ne 0 ]; then
    fail "Aborting before staging anything — fix the above first."
    exit 1
  fi
  scan_for_secret_filenames "${CHANGED_FILES[@]}"
  scan_for_large_files "${CHANGED_FILES[@]}"

  git add -A || { fail "git add failed."; exit 1; }
  STAGED=1

  step "Staged diff (summary)"
  git diff --cached --stat

  if [ -n "$COMMIT_MSG_ARG" ]; then
    COMMIT_MSG="$COMMIT_MSG_ARG"
  else
    echo
    printf "%sCommit message%s (subject + optional body, multi-line paste OK). When done: press Enter, then Ctrl+D:\n" "$BOLD" "$RESET"
    COMMIT_MSG="$(cat)"
  fi

  if [ -z "$COMMIT_MSG" ]; then
    fail "Empty commit message — aborting (changes are staged but not committed)."
    exit 1
  fi

  # Soft nudge only: git itself doesn't care, but a subject over ~72 chars is
  # truncated in "git log --oneline", GitHub's commit list and the release
  # notes this project pastes commits into.
  SUBJECT="$(printf '%s\n' "$COMMIT_MSG" | head -1)"
  if [ "${#SUBJECT}" -gt 72 ]; then
    warn "Commit subject is ${#SUBJECT} chars (>72) — it'll be truncated in git log --oneline and on GitHub."
  fi

  git commit -m "$COMMIT_MSG"
  if [ $? -ne 0 ]; then
    fail "git commit failed."
    exit 1
  fi
  COMMITTED=1
  ok "Committed."
fi

if [ $DO_PUSH -eq 1 ]; then
  step "git push"
  if [ $UPSTREAM_EXISTS -eq 0 ] && [ -n "$BRANCH" ] && git remote get-url origin >/dev/null 2>&1; then
    # First push of this branch — set the upstream instead of a bare push,
    # which would otherwise fail with "no upstream branch".
    git push -u origin "$BRANCH"
  else
    git push
  fi
  if [ $? -eq 0 ]; then
    ok "Pushed."
  else
    fail "git push failed — commit is local, fix and push manually."
    exit 1
  fi
else
  warn "Skipping push (--no-push)."
fi
