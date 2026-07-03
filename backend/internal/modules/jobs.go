package modules

import (
	"context"
	"encoding/json"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/modulab-project/modulab-core/backend/internal/db"
)

// egressHostsJobName is the reserved job name QueryEgressHosts dispatches
// under. Prefixed with "__" so it can never collide with a module-declared
// job name from manifest.yaml's jobs: list (module authors are not
// restricted from using "__"-prefixed names themselves, but nothing in the
// reference modules does, and this is Core-internal wiring, not part of the
// module SDK's public job-name surface).
const egressHostsJobName = "__compute_egress_hosts__"

// ResolveJobEntrypoints turns a manifest's jobs: list (plus, if set,
// EgressHostsHandler) into the job-name -> absolute-path map that
// WorkerOptions.Jobs (and the Deno bootstrap's dynamic imports) expect.
// destDir is the module's installed directory (DataDir/{name}); each job's
// Handler path is relative to it, the same convention as the top-level
// manifest Handler field.
func ResolveJobEntrypoints(destDir string, jobs []ManifestJob, egressHostsHandler string) map[string]string {
	out := make(map[string]string, len(jobs)+1)
	for _, j := range jobs {
		if j.Name == "" || j.Handler == "" {
			continue
		}
		out[j.Name] = filepath.Join(destDir, j.Handler)
	}
	if egressHostsHandler != "" {
		out[egressHostsJobName] = filepath.Join(destDir, egressHostsHandler)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// jobTimeout is the per-invocation budget for a scheduled job — longer than
// the 10s HTTP handler default (WorkerRequest dispatch already applies a
// context deadline; jobs get more room since they typically scatter-gather
// over several external hosts, e.g. unifi-network's poll_gateways polling
// every configured gateway per tick).
const jobTimeout = 5 * time.Minute

// jobTickInterval is how often JobRunner re-evaluates every module's job
// schedules. Cron schedules in module manifests are evaluated at minute
// granularity only — see ManifestJob.Schedule — so there is no point
// ticking faster than once a minute.
const jobTickInterval = time.Minute

// JobRunner periodically dispatches scheduled jobs (manifest.yaml's jobs:
// list) to their module's Deno worker. It is a minimal, generic in-process
// scheduler: no persistence, no retry/backoff, no distributed coordination —
// deliberately so, since Core runs as a single instance in a homelab. A
// module with jobs: gets those jobs invoked on their declared cron schedule
// for as long as Core's process is alive; a missed tick (Core restart,
// schedule computed differently) is simply skipped, not caught up, unless a
// future need for CatchUp semantics arises (ManifestJob.CatchUp is parsed
// but not yet acted on).
type JobRunner struct {
	db      *db.Pool
	workers *WorkerPool
	stop    chan struct{}
}

// NewJobRunner creates a JobRunner. Call Start to begin ticking.
func NewJobRunner(pool *db.Pool, workers *WorkerPool) *JobRunner {
	return &JobRunner{db: pool, workers: workers, stop: make(chan struct{})}
}

// Start begins the scheduling loop in a background goroutine. Call Stop (or
// cancel ctx) on Core shutdown.
func (r *JobRunner) Start(ctx context.Context) {
	go r.loop(ctx)
}

// Stop halts the scheduling loop.
func (r *JobRunner) Stop() {
	close(r.stop)
}

func (r *JobRunner) loop(ctx context.Context) {
	ticker := time.NewTicker(jobTickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stop:
			return
		case now := <-ticker.C:
			r.tick(ctx, now)
		}
	}
}

// tick evaluates every installed, active Tier 2/3 module's job schedules
// against now and dispatches the ones that are due. Each dispatch runs in
// its own goroutine so a slow/hanging job (e.g. a gateway that stopped
// responding) cannot delay other modules' jobs sharing the same tick.
func (r *JobRunner) tick(ctx context.Context, now time.Time) {
	installed, err := r.db.ListInstalledModules(ctx)
	if err != nil {
		log.Printf("modules: jobrunner: list installed modules: %v", err)
		return
	}

	for _, row := range installed {
		if row.Tier < 2 || row.Status != "active" || row.Manifest == nil {
			continue
		}
		var mf struct {
			Jobs []ManifestJob `json:"jobs"`
		}
		if err := json.Unmarshal(row.Manifest, &mf); err != nil || len(mf.Jobs) == 0 {
			continue
		}
		if !r.workers.Running(row.Name) {
			continue // worker not up (e.g. failed to start) — nothing to dispatch to
		}
		for _, job := range mf.Jobs {
			if !cronMatchesMinute(job.Schedule, now) {
				continue
			}
			go r.dispatchJob(row.Name, job.Name)
		}
	}
}

// dispatchJob sends a single job invocation to the module's worker and logs
// the outcome. Errors here are operational (worker crashed, job threw) and
// intentionally do not propagate further — the next tick will try again.
func (r *JobRunner) dispatchJob(moduleName, jobName string) {
	ctx, cancel := context.WithTimeout(context.Background(), jobTimeout)
	defer cancel()

	resp, err := r.workers.Dispatch(ctx, moduleName, WorkerRequest{Job: jobName})
	if err != nil {
		log.Printf("modules: job %q/%q: dispatch error: %v", moduleName, jobName, err)
		return
	}
	if resp.Status >= 400 {
		log.Printf("modules: job %q/%q: failed (status %d): %s", moduleName, jobName, resp.Status, string(resp.Body))
		return
	}
	// Jobs can request an egress reload the same way HTTP handlers do (e.g.
	// a future job that discovers new destinations). Same mechanism as
	// router.go's ModuleProxyHandler.
	if resp.RestartHosts != nil {
		if err := r.workers.ReloadEgress(moduleName, resp.RestartHosts); err != nil {
			log.Printf("modules: job %q/%q: egress reload failed: %v", moduleName, jobName, err)
		}
	}
}

// cronMatchesMinute reports whether a 5-field cron expression
// ("minute hour day month weekday") matches now, evaluated at minute
// granularity (seconds are not part of the schedule — see ManifestJob).
// Supports the two forms actually used by reference modules: "*" (any) and
// a literal integer per field. This is intentionally not a full cron
// implementation (no ranges, steps, or lists) — module manifests seen so
// far only need "every minute" ("* * * * *") and similar simple schedules;
// a fuller parser can be added if a module needs more.
func cronMatchesMinute(expr string, now time.Time) bool {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return false
	}
	minute, hour, day, month, weekday := fields[0], fields[1], fields[2], fields[3], fields[4]
	return cronFieldMatches(minute, now.Minute()) &&
		cronFieldMatches(hour, now.Hour()) &&
		cronFieldMatches(day, now.Day()) &&
		cronFieldMatches(month, int(now.Month())) &&
		cronFieldMatches(weekday, int(now.Weekday()))
}

func cronFieldMatches(field string, value int) bool {
	if field == "*" {
		return true
	}
	n, err := strconv.Atoi(field)
	if err != nil {
		// Unsupported syntax (ranges, steps, lists) — fail closed rather
		// than silently never firing or firing every tick.
		log.Printf("modules: jobrunner: unsupported cron field %q, job will never run — only \"*\" or a literal integer are supported per field", field)
		return false
	}
	return n == value
}
