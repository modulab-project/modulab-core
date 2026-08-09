// Package geoip downloads and refreshes MaxMind's GeoLite2 City and ASN
// databases (credentials configured via internal/setup/geoip.go's admin
// panel handlers, never .env/docker-secrets), and looks up a session's
// city/region/ISP-organization from a client IP for display purposes only
// (see auth/handlers.go's loginCity/loginASN) - never for any
// access-control decision, same treatment Session.Country already gets.
//
// RunScheduler follows the exact same ticker/context-cancellation shape as
// coreupdate.RunScheduler and auth.RunSessionRevalidateWorker: a single
// long-running goroutine started unconditionally from cmd/core/main.go,
// where a tick before GeoIP has ever been configured is a quiet no-op
// (mirroring mail.RunWorker's "not configured yet" handling), never fatal.
package geoip

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	geoip2 "github.com/oschwald/geoip2-golang/v2"

	"github.com/modulab-project/modulab-core/backend/internal/audit"
	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
)

// defaultCheckTimeRaw is CheckTimeRaw's fallback: a quiet, low-traffic time,
// same value coreupdate's own default check time uses. MaxMind only
// republishes GeoLite2 databases weekly (Tuesdays, per their own docs), so
// checking once a day at a fixed clock time - rather than on a re-arming
// interval - is plenty by default and easier for an admin to reason about;
// admin-configurable (see CheckTimeRaw below) for anyone who wants a
// different time of day.
const defaultCheckTimeRaw = "03:00"

// tickInterval is how often RunScheduler re-evaluates the configured check
// time against the wall clock. Matches coreupdate.tickInterval's reasoning
// exactly: the schedule is only ever evaluated at minute granularity (see
// CheckTimeRaw/setup.ParseGeoIPCheckTime), so there is no point ticking
// faster than once a minute.
const tickInterval = time.Minute

// CheckTimeRaw reads the configured daily check time ("HH:MM", 24h) that
// RunScheduler re-downloads both databases at, from core_settings
// (setup.GeoIPCheckTimeSettingKey) - admin-configurable directly on the
// GeoIP settings page (unlike coreupdate's weekday+time schedule, which
// lives on admin/system/limits instead - GeoIP already has its own
// dedicated settings page, so this setting lives there too rather than
// being split across two pages). Defaults to defaultCheckTimeRaw if unset or
// invalid, same pattern as coreupdate.CheckTimeRaw. setup owns the settings
// key and the "HH:MM" parser (not this package) so setup.
// GeoIPConfigureHandler can write/validate it without this package needing
// to expose a setter - same direction as the existing
// GeoIPLastUpdateAtSettingKey etc.
func CheckTimeRaw(ctx context.Context, pool *db.Pool) string {
	val, ok, err := pool.GetSetting(ctx, setup.GeoIPCheckTimeSettingKey)
	if err != nil || !ok || val == "" {
		return defaultCheckTimeRaw
	}
	if _, _, err := setup.ParseGeoIPCheckTime(val); err != nil {
		return defaultCheckTimeRaw
	}
	return val
}

// downloadTimeout bounds a single edition's download+extract. A .mmdb file
// is tens of MB at most - if MaxMind or the network is slow enough that
// this is hit, the next tick (or the admin's own retry via the configure
// endpoint) gets another attempt rather than this goroutine hanging
// indefinitely on one stuck request.
const downloadTimeout = 30 * time.Second

// Edition IDs MaxMind's download endpoint expects, also used verbatim as
// the on-disk file base names (see reader.setPath below) - keeping the two
// identical means there is only one string to get right per database, not
// two that could silently drift apart.
const (
	cityEdition = "GeoLite2-City"
	asnEdition  = "GeoLite2-ASN"
)

// Deps holds everything the downloader and the lookup readers need. Same
// shape convention as auth.Deps/modules' various *Deps structs elsewhere in
// this codebase - a single struct threaded through RunScheduler/TriggerNow
// rather than a long, easy-to-misorder positional parameter list.
type Deps struct {
	Pool      *db.Pool
	MasterKey string
	DataDir   string
}

// RunScheduler is the long-running background goroutine driving the
// database refresh, on the admin-configured daily check time (CheckTimeRaw).
// Unlike coreupdate.RunScheduler (which deliberately does NOT run once at
// startup), this DOES run immediately before entering the tick loop: a
// fresh install with credentials already configured (e.g. restored from a
// backup) should not have to wait up to a full day for its first pair of
// databases - LookupCity/LookupASN would otherwise report ok=false the
// entire time in between for no good reason.
//
// Ticks every minute and fires downloadAll at most once per calendar day,
// the moment the wall clock first matches the configured HH:MM - same
// tick-every-minute/dedup-by-date shape as coreupdate.RunScheduler, since
// "at HH:MM every day" is a wall-clock schedule a re-armed interval timer
// can't express directly (unlike this function's own former interval-hours
// design, replaced 2026-08-09). Re-reads CheckTimeRaw fresh on every tick
// (not cached at goroutine start) so an admin's settings change takes
// effect on the very next tick, same reasoning store.RunSync's interval
// re-read used to have here.
func RunScheduler(ctx context.Context, deps Deps) {
	Configure(deps.DataDir)
	downloadAll(ctx, deps)

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	var lastRunDate string // "2026-08-09" form; empty until the first run this process lifetime
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			today := now.Format("2006-01-02")
			if today == lastRunDate {
				continue // already ran today - a missed/duplicate tick within the same minute is a no-op, not a re-run
			}

			hour, minute, err := setup.ParseGeoIPCheckTime(CheckTimeRaw(ctx, deps.Pool))
			if err != nil {
				// Unreachable in practice - CheckTimeRaw only ever returns a
				// value it already validated or the known-good default -
				// but fail closed (skip this tick) rather than panic if that
				// invariant is ever broken.
				log.Printf("geoip: scheduler: %v", err)
				continue
			}
			if now.Hour() != hour || now.Minute() != minute {
				continue
			}

			lastRunDate = today
			downloadAll(ctx, deps)
		}
	}
}

// TriggerNow performs one immediate, synchronous download attempt for both
// editions - called by setup.GeoIPConfigureHandler right after new
// credentials are saved, so an admin sees the databases appear without
// waiting for RunScheduler's next tick. Bounded by downloadTimeout per
// edition (via downloadAll -> downloadEdition), so this never blocks the
// HTTP response that triggered it for more than a few tens of seconds.
func TriggerNow(ctx context.Context, deps Deps) {
	Configure(deps.DataDir)
	downloadAll(ctx, deps)
}

// downloadAll resolves the current GeoIP configuration and, if configured,
// downloads both editions. Any error - network, bad credentials (non-200
// response), tar parsing - is logged and persisted to
// setup.GeoIPLastUpdateErrorSettingKey so the admin page can surface it,
// but never crashes/panics: this always returns normally, leaving whatever
// databases (if any) were downloaded by a previous, successful attempt
// untouched on disk for LookupCity/LookupASN to keep using.
func downloadAll(ctx context.Context, deps Deps) {
	configured, err := setup.GeoIPConfigured(ctx, deps.Pool)
	if err != nil {
		log.Printf("geoip: check configured: %v", err)
		return
	}
	if !configured {
		// Not configured at all - quiet no-op, not even a log line, same as
		// mail.RunWorker's treatment of an unconfigured SMTP relay.
		return
	}

	cfg, err := setup.ResolveGeoIPConfig(ctx, deps.Pool, deps.MasterKey)
	if err != nil {
		log.Printf("geoip: resolve config: %v", err)
		return
	}

	// Recorded unconditionally, before either the success or failure path
	// below - unlike GeoIPLastUpdateAtSettingKey (success only), this marks
	// that an attempt actually happened at this moment regardless of
	// outcome, which is what the admin page's "last checked at ..." display
	// (setup.GeoIPStatusHandler) needs: RunScheduler runs daily at the
	// configured check time no matter whether the previous attempt
	// succeeded, so that display must anchor on "when did we last try", not
	// "when did we last succeed" - otherwise a run of failures would make it
	// look stuck/wrong instead of reflecting the real, still-running
	// schedule.
	if err := deps.Pool.SetSetting(ctx, setup.GeoIPLastCheckAtSettingKey, time.Now().UTC().Format(time.RFC3339)); err != nil {
		log.Printf("geoip: record last check time: %v", err)
	}

	if err := os.MkdirAll(deps.DataDir, 0o755); err != nil {
		recordFailure(ctx, deps.Pool, deps.MasterKey, fmt.Errorf("create data dir %q: %w", deps.DataDir, err))
		return
	}

	var failures []string
	for _, edition := range []string{cityEdition, asnEdition} {
		if err := downloadEdition(ctx, deps.DataDir, edition, cfg); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", edition, err))
		}
	}
	if len(failures) > 0 {
		recordFailure(ctx, deps.Pool, deps.MasterKey, fmt.Errorf("%s", strings.Join(failures, "; ")))
		return
	}

	if err := deps.Pool.DeleteSetting(ctx, setup.GeoIPLastUpdateErrorSettingKey); err != nil {
		log.Printf("geoip: clear last update error: %v", err)
	}
	if err := deps.Pool.SetSetting(ctx, setup.GeoIPLastUpdateAtSettingKey, time.Now().UTC().Format(time.RFC3339)); err != nil {
		log.Printf("geoip: record last update time: %v", err)
	}
	// Audited (not just the core_settings timestamp above, which only ever
	// shows the single most recent attempt) so an admin reviewing the audit
	// log later can see the full history of refreshes, not just today's
	// state - same reasoning EventGeoIPDownloadSucceeded/Failed's own doc
	// comment gives. No human actor (ActorID/ActorEmail empty), same shape
	// as EventModuleEgressDenied.
	if err := audit.Log(ctx, deps.Pool, deps.MasterKey, audit.LogParams{
		EventType: audit.EventGeoIPDownloadSucceeded,
		Details:   fmt.Sprintf(`{"editions":[%q,%q]}`, cityEdition, asnEdition),
	}); err != nil {
		log.Printf("geoip: audit download success: %v", err)
	}
}

// recordFailure logs err, best-effort persists it to
// setup.GeoIPLastUpdateErrorSettingKey - a failure to write that setting
// itself is only logged, never escalated, since the download failure it
// was trying to record is already the more important fact and this must
// not prevent the next tick from trying again - and audits it (see
// audit.EventGeoIPDownloadFailed's doc comment).
func recordFailure(ctx context.Context, pool *db.Pool, masterKey string, err error) {
	log.Printf("geoip: download: %v", err)
	if setErr := pool.SetSetting(ctx, setup.GeoIPLastUpdateErrorSettingKey, err.Error()); setErr != nil {
		log.Printf("geoip: record last update error: %v", setErr)
	}
	errJSON, _ := json.Marshal(err.Error())
	if auditErr := audit.Log(ctx, pool, masterKey, audit.LogParams{
		EventType: audit.EventGeoIPDownloadFailed,
		Details:   fmt.Sprintf(`{"error":%s}`, errJSON),
	}); auditErr != nil {
		log.Printf("geoip: audit download failure: %v", auditErr)
	}
}

// downloadEdition fetches one edition's tar.gz from MaxMind, extracts the
// single .mmdb entry inside it (MaxMind ships it inside a dated
// subdirectory, e.g. GeoLite2-City_20260101/GeoLite2-City.mmdb - the exact
// subdirectory name is irrelevant here, only the .mmdb suffix is matched),
// and atomically replaces <dataDir>/<edition>.mmdb: written to a .tmp file
// first, then os.Rename'd into place, so a concurrent LookupCity/LookupASN
// call never observes a half-written file mid-download.
func downloadEdition(ctx context.Context, dataDir, edition string, cfg setup.GeoIPRuntimeConfig) error {
	reqCtx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()

	downloadURL := fmt.Sprintf(
		"https://download.maxmind.com/app/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz",
		url.QueryEscape(edition), url.QueryEscape(cfg.LicenseKey),
	)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	// MaxMind's download endpoint also accepts (and current account policy
	// may require) HTTP Basic Auth with the account ID alongside the
	// license-key query parameter - sent in addition to, not instead of,
	// the query parameter, so this keeps working whether or not a given
	// account is on the newer account-scoped policy.
	req.SetBasicAuth(cfg.AccountID, cfg.LicenseKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("geoip: close response body for %s: %v", edition, cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("open gzip stream: %w", err)
	}
	defer func() {
		if cerr := gz.Close(); cerr != nil {
			log.Printf("geoip: close gzip stream for %s: %v", edition, cerr)
		}
	}()

	finalPath := filepath.Join(dataDir, edition+".mmdb")
	tmpPath := finalPath + ".tmp"

	tr := tar.NewReader(gz)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || !strings.HasSuffix(hdr.Name, ".mmdb") {
			continue
		}
		f, err := os.Create(tmpPath)
		if err != nil {
			return fmt.Errorf("create temp file: %w", err)
		}
		if _, err := io.Copy(f, tr); err != nil {
			_ = f.Close()
			_ = os.Remove(tmpPath)
			return fmt.Errorf("write temp file: %w", err)
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("close temp file: %w", err)
		}
		found = true
		break
	}
	if !found {
		return fmt.Errorf("no .mmdb file found in archive")
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

// reader lazily (re)opens one .mmdb file, guarded by its own RWMutex so
// concurrent LookupCity/LookupASN calls (one per authenticated request) can
// read through the same already-open *geoip2.Reader without contending on a
// single package-wide lock for both databases. Reopens whenever the file's
// mtime has advanced since it was last opened, so a fresh download picked
// up by downloadEdition's atomic rename takes effect for the very next
// lookup - no Core restart needed.
type reader struct {
	mu    sync.RWMutex
	path  string
	mmdb  *geoip2.Reader
	mtime time.Time
}

func (r *reader) setPath(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.path == path {
		return
	}
	r.path = path
	if r.mmdb != nil {
		if err := r.mmdb.Close(); err != nil {
			log.Printf("geoip: close reader for %s: %v", r.path, err)
		}
		r.mmdb = nil
	}
}

// get returns the currently-open reader, reopening it first if the file on
// disk is missing (ok=false, no database downloaded yet - not an error) or
// newer than what is currently open in memory.
func (r *reader) get() (*geoip2.Reader, bool) {
	r.mu.RLock()
	path := r.path
	current := r.mmdb
	currentMtime := r.mtime
	r.mu.RUnlock()

	if path == "" {
		return nil, false
	}
	info, err := os.Stat(path)
	if err != nil {
		// Not downloaded yet, or briefly absent mid-rename - either way,
		// "no data available" rather than an error the caller has to
		// handle.
		return nil, false
	}
	if current != nil && info.ModTime().Equal(currentMtime) {
		return current, true
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// Re-check under the write lock in case another goroutine already won
	// the race to reopen this exact mtime while this one was waiting.
	if r.mmdb != nil && info.ModTime().Equal(r.mtime) {
		return r.mmdb, true
	}
	opened, err := geoip2.Open(path)
	if err != nil {
		log.Printf("geoip: open %s: %v", path, err)
		return nil, false
	}
	if r.mmdb != nil {
		if cerr := r.mmdb.Close(); cerr != nil {
			log.Printf("geoip: close previous reader for %s: %v", path, cerr)
		}
	}
	r.mmdb = opened
	r.mtime = info.ModTime()
	return r.mmdb, true
}

var (
	cityReader = &reader{}
	asnReader  = &reader{}
)

// FileInfo describes one edition's .mmdb file as it currently sits on disk -
// used by the GeoIP admin settings page to show "is there actually a
// database here, and how big/recent is it", independent of whether GeoIP is
// currently configured at all (see GeoIPDeleteHandler's doc comment in
// internal/setup: removing credentials deliberately leaves already-
// downloaded files in place, so an admin who did that can still see the
// stale-but-present database here rather than the page going blank).
type FileInfo struct {
	Exists     bool
	SizeBytes  int64
	ModifiedAt time.Time
	// BuildDate is MaxMind's own edition build timestamp, read from the
	// .mmdb file's embedded metadata (Reader.Metadata().BuildEpoch, a Unix
	// timestamp every MaxMind DB file carries regardless of who downloaded
	// it or when) - distinct from ModifiedAt, which only says when *we*
	// wrote this file locally. The two normally track each other closely
	// (we download within a day of a weekly MaxMind release), but BuildDate
	// is what actually answers "how stale is this data at the source",
	// independent of our own download cadence. Zero time.Time if the file
	// couldn't be opened/parsed (corrupt download, wrong format) even
	// though os.Stat above found it.
	BuildDate time.Time
}

func fileInfo(path string) FileInfo {
	info, err := os.Stat(path)
	if err != nil {
		return FileInfo{}
	}
	fi := FileInfo{Exists: true, SizeBytes: info.Size(), ModifiedAt: info.ModTime()}
	// Best-effort: a missing/zero BuildDate just means the admin page shows
	// one less data point, never an error surfaced anywhere - Status() is a
	// read-only diagnostic, not something LookupCity/LookupASN depend on.
	if rd, openErr := geoip2.Open(path); openErr == nil {
		if buildEpoch := rd.Metadata().BuildEpoch; buildEpoch > 0 {
			fi.BuildDate = time.Unix(int64(buildEpoch), 0).UTC()
		}
		if closeErr := rd.Close(); closeErr != nil {
			log.Printf("geoip: close %s after reading metadata: %v", path, closeErr)
		}
	}
	return fi
}

// Status reports both editions' current on-disk FileInfo for dataDir -
// independent of the lazily-opened readers above (this stats the files
// directly rather than going through cityReader/asnReader), so it reflects
// reality even before either reader has ever been opened, e.g. right after
// a fresh install with no lookups performed yet.
func Status(dataDir string) (city, asn FileInfo) {
	return fileInfo(filepath.Join(dataDir, cityEdition+".mmdb")), fileInfo(filepath.Join(dataDir, asnEdition+".mmdb"))
}

// Configure points the lazy readers (and the downloader, via RunScheduler/
// TriggerNow) at dataDir. Idempotent - safe to call on every RunScheduler/
// TriggerNow invocation, since reader.setPath is itself a no-op when the
// path hasn't changed.
func Configure(dataDir string) {
	cityReader.setPath(filepath.Join(dataDir, cityEdition+".mmdb"))
	asnReader.setPath(filepath.Join(dataDir, asnEdition+".mmdb"))
}

// LookupCity returns the city and region (first/largest subdivision, e.g.
// a US state or German Bundesland - see geoip2.City's Subdivisions doc
// comment) for ip, in English. ok is false whenever no answer is available
// for any reason - GeoIP not configured/downloaded yet, ip failed to
// parse, or the address simply has no city-level data in MaxMind's
// database (common for many hosting-provider ranges) - callers must treat
// that identically to Session.Country's existing "" empty-string handling,
// never as evidence of anything by itself.
func LookupCity(ip string) (city, region string, ok bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", "", false
	}
	rd, ok := cityReader.get()
	if !ok {
		return "", "", false
	}
	rec, err := rd.City(addr)
	if err != nil || !rec.HasData() {
		return "", "", false
	}
	city = rec.City.Names.English
	if len(rec.Subdivisions) > 0 {
		region = rec.Subdivisions[0].Names.English
	}
	if city == "" && region == "" {
		return "", "", false
	}
	return city, region, true
}

// LookupASN returns the autonomous system organization (roughly "the ISP
// or hosting provider this IP belongs to") for ip. Same "ok=false means no
// answer, not necessarily an anomaly" contract as LookupCity.
func LookupASN(ip string) (org string, ok bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	rd, ok := asnReader.get()
	if !ok {
		return "", false
	}
	rec, err := rd.ASN(addr)
	if err != nil || !rec.HasData() || rec.AutonomousSystemOrganization == "" {
		return "", false
	}
	return rec.AutonomousSystemOrganization, true
}

// hostingOrVPNKeywords is a best-effort, deliberately coarse list of
// substrings (matched case-insensitively against LookupASN's
// AutonomousSystemOrganization result) that commonly show up in the ASN
// organization name of major cloud/hosting providers and consumer VPN
// services. This is a display-only heuristic, never an access-control
// signal - same treatment every other GeoIP-derived value in this package
// already gets (see LookupCity's doc comment): countless legitimate users
// route through a corporate VPN, a residential IP that happens to sit in a
// hosting provider's range, or one of these networks for entirely
// unremarkable reasons, and the list itself will always be incomplete (new
// providers, regional ISPs that also resell VPS/VPN, etc). It exists purely
// so an admin reviewing System Info/the audit log gets a "this looks like a
// datacenter or VPN, worth a second look" hint alongside the raw ISP name
// they'd otherwise have to recognize themselves - not a verdict.
//
// Deliberately not admin-configurable (unlike GeoIP's own credentials):
// this is a static, code-level heuristic list, not a per-instance policy -
// keeping it here means it improves for every instance on a Core upgrade
// rather than needing to be curated per install.
var hostingOrVPNKeywords = []string{
	// Major cloud/hosting providers.
	"amazon", "aws", "google cloud", "google llc", "microsoft", "azure",
	"digitalocean", "linode", "akamai", "cloudflare", "hetzner", "ovh",
	"vultr", "contabo", "scaleway", "leaseweb", "m247", "choopa",
	"datacamp", "hostinger", "oracle cloud", "alibaba", "tencent",
	"ionos", "netcup", "upcloud", "packet", "equinix", "rackspace",
	"fastly",
	// Consumer/commercial VPN services.
	"nordvpn", "nord security", "expressvpn", "surfshark", "protonvpn",
	"proton ag", "mullvad", "private internet access", "ipvanish",
	"cyberghost", "tunnelbear", "windscribe", "hide.me", "privado",
	"perfect privacy", "airvpn", "torguard", "vpnunlimited", "purevpn",
	"astrill", "hola networks",
}

// IsHostingOrVPN reports whether org (an AutonomousSystemOrganization string
// from LookupASN) matches one of hostingOrVPNKeywords. Returns false for an
// empty/unrecognized org - "no data" and "not on the list" are
// indistinguishable here on purpose, same as every other lookup in this
// package failing open rather than flagging the absence of information as
// suspicious.
func IsHostingOrVPN(org string) bool {
	if org == "" {
		return false
	}
	lower := strings.ToLower(org)
	for _, kw := range hostingOrVPNKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
