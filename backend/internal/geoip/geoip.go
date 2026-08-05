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

	"github.com/modulab-project/modulab-core/backend/internal/db"
	"github.com/modulab-project/modulab-core/backend/internal/setup"
)

// tickInterval is how often RunScheduler re-downloads both databases. Once
// per day is plenty - MaxMind only republishes GeoLite2 databases weekly
// (Tuesdays, per their own docs), so anything more frequent would just be
// re-downloading the same bytes. Matches revalidateTickInterval's reasoning
// of "generous enough to never matter in practice, small enough that a
// credential fix or a new weekly release is picked up the same day".
const tickInterval = 24 * time.Hour

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

// RunScheduler is the long-running background goroutine driving the daily
// database refresh. Unlike coreupdate.RunScheduler (which deliberately does
// NOT run once at startup), this DOES run immediately before entering the
// ticker loop: a fresh install with credentials already configured (e.g.
// restored from a backup) should not have to wait up to tickInterval for
// its first pair of databases - LookupCity/LookupASN would otherwise report
// ok=false the entire time in between for no good reason.
func RunScheduler(ctx context.Context, deps Deps) {
	Configure(deps.DataDir)
	downloadAll(ctx, deps)

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
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

	if err := os.MkdirAll(deps.DataDir, 0o755); err != nil {
		recordFailure(ctx, deps.Pool, fmt.Errorf("create data dir %q: %w", deps.DataDir, err))
		return
	}

	var failures []string
	for _, edition := range []string{cityEdition, asnEdition} {
		if err := downloadEdition(ctx, deps.DataDir, edition, cfg); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", edition, err))
		}
	}
	if len(failures) > 0 {
		recordFailure(ctx, deps.Pool, fmt.Errorf("%s", strings.Join(failures, "; ")))
		return
	}

	if err := deps.Pool.DeleteSetting(ctx, setup.GeoIPLastUpdateErrorSettingKey); err != nil {
		log.Printf("geoip: clear last update error: %v", err)
	}
	if err := deps.Pool.SetSetting(ctx, setup.GeoIPLastUpdateAtSettingKey, time.Now().UTC().Format(time.RFC3339)); err != nil {
		log.Printf("geoip: record last update time: %v", err)
	}
}

// recordFailure logs err and best-effort persists it to
// setup.GeoIPLastUpdateErrorSettingKey - a failure to write that setting
// itself is only logged, never escalated, since the download failure it
// was trying to record is already the more important fact and this must
// not prevent the next tick from trying again.
func recordFailure(ctx context.Context, pool *db.Pool, err error) {
	log.Printf("geoip: download: %v", err)
	if setErr := pool.SetSetting(ctx, setup.GeoIPLastUpdateErrorSettingKey, err.Error()); setErr != nil {
		log.Printf("geoip: record last update error: %v", setErr)
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
