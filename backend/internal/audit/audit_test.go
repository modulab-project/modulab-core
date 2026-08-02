package audit

import "testing"

// entryHMAC/legacyEntryHMAC are the pure functions behind the audit log's
// tamper-evidence chain (Audit 2026-08-02, A-1 #4) - the actual security
// property the README promises ("Audit-Log: Manipulationssicher") lives
// entirely in these two functions plus Verify's walk over them. Verify
// itself needs a real db.Pool, so these tests exercise the hashing directly:
// same inputs -> same hash, any single field changing -> a different hash,
// and the legacy (pre-2026-07-23) formula staying distinct from the
// current one so old rows keep verifying under their original formula.
const testMasterKey = "test-master-key-not-a-real-secret"

func TestEntryHMAC_Deterministic(t *testing.T) {
	h1 := entryHMAC(testMasterKey, "user.approved", "actor-1", "target-1", "encA", "encB", "encC", "prevHash")
	h2 := entryHMAC(testMasterKey, "user.approved", "actor-1", "target-1", "encA", "encB", "encC", "prevHash")
	if h1 != h2 {
		t.Fatalf("entryHMAC is not deterministic: %q vs %q", h1, h2)
	}
	if h1 == "" {
		t.Fatalf("entryHMAC returned empty hash")
	}
}

// Every field entryHMAC takes must actually be covered by the hash - if any
// of these could change without changing the output, that field could be
// tampered with in place and Verify would never notice.
func TestEntryHMAC_EveryFieldIsCovered(t *testing.T) {
	base := entryHMAC(testMasterKey, "user.approved", "actor-1", "target-1", "encA", "encB", "encC", "prevHash")

	variants := map[string]string{
		"eventType":      entryHMAC(testMasterKey, "user.locked", "actor-1", "target-1", "encA", "encB", "encC", "prevHash"),
		"actorID":        entryHMAC(testMasterKey, "user.approved", "actor-2", "target-1", "encA", "encB", "encC", "prevHash"),
		"targetID":       entryHMAC(testMasterKey, "user.approved", "actor-1", "target-2", "encA", "encB", "encC", "prevHash"),
		"actorEmailEnc":  entryHMAC(testMasterKey, "user.approved", "actor-1", "target-1", "encX", "encB", "encC", "prevHash"),
		"targetEmailEnc": entryHMAC(testMasterKey, "user.approved", "actor-1", "target-1", "encA", "encX", "encC", "prevHash"),
		"detailsEnc":     entryHMAC(testMasterKey, "user.approved", "actor-1", "target-1", "encA", "encB", "encX", "prevHash"),
		"prevHash":       entryHMAC(testMasterKey, "user.approved", "actor-1", "target-1", "encA", "encB", "encC", "differentPrev"),
	}

	for field, hash := range variants {
		if hash == base {
			t.Fatalf("changing %s did not change the resulting hash - field is not covered by the HMAC", field)
		}
	}
}

// Different master keys must produce different hashes for identical entry
// data - otherwise copying the DB to another instance with a different
// master key would still verify, defeating the "hashes tied to this
// instance's key" property the audit.go doc comment promises.
func TestEntryHMAC_DifferentKeyDifferentHash(t *testing.T) {
	a := entryHMAC(testMasterKey, "user.approved", "actor-1", "target-1", "encA", "encB", "encC", "prevHash")
	b := entryHMAC("a-different-master-key", "user.approved", "actor-1", "target-1", "encA", "encB", "encC", "prevHash")
	if a == b {
		t.Fatalf("entries hashed under different master keys produced the same hash")
	}
}

// legacyEntryHMAC must keep reproducing the pre-2026-07-23 formula exactly
// (eventType/actorID/targetID/prevHash only) so historical rows keep
// verifying - and it must differ from the current, wider entryHMAC for the
// same logical entry, since that's precisely why both functions still exist.
func TestLegacyEntryHMAC_DiffersFromCurrentFormula(t *testing.T) {
	legacy := legacyEntryHMAC(testMasterKey, "user.approved", "actor-1", "target-1", "prevHash")
	current := entryHMAC(testMasterKey, "user.approved", "actor-1", "target-1", "", "", "", "prevHash")
	if legacy == current {
		t.Fatalf("legacyEntryHMAC collided with entryHMAC given empty ciphertext fields - the two formulas must stay distinct")
	}
}

func TestLegacyEntryHMAC_Deterministic(t *testing.T) {
	h1 := legacyEntryHMAC(testMasterKey, "user.approved", "actor-1", "target-1", "prevHash")
	h2 := legacyEntryHMAC(testMasterKey, "user.approved", "actor-1", "target-1", "prevHash")
	if h1 != h2 {
		t.Fatalf("legacyEntryHMAC is not deterministic: %q vs %q", h1, h2)
	}
}

// A minimal simulation of what Verify does across a chain of entries: each
// entry's hash depends on the previous entry's hash, so tampering with any
// one entry's stored fields breaks every hash computed from it onward -
// this is the actual tamper-evidence property, exercised here without a
// database.
func TestHashChain_TamperingBreaksSubsequentLinks(t *testing.T) {
	type entry struct {
		eventType, actorID, targetID, actorEmailEnc, targetEmailEnc, detailsEnc string
	}
	entries := []entry{
		{"user.approved", "admin-1", "user-1", "", "", ""},
		{"user.locked", "admin-1", "user-2", "", "", ""},
		{"user.deleted", "admin-1", "user-3", "", "", ""},
	}

	// Build the honest chain.
	hashes := make([]string, len(entries))
	prev := ""
	for i, e := range entries {
		hashes[i] = entryHMAC(testMasterKey, e.eventType, e.actorID, e.targetID, e.actorEmailEnc, e.targetEmailEnc, e.detailsEnc, prev)
		prev = hashes[i]
	}

	// Walk it back and confirm it verifies cleanly, as Verify would.
	prev = ""
	for i, e := range entries {
		want := entryHMAC(testMasterKey, e.eventType, e.actorID, e.targetID, e.actorEmailEnc, e.targetEmailEnc, e.detailsEnc, prev)
		if want != hashes[i] {
			t.Fatalf("entry %d: chain does not verify before tampering", i)
		}
		prev = hashes[i]
	}

	// Now tamper with entry 1's targetID in place (as if someone edited the
	// row directly in the DB) and recompute the walk exactly as Verify
	// would, using the *stored* hashes unchanged.
	tampered := entries
	tampered[1].targetID = "user-99"

	prev = ""
	brokenAt := -1
	for i, e := range tampered {
		recomputed := entryHMAC(testMasterKey, e.eventType, e.actorID, e.targetID, e.actorEmailEnc, e.targetEmailEnc, e.detailsEnc, prev)
		if recomputed != hashes[i] {
			brokenAt = i
			break
		}
		prev = hashes[i]
	}

	if brokenAt != 1 {
		t.Fatalf("expected tampering at entry 1 to be detected there, broke at index %d instead", brokenAt)
	}
}
