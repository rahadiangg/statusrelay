// Package store persists the poller's per-record state between runs.
//
// It is a single JSON file rewritten atomically on every poll. The corpus is
// tiny (the reference upstream has published one incident in four years) and
// there is exactly one writer, so a database would add an operational
// dependency without buying anything. The one property that matters — a crash
// mid-write must leave the previous file intact — comes from write-to-temp
// plus rename.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/rahadiangg/statwatch/internal/incident"
	"github.com/rahadiangg/statwatch/internal/platform/clock"
)

// Version is the on-disk format version. Bump it when a field changes
// meaning, not when one is added: encoding/json ignores unknown fields, so
// additions are free.
const Version = 1

// Store is one state file.
type Store struct {
	path  string
	clock clock.Clock
}

// New returns a Store for path. Nothing is touched until Load or Save. The
// clock names the corrupt-file backup; nil means the system clock.
func New(path string, clk clock.Clock) *Store {
	if clk == nil {
		clk = clock.System{}
	}
	return &Store{path: path, clock: clk}
}

// Path returns the file location, for logs.
func (s *Store) Path() string { return s.path }

// file is the on-disk document. Records are a list because incident.Key is
// a struct and cannot be a JSON object key.
type file struct {
	Version int               `json:"version"`
	SavedAt time.Time         `json:"saved_at"`
	Records []incident.Stored `json:"records"`
}

// Load reads the state. A missing file is an empty state, not an error: it is
// the normal first run.
//
// A file that exists but cannot be parsed is moved to <path>.corrupt-<unix>
// and ErrCorrupt is returned with an empty map. The caller is expected to log
// loudly and cold-start: a watcher that refuses to start over a damaged cache
// is down during exactly the outage it exists to report, and cold start only
// re-alerts what is currently open, which is the safe direction.
func (s *Store) Load() (map[incident.Key]incident.Stored, error) {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[incident.Key]incident.Stored{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading %s: %w", s.path, err)
	}

	var f file
	if perr := json.Unmarshal(raw, &f); perr != nil || f.Version == 0 {
		aside := fmt.Sprintf("%s.corrupt-%d", s.path, s.clock.Now().Unix())
		if rerr := os.Rename(s.path, aside); rerr != nil {
			return nil, fmt.Errorf("%w: %s (and could not move it aside: %v)", ErrCorrupt, s.path, rerr)
		}
		if perr == nil {
			perr = errors.New("missing version field")
		}
		return map[incident.Key]incident.Stored{}, fmt.Errorf("%w: %s moved to %s: %v", ErrCorrupt, s.path, aside, perr)
	}
	if f.Version > Version {
		return nil, fmt.Errorf("%w: file is v%d, binary reads v%d", ErrVersion, f.Version, Version)
	}

	out := make(map[incident.Key]incident.Stored, len(f.Records))
	for _, r := range f.Records {
		// A duplicate key cannot be produced by Save; if one is here the
		// file was edited by hand. Last wins, and the caller's count will
		// not match the record count, which is visible enough.
		out[r.Record.Key] = r
	}
	return out, nil
}

// Save writes the state atomically.
//
// The temp file lives in the same directory so the rename is a same-filesystem
// metadata operation, and the directory is fsynced afterwards so the rename
// itself survives a power loss. Records are sorted so two saves of the same
// state are byte-identical and the file diffs cleanly.
func (s *Store) Save(m map[incident.Key]incident.Stored, now time.Time) error {
	f := file{Version: Version, SavedAt: now.UTC(), Records: make([]incident.Stored, 0, len(m))}
	for _, r := range m {
		f.Records = append(f.Records, r)
	}
	sort.Slice(f.Records, func(i, j int) bool {
		return f.Records[i].Record.Key.String() < f.Records[j].Record.Key.String()
	})
	// Compact, not indented: Record.RawReport is an opaque json.RawMessage
	// and MarshalIndent would reformat it, so the bytes we were handed would
	// no longer be the bytes we hand back.
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("store: encoding: %w", err)
	}
	data = append(data, '\n')

	tmp := s.path + ".tmp"
	if err := writeSync(tmp, data); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("store: replacing %s: %w", s.path, err)
	}
	// Directory fsync is best effort: some filesystems refuse it, and a
	// failure here means the rename may be lost on power cut, not that the
	// data is wrong.
	if d, err := os.Open(filepath.Dir(s.path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func writeSync(path string, data []byte) error {
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("store: creating %s: %w", path, err)
	}
	if _, err := fh.Write(data); err != nil {
		_ = fh.Close()
		return fmt.Errorf("store: writing %s: %w", path, err)
	}
	if err := fh.Sync(); err != nil {
		_ = fh.Close()
		return fmt.Errorf("store: syncing %s: %w", path, err)
	}
	if err := fh.Close(); err != nil {
		return fmt.Errorf("store: closing %s: %w", path, err)
	}
	return nil
}
