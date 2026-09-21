package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
	"github.com/rahadiangg/statusrelay/internal/platform/clock"
)

var testEpoch = time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)

// fullRecord carries every field a Stored can hold, so a round-trip test
// cannot pass while silently dropping one.
func fullRecord(id string) incident.Stored {
	r := incident.Record{
		Key:         incident.Key{SourceID: "huawei-intl", ProviderID: id},
		Title:       "Abnormal accounts 亚太",
		TitleLang:   "en",
		Titles:      map[string]string{"en": "Abnormal accounts 亚太", "zh": "账号异常"},
		Severity:    incident.SeverityMajor,
		RawSeverity: "2",
		Status:      incident.StatusOpen,
		StartedAt:   testEpoch.Add(-time.Hour),
		UpdatedAt:   testEpoch.Add(-time.Minute),
		Scope: []incident.Scope{{
			RegionID: "rid", RegionCode: "ap-southeast-4", RegionName: "AP-Jakarta",
			Services: []incident.Service{{ID: "sid", Name: "Elastic Cloud Server", Abbr: "ECS"}},
		}},
		Updates:   []incident.Update{{At: testEpoch.Add(-time.Hour), Text: "Dear customer", Lang: "en", Hash: "h1"}},
		HasReport: true,
		RawReport: json.RawMessage(`{"x":1}`),
	}
	r.FP = incident.Compute(r)
	return incident.Stored{
		Record: r, Status: incident.StatusOpen, FP: r.FP, Identity: "ident", Matched: true,
		FirstSeenAt: testEpoch.Add(-time.Hour), LastSeenAt: testEpoch, VanishCount: 2,
	}
}

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	return New(path, clock.NewFake(testEpoch)), path
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	s, _ := newTestStore(t)
	got, err := s.Load()
	if err != nil {
		t.Fatalf("got err %v, want nil", err)
	}
	if len(got) != 0 || got == nil {
		t.Errorf("got %v, want empty non-nil map", got)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	s, path := newTestStore(t)
	want := map[incident.Key]incident.Stored{}
	for _, id := range []string{"13", "7", "20"} {
		r := fullRecord(id)
		want[r.Record.Key] = r
	}
	if err := s.Save(want, testEpoch); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Times survive with location normalised to UTC; compare after the same
	// normalisation so a timezone difference cannot mask a real field loss.
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round-trip mismatch\n got %+v\nwant %+v", got, want)
	}

	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temp file left behind: %v", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("got mode %o, want 0600", info.Mode().Perm())
	}

	raw, _ := os.ReadFile(path)
	// Sorted by key string: "huawei-intl/13" < "huawei-intl/20" < "huawei-intl/7".
	i13 := strings.Index(string(raw), `"ProviderID":"13"`)
	i20 := strings.Index(string(raw), `"ProviderID":"20"`)
	i7 := strings.Index(string(raw), `"ProviderID":"7"`)
	if i13 >= i20 || i20 >= i7 {
		t.Errorf("records not sorted by key: 13@%d 20@%d 7@%d", i13, i20, i7)
	}
	var f file
	if err := json.Unmarshal(raw, &f); err != nil || f.Version != Version || !f.SavedAt.Equal(testEpoch) {
		t.Errorf("envelope wrong: err=%v version=%d saved_at=%s", err, f.Version, f.SavedAt)
	}
}

func TestSaveIsByteStable(t *testing.T) {
	s, path := newTestStore(t)
	m := map[incident.Key]incident.Stored{}
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		r := fullRecord(id)
		m[r.Record.Key] = r
	}
	if err := s.Save(m, testEpoch); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(path)
	if err := s.Save(m, testEpoch); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(path)
	if string(first) != string(second) {
		t.Error("two saves of identical state produced different bytes")
	}
}

func TestLoadCorruptMovesAside(t *testing.T) {
	for _, tc := range []struct{ name, content string }{
		{name: "garbage", content: "not json {"},
		{name: "empty file", content: ""},
		{name: "wrong shape", content: `[1,2,3]`},
		{name: "missing version", content: `{"records":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, path := newTestStore(t)
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := s.Load()
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("got err %v, want ErrCorrupt", err)
			}
			if len(got) != 0 || got == nil {
				t.Errorf("got %v, want empty non-nil map for cold start", got)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Error("corrupt file still in place")
			}
			aside := path + ".corrupt-" + "1789984800" // testEpoch unix
			b, rerr := os.ReadFile(aside)
			if rerr != nil {
				t.Fatalf("backup not found at %s: %v", aside, rerr)
			}
			if string(b) != tc.content {
				t.Error("backup content differs from the original")
			}
			if !strings.Contains(err.Error(), aside) {
				t.Errorf("error should name the backup: %v", err)
			}
			// Second load is a clean cold start.
			if _, err := s.Load(); err != nil {
				t.Errorf("load after move-aside: %v", err)
			}
		})
	}
}

func TestLoadNewerVersionIsFatal(t *testing.T) {
	s, path := newTestStore(t)
	if err := os.WriteFile(path, []byte(`{"version":2,"records":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Load()
	if !errors.Is(err, ErrVersion) {
		t.Fatalf("got err %v, want ErrVersion", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Error("a newer-version file must be left untouched")
	}
}

func TestLoadDuplicateKeyLastWins(t *testing.T) {
	s, path := newTestStore(t)
	a, b := fullRecord("13"), fullRecord("13")
	b.VanishCount = 99
	f := file{Version: Version, Records: []incident.Stored{a, b}}
	raw, _ := json.Marshal(f)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[a.Record.Key].VanishCount != 99 {
		t.Errorf("got %d records, VanishCount %d; want 1 record with 99", len(got), got[a.Record.Key].VanishCount)
	}
}

func TestSaveFailsInUnwritableDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	s := New(filepath.Join(dir, "state.json"), clock.NewFake(testEpoch))
	err := s.Save(map[incident.Key]incident.Stored{}, testEpoch)
	if err == nil {
		t.Fatal("got nil, want error")
	}
	if _, serr := os.Stat(filepath.Join(dir, "state.json.tmp")); !errors.Is(serr, os.ErrNotExist) {
		t.Error("temp file left behind after failed save")
	}
}

func TestSaveKeepsOldFileWhenTempWriteFails(t *testing.T) {
	// The temp path is occupied by a directory, so the write fails after
	// the previous good file already exists: it must survive untouched.
	s, path := newTestStore(t)
	m := map[incident.Key]incident.Stored{}
	r := fullRecord("1")
	m[r.Record.Key] = r
	if err := s.Save(m, testEpoch); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(map[incident.Key]incident.Stored{}, testEpoch); err == nil {
		t.Fatal("got nil, want error")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("previous state file was damaged by a failed save")
	}
}

func TestNewNilClockUsesSystem(t *testing.T) {
	s := New("x", nil)
	if s.clock == nil {
		t.Fatal("clock is nil")
	}
	if s.Path() != "x" {
		t.Errorf("got path %q, want x", s.Path())
	}
}
