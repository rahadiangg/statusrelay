package notify

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
)

var update = flag.Bool("update", false, "rewrite golden files")

func TestRenderGolden(t *testing.T) {
	base := event13()

	jakarta, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		t.Fatal(err)
	}
	named := Renderer{Loc: jakarta, Names: map[string]string{"huawei-intl": "Huawei Cloud"}}

	for _, tc := range []struct {
		name string
		rd   Renderer
		ev   func() incident.Event
	}{
		{name: "new", ev: func() incident.Event { return base }},
		{name: "new_named_local_time", rd: named, ev: func() incident.Event { return base }},
		{name: "many_watched_regions", rd: named, ev: func() incident.Event {
			ev := base
			ev.Record.Scope = nil
			for _, c := range []string{"ap-southeast-4", "ap-southeast-3", "ap-southeast-2", "cn-hongkong", "tr-west-1"} {
				ev.Record.Scope = append(ev.Record.Scope, incident.Scope{RegionCode: c, RegionName: c})
			}
			ev.Watched = ev.Record.Scope // watching everything: no separate Watched line, capped subject
			ev.NewUpdates = nil
			return ev
		}},
		{name: "updated", ev: func() incident.Event {
			ev := base
			ev.Kind = incident.KindUpdated
			ev.NewUpdates = []incident.Update{{
				At:   time.Date(2026, 7, 26, 3, 5, 0, 0, time.UTC),
				Text: "尊敬的华为云客户：\n问题已修复。<b>感谢</b> *您* 的支持！",
				Lang: "zh",
			}}
			return ev
		}},
		{name: "scope_changed", ev: func() incident.Event {
			ev := base
			ev.Kind = incident.KindScopeChanged
			ev.NewUpdates = nil
			ev.Added = []string{"ap-southeast-5/ECS"}
			ev.Removed = []string{"ap-southeast-3/IAM"}
			return ev
		}},
		{name: "resolved", ev: func() incident.Event {
			ev := base
			ev.Kind = incident.KindResolved
			ev.Record.Status = incident.StatusResolved
			ev.Record.EndedAt = time.Date(2026, 7, 27, 0, 4, 52, 0, time.UTC)
			ev.NewUpdates = nil
			return ev
		}},
		{name: "vanished", ev: func() incident.Event {
			ev := base
			ev.Kind = incident.KindVanished
			ev.Record.Status = incident.StatusUnknown
			ev.NewUpdates = nil
			return ev
		}},
		{name: "global_cold_start_unknown_severity", ev: func() incident.Event {
			ev := base
			ev.ColdStart = true
			ev.Record.Global = true
			ev.Record.Scope = nil
			ev.Watched = []incident.Scope{}
			ev.Record.Severity = incident.SeverityUnknown
			ev.Record.RawSeverity = "7"
			ev.Record.StartedAt = time.Time{}
			ev.NewUpdates = []incident.Update{{Text: "no timestamp on this one"}}
			return ev
		}},
		{name: "empty_scope_region_without_services", ev: func() incident.Event {
			ev := base
			ev.Kind = incident.KindMinorUpdated
			ev.NewUpdates = nil
			ev.Record.Scope = []incident.Scope{{RegionCode: "tr-west-1"}}
			ev.Watched = nil // built without a filter: falls back to the full scope
			return ev
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.rd.Render(tc.ev())
			got := "Subject: " + m.Subject + "\n\n" + m.Body
			path := filepath.Join("testdata", tc.name+".golden")
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want := string(goldenDoc(t, tc.name+".golden"))
			if got != want {
				t.Errorf("render mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}
		})
	}
}

// Provider-controlled text reaches the subject through region names; a line
// break there would inject mail headers.
func TestRenderSubjectIsOneLine(t *testing.T) {
	ev := event13()
	ev.Watched[0].RegionName = "Line one\r\nBcc: attacker@example.com\nline three"
	m := Render(ev)
	if strings.ContainsAny(m.Subject, "\r\n") {
		t.Errorf("subject contains line breaks: %q", m.Subject)
	}
	if !strings.Contains(m.Subject, "Line one Bcc: attacker@example.com line three") {
		t.Errorf("subject lost text: got %q", m.Subject)
	}
	if strings.Contains(m.Subject, ev.Record.Title[:20]) {
		t.Errorf("subject still carries the provider title: %q", m.Subject)
	}
}

func TestRenderUnknownKindStillLabelled(t *testing.T) {
	ev := event13()
	ev.Kind = incident.EventKind("teleported")
	m := Render(ev)
	if !strings.HasPrefix(m.Body, "TELEPORTED ·") {
		t.Errorf("got body prefix %q, want raw kind upper-cased", strings.SplitN(m.Body, "\n", 2)[0])
	}
}

func TestRenderNeverQuotesFullHistory(t *testing.T) {
	ev := event13()
	ev.Kind = incident.KindUpdated
	ev.Record.Updates = append(ev.Record.Updates, incident.Update{Text: "second entry, already delivered"})
	ev.NewUpdates = []incident.Update{{Text: "third entry, the news"}}
	m := Render(ev)
	if strings.Contains(m.Body, "already delivered") {
		t.Errorf("body quoted history, not just NewUpdates:\n%s", m.Body)
	}
	if !strings.Contains(m.Body, "third entry, the news") {
		t.Errorf("body missing the new update:\n%s", m.Body)
	}
}

func TestEventIDAndThreadID(t *testing.T) {
	a := event13()
	b := event13()
	if EventID(a) != EventID(b) {
		t.Fatal("EventID is not deterministic")
	}
	if ThreadID(a.Record.Key) != ThreadID(b.Record.Key) {
		t.Fatal("ThreadID is not deterministic")
	}

	// A new progress entry is new information: different id, same thread.
	c := event13()
	c.Record.Updates = append(c.Record.Updates, incident.Update{Text: "more"})
	c.Record.FP = incident.Compute(c.Record)
	if EventID(a) == EventID(c) {
		t.Error("EventID ignored a fingerprint change")
	}
	if ThreadID(a.Record.Key) != ThreadID(c.Record.Key) {
		t.Error("ThreadID changed within one incident")
	}

	// Same record, different transition: different id.
	d := event13()
	d.Kind = incident.KindResolved
	if EventID(a) == EventID(d) {
		t.Error("EventID ignored the event kind")
	}

	if len(EventID(a)) != 16 || len(ThreadID(a.Record.Key)) != 16 {
		t.Errorf("ids are not 16 hex chars: %q %q", EventID(a), ThreadID(a.Record.Key))
	}
}
