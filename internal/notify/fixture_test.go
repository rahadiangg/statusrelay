package notify

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rahadiangg/statusrelay/internal/incident"
)

// goldenDoc loads a fixture. A missing or empty golden fails loudly: a
// rendering test that compares against nothing passes vacuously.
func goldenDoc(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	if len(b) == 0 {
		t.Fatalf("fixture %s is empty; a golden test reading nothing passes vacuously", name)
	}
	return b
}

// event13 is the reference incident, shaped as the Huawei adapter emits it.
// It is built by hand rather than loaded through the adapter so this package
// stays independent of any concrete provider.
func event13() incident.Event {
	svcs := []incident.Service{
		{ID: "iam", Name: "Identity and Access Management", Abbr: "IAM"},
		{ID: "ecs", Name: "Elastic Cloud Server", Abbr: "ECS"},
	}
	r := incident.Record{
		Key:         incident.Key{SourceID: "huawei-intl", ProviderID: "13"},
		Title:       "Notification of Abnormal Huawei Cloud Accounts in AP-Manila, CN-Hong Kong, AP-Jakarta, LA-Sao Paulo1 and TR-Istanbul Regions on Jul 26, 2026 GMT+8:00",
		TitleLang:   "en",
		Severity:    incident.SeverityMajor,
		RawSeverity: "2",
		Status:      incident.StatusOpen,
		StartedAt:   time.Date(2026, 7, 25, 19, 5, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 7, 27, 0, 4, 52, 0, time.UTC),
		Scope: []incident.Scope{
			{RegionCode: "ap-southeast-4", RegionName: "AP-Jakarta", Services: svcs},
			{RegionCode: "ap-southeast-3", RegionName: "AP-Singapore", Services: svcs},
		},
		Updates: []incident.Update{{
			At:   time.Date(2026, 7, 25, 19, 5, 0, 0, time.UTC),
			Text: "Dear customer,\nOn Jul 26, 2026, 02:49:00 GMT+8:00, Huawei Cloud detected that an anomaly occurred in the Huawei Cloud International Site accounts.\n  We are working to resolve this issue.",
			Lang: "en",
		}},
	}
	r.FP = incident.Compute(r)
	return incident.Event{Kind: incident.KindNew, Record: r, NewUpdates: r.Updates}
}
