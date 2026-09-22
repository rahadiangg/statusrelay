package alibaba

import (
	"testing"

	"github.com/rahadiangg/statusrelay/internal/incident"
)

func TestPageURL(t *testing.T) {
	for _, tc := range []struct{ name, base, id, want string }{
		{"default base", DefaultBaseURL, "32", "https://status.alibabacloud.com/#/eventDetail?eventId=32"},
		{"trailing slash", DefaultBaseURL + "/", "32", "https://status.alibabacloud.com/#/eventDetail?eventId=32"},
		{"custom base without api path falls back to origin", "https://mirror.example.com/other/api", "1", "https://mirror.example.com/#/eventDetail?eventId=1"},
		{"id is query-escaped", DefaultBaseURL, "a&b", "https://status.alibabacloud.com/#/eventDetail?eventId=a%26b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pageURL(tc.base)(tc.id); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMappedRecordCarriesURL(t *testing.T) {
	recs, _ := mapFixture(t, "detail_35.json", incident.StatusResolved)
	if len(recs) == 0 {
		t.Fatal("fixture mapped to no records")
	}
	want := "https://status.alibabacloud.com/#/eventDetail?eventId=" + recs[0].Key.ProviderID
	if recs[0].URL != want {
		t.Errorf("URL: got %q, want %q", recs[0].URL, want)
	}
}
