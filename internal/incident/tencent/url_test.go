package tencent

import "testing"

// Tencent publishes no per-incident page, so the link is the site root: a
// working link to the grid beats a guessed deep link that 404s.
func TestPageURL(t *testing.T) {
	for _, tc := range []struct{ name, base, id, want string }{
		{"default base", DefaultBaseURL, "X1", "https://status.tencentcloud.com/"},
		{"path on base is dropped", DefaultBaseURL + "/api/v1/", "X1", "https://status.tencentcloud.com/"},
		{"id is ignored", DefaultBaseURL, "any/thing", "https://status.tencentcloud.com/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pageURL(tc.base)(tc.id); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMappedRecordCarriesURL(t *testing.T) {
	open, resolved, _ := mapFixture(t, "history_all.json")
	recs := append(open, resolved...)
	if len(recs) == 0 {
		t.Fatal("fixture mapped to no records")
	}
	if recs[0].URL != "https://status.tencentcloud.com/" {
		t.Errorf("URL: got %q, want the site root", recs[0].URL)
	}
}
