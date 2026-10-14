package metrics

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/rahadiangg/statusrelay/internal/incident"
)

// dashboardPath is the example Grafana dashboard shipped in examples/. A
// renamed metric does not break Grafana loudly: the panel just reads
// "No data", which on this dashboard is indistinguishable from "nothing
// happened". This test is the only thing that notices.
const dashboardPath = "../../examples/docker-compose/grafana/dashboards/statusrelay.json"

var metricRef = regexp.MustCompile(`\bstatusrelay_[a-z_]+`)

func TestDashboardReferencesOnlyExposedMetrics(t *testing.T) {
	raw, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Panels []struct {
			Title   string `json:"title"`
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
		Templating struct {
			List []struct {
				Definition string `json:"definition"`
			} `json:"list"`
		} `json:"templating"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("dashboard is not valid JSON: %v", err)
	}

	exposed := exposedNames(t)
	refs := 0
	check := func(where, expr string) {
		for _, name := range metricRef.FindAllString(expr, -1) {
			refs++
			if !exposed[name] {
				t.Errorf("%s: %s is not exposed by the registry", where, name)
			}
		}
	}
	for _, p := range doc.Panels {
		for _, tg := range p.Targets {
			check("panel "+p.Title, tg.Expr)
		}
	}
	for _, v := range doc.Templating.List {
		check("variable", v.Definition)
	}
	// Guards the test itself: a JSON layout change that hides every expr
	// from the struct above would otherwise pass vacuously.
	if refs < 20 {
		t.Errorf("got %d metric references, want at least 20", refs)
	}
}

// exposedNames is every series name a scrape can return, histogram
// suffixes included.
func exposedNames(t *testing.T) map[string]bool {
	t.Helper()
	r, reg := newTestRecorder(t)
	// The one family that is absent until the provider reports a count.
	r.SnapshotSeen("huawei-intl", &incident.Snapshot{Complete: true, UnresolvedCount: 1})
	fams, err := prometheus.Gatherer(reg).Gather()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range fams {
		names[f.GetName()] = true
		if f.GetType() == dto.MetricType_HISTOGRAM {
			for _, s := range []string{"_bucket", "_sum", "_count"} {
				names[f.GetName()+s] = true
			}
		}
	}
	return names
}
