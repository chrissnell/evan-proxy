package metrics

import (
	"testing"

	"evan-proxy/pkg/logging"
)

// gatherLabelValues returns every value observed for labelName across all
// series of the named metric in m's private registry.
func gatherLabelValues(t *testing.T, m *Metrics, metricName, labelName string) []string {
	t.Helper()
	families, err := m.reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var out []string
	for _, mf := range families {
		if mf.GetName() != metricName {
			continue
		}
		for _, series := range mf.GetMetric() {
			for _, lp := range series.GetLabel() {
				if lp.GetName() == labelName {
					out = append(out, lp.GetValue())
				}
			}
		}
	}
	return out
}

func TestObserve_NoUserLabelByDefault(t *testing.T) {
	m := New(Options{UserLabel: false})
	m.Observe(logging.Entry{Event: "request", Method: "GET", Status: 200, User: "alice"})

	got := gatherLabelValues(t, m, "evanproxy_requests_total", "user")
	if len(got) != 0 {
		t.Fatalf("user label must not be emitted when UserLabel is false, got %v", got)
	}
}

func TestObserve_UserLabelWhenEnabled(t *testing.T) {
	m := New(Options{UserLabel: true})
	m.Observe(logging.Entry{Event: "request", Method: "GET", Status: 200, User: "alice"})

	got := gatherLabelValues(t, m, "evanproxy_requests_total", "user")
	var found bool
	for _, v := range got {
		if v == "alice" {
			found = true
		}
	}
	if !found {
		t.Fatalf("user label must be emitted when UserLabel is true, got %v", got)
	}
}
