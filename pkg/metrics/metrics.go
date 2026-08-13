package metrics

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"evan-proxy/pkg/logging"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Options configures the metrics collector.
type Options struct {
	// UserLabel includes the per-user label on evanproxy_requests_total. This
	// is PII (the children's usernames) so it is opt-in and off by default.
	UserLabel bool
}

type Metrics struct {
	reg       *prometheus.Registry
	userLabel bool

	requests      *prometheus.CounterVec
	blocked       *prometheus.CounterVec
	duration      *prometheus.HistogramVec
	bytesRead     prometheus.Counter
	bytesWritten  prometheus.Counter
	activeTunnels prometheus.Gauge
	authFailures  prometheus.Counter
	dnsLookups    *prometheus.CounterVec
	dnsDuration   prometheus.Histogram
}

func New(opts Options) *Metrics {
	requestLabels := []string{"method", "status_code"}
	requestHelp := "Total proxy requests by method and status code."
	if opts.UserLabel {
		requestLabels = append(requestLabels, "user")
		requestHelp = "Total proxy requests by method, status code, and user."
	}

	m := &Metrics{
		userLabel: opts.UserLabel,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "evanproxy_requests_total",
			Help: requestHelp,
		}, requestLabels),

		blocked: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "evanproxy_blocked_total",
			Help: "Total blocked requests by reason.",
		}, []string{"reason"}),

		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "evanproxy_request_duration_seconds",
			Help:    "Request duration in seconds.",
			Buckets: []float64{.01, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60, 300},
		}, []string{"method"}),

		bytesRead: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "evanproxy_bytes_read_total",
			Help: "Total bytes read from clients.",
		}),

		bytesWritten: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "evanproxy_bytes_written_total",
			Help: "Total bytes written to clients.",
		}),

		activeTunnels: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "evanproxy_active_tunnels",
			Help: "Number of active CONNECT tunnels.",
		}),

		authFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "evanproxy_auth_failures_total",
			Help: "Total authentication failures.",
		}),

		dnsLookups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "evanproxy_dns_lookups_total",
			Help: "Total DNS lookups by result.",
		}, []string{"result"}),

		dnsDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "evanproxy_dns_duration_seconds",
			Help:    "DNS lookup duration in seconds.",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		}),
	}

	// Use a private registry rather than the global default so metrics can't
	// leak across processes and tests stay isolated.
	m.reg = prometheus.NewRegistry()
	m.reg.MustRegister(
		m.requests,
		m.blocked,
		m.duration,
		m.bytesRead,
		m.bytesWritten,
		m.activeTunnels,
		m.authFailures,
		m.dnsLookups,
		m.dnsDuration,
	)

	return m
}

// Handler returns the Prometheus HTTP handler for /metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// ObserveLiveBytes updates throughput counters from live traffic deltas.
func (m *Metrics) ObserveLiveBytes(read, written int64) {
	if read > 0 {
		m.bytesRead.Add(float64(read))
	}
	if written > 0 {
		m.bytesWritten.Add(float64(written))
	}
}

// Observe implements the logger observer pattern. Must not block.
func (m *Metrics) Observe(e logging.Entry) {
	// Track tunnel open/close
	if e.Event == "open" {
		m.activeTunnels.Inc()
		return // don't count "open" as a request to avoid double-counting
	}
	if e.Event == "close" {
		m.activeTunnels.Dec()
	}

	// Request counter. The per-user label is PII (usernames) and only emitted
	// when explicitly enabled.
	if m.userLabel {
		user := e.User
		if user == "" {
			user = "anonymous"
		}
		m.requests.WithLabelValues(e.Method, strconv.Itoa(e.Status), user).Inc()
	} else {
		m.requests.WithLabelValues(e.Method, strconv.Itoa(e.Status)).Inc()
	}

	// Blocked request classification
	switch {
	case e.Event == "dns-block":
		m.blocked.WithLabelValues("dns_block").Inc()
	case e.Status == 403:
		m.blocked.WithLabelValues("acl").Inc()
	case strings.Contains(e.Error, "rate limited"):
		m.blocked.WithLabelValues("rate_limit").Inc()
	}

	// Auth failures (407 with actual credential errors, not rate limits)
	if e.Status == 407 && !strings.Contains(e.Error, "rate limited") {
		m.authFailures.Inc()
	}

	// Duration
	if e.DurationMS > 0 {
		m.duration.WithLabelValues(e.Method).Observe(float64(e.DurationMS) / 1000.0)
	}

	// Throughput for non-tunnel requests (HTTP forwarding).
	// CONNECT tunnel bytes are tracked via ObserveLiveBytes.
	if e.Method != "CONNECT" {
		if e.BytesRead > 0 {
			m.bytesRead.Add(float64(e.BytesRead))
		}
		if e.BytesWritten > 0 {
			m.bytesWritten.Add(float64(e.BytesWritten))
		}
	}
}

// ObserveDNS records a DNS lookup result and duration.
// Result should be "success", "failure", or "blocked".
func (m *Metrics) ObserveDNS(d time.Duration, result string) {
	m.dnsDuration.Observe(d.Seconds())
	m.dnsLookups.WithLabelValues(result).Inc()
}
