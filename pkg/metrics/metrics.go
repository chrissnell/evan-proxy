package metrics

import (
	"net/http"
	"strconv"
	"strings"

	"evan-proxy/pkg/logging"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	requests      *prometheus.CounterVec
	blocked       *prometheus.CounterVec
	duration      *prometheus.HistogramVec
	bytesRead     prometheus.Counter
	bytesWritten  prometheus.Counter
	activeTunnels prometheus.Gauge
	authFailures  prometheus.Counter
}

func New() *Metrics {
	m := &Metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "evanproxy_requests_total",
			Help: "Total proxy requests by method, status code, and user.",
		}, []string{"method", "status_code", "user"}),

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
	}

	prometheus.MustRegister(
		m.requests,
		m.blocked,
		m.duration,
		m.bytesRead,
		m.bytesWritten,
		m.activeTunnels,
		m.authFailures,
	)

	return m
}

// Handler returns the Prometheus HTTP handler for /metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.Handler()
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

	// Request counter
	user := e.User
	if user == "" {
		user = "anonymous"
	}
	m.requests.WithLabelValues(e.Method, strconv.Itoa(e.Status), user).Inc()

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

	// Throughput
	if e.BytesRead > 0 {
		m.bytesRead.Add(float64(e.BytesRead))
	}
	if e.BytesWritten > 0 {
		m.bytesWritten.Add(float64(e.BytesWritten))
	}
}
