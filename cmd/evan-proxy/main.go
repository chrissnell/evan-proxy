package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"evan-proxy/pkg/acl"
	"evan-proxy/pkg/admin"
	"evan-proxy/pkg/auth"
	"evan-proxy/pkg/config"
	"evan-proxy/pkg/logging"
	"evan-proxy/pkg/metrics"
	"evan-proxy/pkg/proxy"
	"evan-proxy/pkg/ratelimit"
	"evan-proxy/pkg/stats"
	"evan-proxy/pkg/userdb"
)

// Version is set at build time via -ldflags.
var Version = "dev"

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Build logger — console backend is always active
	backends := []logging.Backend{
		logging.NewConsoleBackend(os.Stdout, cfg.LogFormat),
	}

	// Network logging (independent of console)
	switch cfg.LogNetMode {
	case "json-udp":
		udp, err := logging.NewJSONUDPBackend(cfg.LogNetAddr)
		if err != nil {
			log.Fatalf("json-udp logger: %v", err)
		}
		backends = append(backends, udp)
	case "json-http":
		backends = append(backends, logging.NewJSONHTTPBackend(
			cfg.LogNetAddr, cfg.LogNetBatchSize, cfg.LogNetFlushInterval,
		))
	}

	logger := logging.New(backends...)
	defer logger.Close()

	users, err := userdb.Open(cfg.ProxyDBPath, logger)
	if err != nil {
		logger.Fatalf("userdb", "%v", err)
	}
	defer users.Close()

	adminAuth := auth.NewAdminAuth(cfg.AdminUser, cfg.AdminPassword)
	a := acl.AllowAll{}
	limiter := ratelimit.New(cfg.AuthFailRateLimit, cfg.AuthFailWindow)
	collector := stats.NewCollector()
	logger.AddObserver(collector.Observe)

	m := metrics.New(metrics.Options{UserLabel: cfg.MetricsUserLabel})
	logger.AddObserver(m.Observe)

	counter := stats.NewTrafficCounter(collector)
	counter.AddObserver(m.ObserveLiveBytes)
	proxyHandler := proxy.New(cfg, users, users, users, users, users, a, limiter, logger, counter, m)

	// Parse trusted-proxy CIDRs for admin login client-IP extraction. The
	// config layer already validated each entry, so ParseCIDR cannot fail here.
	var trustedProxies []*net.IPNet
	for _, cidr := range cfg.TrustedProxyCIDRs {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			trustedProxies = append(trustedProxies, n)
		}
	}
	// /metrics is mounted on the admin port only when no dedicated internal
	// metrics listener is configured.
	adminServer := admin.NewServer(adminAuth, collector, users, proxyHandler, m, logger, Version,
		admin.Options{
			LoginRateLimit: cfg.AdminLoginRateLimit,
			LoginWindow:    cfg.AdminLoginWindow,
			LoginGlobalMax: cfg.AdminLoginGlobalMax,
			TrustedProxies: trustedProxies,
		},
		cfg.MetricsListen == "")

	// Per-user dedicated port listeners
	if err := proxyHandler.StartUserListeners(); err != nil {
		logger.Fatalf("proxy", "user listeners: %v", err)
	}
	proxyHandler.StartReconciler(30 * time.Second)

	// Admin listener (no WriteTimeout -- SSE log streaming needs long-lived responses)
	adminSrv := &http.Server{
		Addr:        cfg.AdminListen,
		Handler:     adminServer,
		ReadTimeout: 10 * time.Second,
		IdleTimeout: 120 * time.Second,
	}

	go func() {
		logger.Infof("admin", "listening on %s", cfg.AdminListen)
		if err := adminSrv.ListenAndServe(); err != http.ErrServerClosed {
			logger.Fatalf("admin", "%v", err)
		}
	}()

	// Internal metrics listener — serves /metrics off the public admin host.
	// Bound to a private address by default (127.0.0.1:9091); in k8s it binds
	// inside the pod and is reached only via a ClusterIP + NetworkPolicy.
	var metricsSrv *http.Server
	if cfg.MetricsListen != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", m.Handler())
		metricsSrv = &http.Server{
			Addr:        cfg.MetricsListen,
			Handler:     metricsMux,
			ReadTimeout: 10 * time.Second,
			IdleTimeout: 120 * time.Second,
		}
		go func() {
			logger.Infof("metrics", "listening on %s", cfg.MetricsListen)
			if err := metricsSrv.ListenAndServe(); err != http.ErrServerClosed {
				logger.Fatalf("metrics", "%v", err)
			}
		}()
	}

	// Optional pprof profiling on a separate loopback listener (never the public
	// admin port, and off unless PPROF_ENABLED). Reach it via `kubectl port-forward`.
	if cfg.PProfEnabled {
		// Defense in depth: pprof is unauthenticated and leaks cmdline/heap
		// dumps, so a non-loopback bind re-exposes exactly what this listener
		// exists to keep off the public port. Warn loudly if so configured.
		if !isLoopbackListen(cfg.PProfListen) {
			logger.Errorf("pprof", "PPROF_LISTEN %q is not loopback — unauthenticated profiling endpoints will be network-reachable; bind to 127.0.0.1 and use kubectl port-forward", cfg.PProfListen)
		}
		pmux := http.NewServeMux()
		admin.RegisterPprof(pmux)
		go func() {
			logger.Infof("pprof", "listening on %s", cfg.PProfListen)
			if err := http.ListenAndServe(cfg.PProfListen, pmux); err != nil {
				logger.Errorf("pprof", "%v", err)
			}
		}()
	}

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	logger.Infof("main", "shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	proxyHandler.StopReconciler()
	proxyHandler.ShutdownUserListeners(ctx)
	proxyHandler.StopAuthCleanup()
	adminSrv.Shutdown(ctx)
	if metricsSrv != nil {
		metricsSrv.Shutdown(ctx)
	}
	counter.Stop()
	collector.Stop()
	limiter.Stop()
}

// isLoopbackListen reports whether a "host:port" listen address binds only the
// loopback interface. A literal loopback IP (127.0.0.0/8, ::1) or the "localhost"
// hostname qualifies; a bare/empty host, "0.0.0.0", "::", or any routable IP
// does not. On a parse failure it returns false so the caller warns rather than
// staying silent.
func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
