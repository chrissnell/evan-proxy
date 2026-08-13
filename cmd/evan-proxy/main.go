package main

import (
	"context"
	"log"
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
	// When a dedicated metrics listener is configured, /metrics is served there
	// instead of on the public admin port.
	adminServer := admin.NewServer(adminAuth, collector, users, proxyHandler, m, logger, Version, cfg.MetricsListen == "")

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

	// Internal diagnostics listener — serves /metrics and the unauthenticated
	// pprof endpoints, kept off the public admin host. Bound to a private
	// address by default (127.0.0.1:9091); in k8s it binds inside the pod and is
	// reached only via a ClusterIP + NetworkPolicy.
	var metricsSrv *http.Server
	if cfg.MetricsListen != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", m.Handler())
		admin.RegisterPprof(metricsMux)
		metricsSrv = &http.Server{
			Addr:        cfg.MetricsListen,
			Handler:     metricsMux,
			ReadTimeout: 10 * time.Second,
			// No WriteTimeout: pprof CPU/trace profiles stream for 30s+ and would
			// be truncated. This listener is internal-only.
			IdleTimeout: 120 * time.Second,
		}
		go func() {
			logger.Infof("metrics", "listening on %s", cfg.MetricsListen)
			if err := metricsSrv.ListenAndServe(); err != http.ErrServerClosed {
				logger.Fatalf("metrics", "%v", err)
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
