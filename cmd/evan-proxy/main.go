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

	users, err := userdb.Open(cfg.ProxyDBPath, cfg.ProxyUsersFile, logger)
	if err != nil {
		logger.Fatalf("userdb", "%v", err)
	}
	defer users.Close()

	adminAuth := auth.NewAdminAuth(cfg.AdminUser, cfg.AdminPassword)
	a := acl.AllowAll{}
	limiter := ratelimit.New(cfg.AuthFailRateLimit, cfg.AuthFailWindow)
	collector := stats.NewCollector()
	logger.AddObserver(collector.Observe)

	m := metrics.New()
	logger.AddObserver(m.Observe)

	counter := stats.NewTrafficCounter(collector)
	counter.AddObserver(m.ObserveLiveBytes)
	proxyHandler := proxy.New(cfg, users, users, users, users, a, limiter, logger, counter, m)
	adminServer, err := admin.NewServer(adminAuth, collector, users, proxyHandler, m, cfg.ProxyDBPath, logger)
	if err != nil {
		logger.Fatalf("admin", "%v", err)
	}

	// Per-user dedicated port listeners
	if err := proxyHandler.StartUserListeners(); err != nil {
		logger.Fatalf("proxy", "user listeners: %v", err)
	}

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

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	logger.Infof("main", "shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	proxyHandler.ShutdownUserListeners(ctx)
	proxyHandler.StopAuthCleanup()
	adminSrv.Shutdown(ctx)
	counter.Stop()
	collector.Stop()
	limiter.Stop()
}
