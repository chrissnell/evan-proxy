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

	"golang.org/x/crypto/acme/autocert"
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

	m := metrics.New()
	logger.AddObserver(m.Observe)

	counter := stats.NewTrafficCounter(collector)
	counter.AddObserver(m.ObserveLiveBytes)
	proxyHandler := proxy.New(cfg, users, users, users, users, users, a, limiter, logger, counter, m)
	adminServer := admin.NewServer(adminAuth, collector, users, proxyHandler, m, logger, Version, cfg.ForceHTTPS)

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

	if cfg.AutocertHost != "" {
		// Terminate TLS in-process via Let's Encrypt (single-host deployments,
		// e.g. Raspberry Pi). No manual cert files needed.
		mgr := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.AutocertHost),
			Cache:      autocert.DirCache(cfg.AutocertDir),
		}
		adminSrv.TLSConfig = mgr.TLSConfig()
		// Serve HTTPS on the standard port so it matches the :80 ACME handler's
		// HTTP->HTTPS redirect (which targets :443) and what iOS/ATS expects.
		// Binding :443 needs root or CAP_NET_BIND_SERVICE; NAT/port-forward
		// setups can forward external 443 to this host instead.
		adminSrv.Addr = ":443"

		// :80 serves the ACME http-01 challenge and redirects everything else
		// to HTTPS.
		challengeSrv := &http.Server{Addr: ":80", Handler: mgr.HTTPHandler(nil)}
		go func() {
			if err := challengeSrv.ListenAndServe(); err != http.ErrServerClosed {
				logger.Fatalf("admin", "acme http: %v", err)
			}
		}()
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			challengeSrv.Shutdown(ctx)
		}()

		go func() {
			logger.Infof("admin", "listening with autocert TLS for %s on %s", cfg.AutocertHost, adminSrv.Addr)
			if err := adminSrv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				logger.Fatalf("admin", "tls: %v", err)
			}
		}()
	} else {
		go func() {
			logger.Infof("admin", "listening on %s", cfg.AdminListen)
			if err := adminSrv.ListenAndServe(); err != http.ErrServerClosed {
				logger.Fatalf("admin", "%v", err)
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
	counter.Stop()
	collector.Stop()
	limiter.Stop()
}
