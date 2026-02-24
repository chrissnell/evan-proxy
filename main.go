package main

import (
	"context"
	"crypto/tls"
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

	users, err := userdb.Open(cfg.ProxyDBPath, cfg.ProxyUsersFile)
	if err != nil {
		log.Fatalf("userdb: %v", err)
	}
	defer users.Close()

	adminAuth := auth.NewAdminAuth(cfg.AdminUser, cfg.AdminPassword)
	a := acl.AllowAll{}
	limiter := ratelimit.New(cfg.AuthFailRateLimit, cfg.AuthFailWindow)
	logger := logging.New(os.Stdout, cfg.LogFormat)
	collector := stats.NewCollector()
	logger.AddObserver(collector.Observe)
	state := admin.NewProxyState()

	m := metrics.New()
	logger.AddObserver(m.Observe)

	counter := stats.NewTrafficCounter(collector)
	counter.AddObserver(m.ObserveLiveBytes)
	proxyHandler := proxy.New(cfg, users, users, users, a, limiter, logger, counter, state)
	adminServer := admin.NewServer(adminAuth, state, collector, users, proxyHandler, m)

	// Per-user dedicated port listeners
	if err := proxyHandler.StartUserListeners(); err != nil {
		log.Fatalf("user listeners: %v", err)
	}

	// Plain proxy listener
	plainSrv := &http.Server{
		Addr:        cfg.ListenPlain,
		Handler:     proxyHandler,
		IdleTimeout: cfg.IdleTimeout,
	}

	// Admin listener (no WriteTimeout -- SSE log streaming needs long-lived responses)
	adminSrv := &http.Server{
		Addr:        cfg.AdminListen,
		Handler:     adminServer,
		ReadTimeout: 10 * time.Second,
		IdleTimeout: 120 * time.Second,
	}

	// Start servers
	go func() {
		log.Printf("proxy (plain) listening on %s", cfg.ListenPlain)
		if err := plainSrv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("plain proxy: %v", err)
		}
	}()

	// TLS proxy listener (if configured)
	var tlsSrv *http.Server
	if cfg.TLSCert != "" {
		tlsSrv = &http.Server{
			Addr:        cfg.ListenTLS,
			Handler:     proxyHandler,
			IdleTimeout: cfg.IdleTimeout,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
		go func() {
			log.Printf("proxy (TLS) listening on %s", cfg.ListenTLS)
			if err := tlsSrv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != http.ErrServerClosed {
				log.Fatalf("TLS proxy: %v", err)
			}
		}()
	}

	go func() {
		log.Printf("admin listening on %s", cfg.AdminListen)
		if err := adminSrv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("admin: %v", err)
		}
	}()

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	proxyHandler.ShutdownUserListeners(ctx)
	plainSrv.Shutdown(ctx)
	if tlsSrv != nil {
		tlsSrv.Shutdown(ctx)
	}
	adminSrv.Shutdown(ctx)
	counter.Stop()
	collector.Stop()
	limiter.Stop()
}
