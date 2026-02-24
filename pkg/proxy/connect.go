package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"evan-proxy/pkg/logging"
)

// handleConnect handles CONNECT requests with the iOS-compatible 407 flow.
// Hijacks the connection to write raw HTTP responses, keeping the TCP
// connection alive through the auth challenge-response cycle.
func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clientIP := clientAddr(r)
	host := r.Host

	// Per-user port: user is already identified by the listening port.
	// Hijack and tunnel directly — no auth challenge needed.
	if ctxUser := userFromCtx(r.Context()); ctxUser != "" {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		h.connectTunnel(conn, bufrw, r.Context(), start, clientIP, host, ctxUser)
		return
	}

	// Rate limit check
	if !h.limiter.Allow(clientIP) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nRetry-After: 60\r\nContent-Length: 0\r\n\r\n"))
		conn.Close()
		h.logger.Log(logging.Entry{
			Timestamp: start, ClientIP: clientIP, Method: "CONNECT",
			Host: host, Status: 407, Error: "rate limited",
			DurationMS: time.Since(start).Milliseconds(),
		})
		return
	}

	// Hijack the connection for raw I/O
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	// Check auth on initial request
	hadCredentials := r.Header.Get("Proxy-Authorization") != ""
	user, authErr := h.users.Check(r.Header.Get("Proxy-Authorization"))

	// If no credentials provided, check for a recent auth session from this IP.
	// iOS/macOS often send CONNECT without credentials for subresource requests
	// and don't retry after the 407 challenge.
	if authErr != nil && !hadCredentials {
		if sessionUser := h.checkAuthSession(clientIP); sessionUser != "" {
			user = sessionUser
			authErr = nil
		}
	}

	if authErr != nil {
		// Send 407 challenge — keep connection alive for iOS retry
		conn.Write([]byte(
			"HTTP/1.1 407 Proxy Authentication Required\r\n" +
				"Proxy-Authenticate: Basic realm=\"proxy\"\r\n" +
				"Proxy-Connection: keep-alive\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
		))

		// Wait for retry on the same connection
		conn.SetReadDeadline(time.Now().Add(h.cfg.AuthRetryTimeout))
		retry, err := http.ReadRequest(bufrw.Reader)
		if err != nil {
			if hadCredentials {
				h.limiter.RecordFailure(clientIP)
			}
			h.logger.Log(logging.Entry{
				Timestamp: start, ClientIP: clientIP, Method: "CONNECT",
				Host: host, Status: 407, Error: authErr.Error() + "; retry read failed",
				DurationMS: time.Since(start).Milliseconds(),
			})
			return
		}
		conn.SetReadDeadline(time.Time{}) // clear deadline

		host = retry.Host
		user, authErr = h.users.Check(retry.Header.Get("Proxy-Authorization"))
		if authErr != nil {
			h.limiter.RecordFailure(clientIP)
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"))
			h.logger.Log(logging.Entry{
				Timestamp: start, ClientIP: clientIP, Method: "CONNECT",
				Host: host, Status: 407, Error: authErr.Error(),
				DurationMS: time.Since(start).Milliseconds(),
			})
			return
		}
	}

	// Cache successful auth for this IP
	h.recordAuthSuccess(clientIP, user)

	h.connectTunnel(conn, bufrw, r.Context(), start, clientIP, host, user)
}

// connectTunnel establishes the CONNECT tunnel after authentication succeeds.
// Handles ACL check, DNS resolution, dialing, and bidirectional copy.
func (h *Handler) connectTunnel(conn net.Conn, bufrw *bufio.ReadWriter, baseCtx context.Context, start time.Time, clientIP, host, user string) {
	// Attach per-user DNS resolver to context
	ctx := h.ctxWithUserDNS(baseCtx, user)

	// ACL check
	if !h.acl.Allow(host) {
		conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
		h.logger.Log(logging.Entry{
			Timestamp: start, ClientIP: clientIP, Method: "CONNECT",
			Host: host, User: user, Status: 403, DurationMS: time.Since(start).Milliseconds(),
		})
		return
	}

	// Dial target
	targetConn, err := h.dial(ctx, "tcp", host)
	if err != nil {
		status := 502
		if errors.Is(err, ErrDNSBlocked) {
			status = 523 // non-standard: Origin Is Unreachable (DNS blocked)
		}
		event := ""
		if status == 523 {
			event = "dns-block"
		}
		conn.Write([]byte(fmt.Sprintf("HTTP/1.1 %d Bad Gateway\r\nContent-Length: 0\r\n\r\n", status)))
		h.logger.Log(logging.Entry{
			Timestamp: start, Event: event, ClientIP: clientIP, Method: "CONNECT",
			Host: host, User: user, Status: status, DurationMS: time.Since(start).Milliseconds(),
		})
		return
	}
	defer targetConn.Close()

	// Success — establish tunnel
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	h.logger.Log(logging.Entry{
		Timestamp: start, Event: "open", ClientIP: clientIP, Method: "CONNECT",
		Host: host, User: user, Status: 200,
	})

	// Bidirectional copy with live byte counting
	readCounter := h.counter.NewWriter(targetConn, true)
	writeCounter := h.counter.NewWriter(conn, false)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(readCounter, bufrw) // client -> target
		readCounter.Close()
		targetConn.(*net.TCPConn).CloseWrite()
	}()

	go func() {
		defer wg.Done()
		io.Copy(writeCounter, targetConn) // target -> client
		writeCounter.Close()
	}()

	wg.Wait()

	h.logger.Log(logging.Entry{
		Timestamp:    start,
		Event:        "close",
		ClientIP:     clientIP,
		Method:       "CONNECT",
		Host:         host,
		User:         user,
		Status:       200,
		DurationMS:   time.Since(start).Milliseconds(),
		BytesRead:    readCounter.Total(),
		BytesWritten: writeCounter.Total(),
	})
}
