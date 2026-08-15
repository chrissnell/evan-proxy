package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"evan-proxy/pkg/userdb"

	qrcode "github.com/skip2/go-qrcode"
)

// pairURL builds the evanproxy://pair deep link a device scans to enroll.
// The scheme rides along so devices can reach plain-http servers; the app
// treats a missing scheme as https.
func pairURL(scheme, host, code string) string {
	return "evanproxy://pair?scheme=" + url.QueryEscape(scheme) +
		"&host=" + url.QueryEscape(host) + "&code=" + url.QueryEscape(code)
}

// requestScheme reports how the admin request arrived, honoring a TLS
// terminator's X-Forwarded-Proto. The device must pair over the same scheme
// the admin panel is served on.
func requestScheme(r *http.Request) string {
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		return "https"
	}
	return "http"
}

// handleEnroll manages device enrollment codes (admin session required).
// POST mints a single-use code and returns it with the pair deep link;
// GET ?code= renders that code's deep link as an SVG QR for the admin UI.
func (a *api) handleEnroll(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		code := a.enroll.create()
		// In demo mode the code never expires and is reusable; signal that to
		// the UI (persistent=true, expires_in=0) so it keeps the QR on screen.
		expiresIn := int(a.enroll.ttl.Seconds())
		if a.enroll.persistent {
			expiresIn = 0
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"code":       code,
			"pair_url":   pairURL(requestScheme(r), r.Host, code),
			"expires_in": expiresIn,
			"persistent": a.enroll.persistent,
		})
	case http.MethodGet:
		code := r.URL.Query().Get("code")
		if code == "" || !a.enroll.peek(code) {
			http.Error(w, "unknown or expired code", http.StatusNotFound)
			return
		}
		svg, err := qrSVG(pairURL(requestScheme(r), r.Host, code))
		if err != nil {
			a.logger.Errorf("admin", "render enroll QR: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(svg)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type pairRequest struct {
	Code       string `json:"code"`
	DeviceName string `json:"device_name"`
}

// handlePair redeems a single-use enrollment code for a long-lived bearer
// token. No session — the code is the credential, and it redeems at most once.
func (a *api) handlePair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req pairRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if req.Code == "" || !a.enroll.consume(req.Code) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	name := req.DeviceName
	if name == "" {
		name = "device"
	}
	if r := []rune(name); len(r) > 64 {
		name = string(r[:64])
	}
	token, id, err := a.users.CreateDeviceToken(name)
	if err != nil {
		a.logger.Errorf("admin", "create device token: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.logger.Infof("admin", "paired device %q (%s)", name, id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// handleDevices lists (GET) and revokes (DELETE ?id=) paired devices.
func (a *api) handleDevices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		devices, err := a.users.ListDeviceTokens()
		if err != nil {
			a.logger.Errorf("admin", "list devices: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if devices == nil {
			devices = []userdb.DeviceToken{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(devices)
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		if err := a.users.RevokeDeviceToken(id); err != nil {
			if errors.Is(err, userdb.ErrUnknownDevice) {
				http.Error(w, "device not found", http.StatusNotFound)
				return
			}
			a.logger.Errorf("admin", "revoke device: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// qrSVG renders content as a QR code in a scalable SVG (one path, unit modules).
func qrSVG(content string) ([]byte, error) {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return nil, err
	}
	bm := q.Bitmap() // includes the quiet-zone border
	n := len(bm)

	var b strings.Builder
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ` +
		strconv.Itoa(n) + ` ` + strconv.Itoa(n) + `" shape-rendering="crispEdges">`)
	b.WriteString(`<rect width="100%" height="100%" fill="#ffffff"/>`)
	b.WriteString(`<path fill="#000000" d="`)
	for y, row := range bm {
		for x, on := range row {
			if on {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x, y)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return []byte(b.String()), nil
}
