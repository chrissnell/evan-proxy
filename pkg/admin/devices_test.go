package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"evan-proxy/pkg/userdb"
)

// sessionRequest builds a request carrying a valid admin session cookie.
func sessionRequest(a *api, method, target string, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: a.sessions.Create()})
	return r
}

func TestEnroll_RequiresAuth(t *testing.T) {
	a := setupAPI(t)
	w := httptest.NewRecorder()
	a.requireAdminSession(a.handleEnroll)(w, httptest.NewRequest(http.MethodPost, "/api/devices/enroll", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated enroll: want 401, got %d", w.Code)
	}
}

// A device bearer token must not manage devices: a leaked token could
// otherwise enroll a replacement for itself or revoke other devices.
func TestDeviceManagement_RejectsBearerToken(t *testing.T) {
	a := setupAPI(t)
	tok, _, err := a.users.CreateDeviceToken("phone")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		method, target string
		h              http.HandlerFunc
	}{
		{http.MethodPost, "/api/devices/enroll", a.handleEnroll},
		{http.MethodGet, "/api/devices", a.handleDevices},
		{http.MethodDelete, "/api/devices?id=x", a.handleDevices},
	} {
		req := httptest.NewRequest(tc.method, tc.target, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		a.requireAdminSession(tc.h)(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s with bearer: want 401, got %d", tc.method, tc.target, w.Code)
		}
	}
}

func TestEnrollPairAndBearerAuth(t *testing.T) {
	a := setupAPI(t)

	// Admin creates an enrollment code.
	w := httptest.NewRecorder()
	a.requireAdminSession(a.handleEnroll)(w, sessionRequest(a, http.MethodPost, "/api/devices/enroll", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("enroll: want 200, got %d", w.Code)
	}
	var enr struct {
		Code      string `json:"code"`
		PairURL   string `json:"pair_url"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.NewDecoder(w.Body).Decode(&enr); err != nil {
		t.Fatal(err)
	}
	if enr.Code == "" || enr.ExpiresIn <= 0 {
		t.Fatalf("incomplete enroll response: %+v", enr)
	}
	if !strings.HasPrefix(enr.PairURL, "evanproxy://pair?") || !strings.Contains(enr.PairURL, "code="+enr.Code) {
		t.Fatalf("bad pair_url: %q", enr.PairURL)
	}
	// httptest requests are plain http, so the link must say so.
	if !strings.Contains(enr.PairURL, "scheme=http&") {
		t.Fatalf("pair_url missing http scheme: %q", enr.PairURL)
	}

	// The device redeems the code for a bearer token — no session.
	w = httptest.NewRecorder()
	a.handlePair(w, httptest.NewRequest(http.MethodPost, "/api/pair",
		strings.NewReader(`{"code":"`+enr.Code+`","device_name":"Chris's iPhone"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("pair: want 200, got %d", w.Code)
	}
	var pair struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&pair); err != nil {
		t.Fatal(err)
	}
	if pair.Token == "" {
		t.Fatal("empty token")
	}

	// The code is single-use.
	w = httptest.NewRecorder()
	a.handlePair(w, httptest.NewRequest(http.MethodPost, "/api/pair",
		strings.NewReader(`{"code":"`+enr.Code+`"}`)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code reuse: want 401, got %d", w.Code)
	}

	// The bearer token authenticates a protected endpoint without a cookie.
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+pair.Token)
	w = httptest.NewRecorder()
	a.requireSession(a.handleUsers)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("bearer /api/users: want 200, got %d", w.Code)
	}

	// The device shows up in the list.
	w = httptest.NewRecorder()
	a.requireAdminSession(a.handleDevices)(w, sessionRequest(a, http.MethodGet, "/api/devices", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("list devices: want 200, got %d", w.Code)
	}
	var devices []userdb.DeviceToken
	if err := json.NewDecoder(w.Body).Decode(&devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Name != "Chris's iPhone" {
		t.Fatalf("unexpected device list: %+v", devices)
	}

	// Revoking the device kills the bearer token.
	w = httptest.NewRecorder()
	a.requireAdminSession(a.handleDevices)(w, sessionRequest(a, http.MethodDelete, "/api/devices?id="+devices[0].ID, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("revoke: want 200, got %d", w.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+pair.Token)
	w = httptest.NewRecorder()
	a.requireSession(a.handleUsers)(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked bearer: want 401, got %d", w.Code)
	}
}

func TestPair_BadCode(t *testing.T) {
	a := setupAPI(t)
	w := httptest.NewRecorder()
	a.handlePair(w, httptest.NewRequest(http.MethodPost, "/api/pair", strings.NewReader(`{"code":"bogus"}`)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad code: want 401, got %d", w.Code)
	}
}

func TestRevokeDevice_Unknown(t *testing.T) {
	a := setupAPI(t)
	w := httptest.NewRecorder()
	a.requireAdminSession(a.handleDevices)(w, sessionRequest(a, http.MethodDelete, "/api/devices?id=nope", ""))
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown device: want 404, got %d", w.Code)
	}
}

func TestEnrollQR(t *testing.T) {
	a := setupAPI(t)

	w := httptest.NewRecorder()
	a.requireAdminSession(a.handleEnroll)(w, sessionRequest(a, http.MethodPost, "/api/devices/enroll", ""))
	var enr struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(w.Body).Decode(&enr); err != nil {
		t.Fatal(err)
	}

	w = httptest.NewRecorder()
	a.requireAdminSession(a.handleEnroll)(w, sessionRequest(a, http.MethodGet, "/api/devices/enroll?code="+enr.Code, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("QR: want 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/svg+xml" {
		t.Fatalf("QR content type: %q", ct)
	}
	if !strings.Contains(w.Body.String(), "<svg") {
		t.Fatal("QR body is not SVG")
	}

	// An unknown code must not render a QR.
	w = httptest.NewRecorder()
	a.requireAdminSession(a.handleEnroll)(w, sessionRequest(a, http.MethodGet, "/api/devices/enroll?code=bogus", ""))
	if w.Code != http.StatusNotFound {
		t.Fatalf("bogus QR code: want 404, got %d", w.Code)
	}
}

func TestRequestScheme(t *testing.T) {
	plain := httptest.NewRequest(http.MethodGet, "/api/devices/enroll", nil)
	if got := requestScheme(plain); got != "http" {
		t.Fatalf("plain request: want http, got %q", got)
	}
	tls := httptest.NewRequest(http.MethodGet, "https://x/api/devices/enroll", nil)
	if got := requestScheme(tls); got != "https" {
		t.Fatalf("TLS request: want https, got %q", got)
	}
	fwd := httptest.NewRequest(http.MethodGet, "/api/devices/enroll", nil)
	fwd.Header.Set("X-Forwarded-Proto", "https")
	if got := requestScheme(fwd); got != "https" {
		t.Fatalf("forwarded request: want https, got %q", got)
	}
}

func TestPairURL_EscapesAndCarriesScheme(t *testing.T) {
	got := pairURL("http", "192.168.1.5:8080", "ab/cd")
	want := "evanproxy://pair?scheme=http&host=192.168.1.5%3A8080&code=ab%2Fcd"
	if got != want {
		t.Fatalf("pairURL:\n got %q\nwant %q", got, want)
	}
}
