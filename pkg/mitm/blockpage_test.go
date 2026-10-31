package mitm

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestRenderBlockPageContent(t *testing.T) {
	at := time.Date(2026, 3, 1, 15, 42, 0, 0, time.UTC)
	page := string(RenderBlockPage("example.com:443", at))

	for _, want := range []string{
		"Pancho says no.",
		"example.com",
		"is off-limits while your internet is paused.",
		"Paused at 3:42 PM",
		"data:image/jpeg;base64,",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("block page is missing %q:\n%s", want, page)
		}
	}

	// The :443 every CONNECT carries would read as noise next to the URL bar.
	if strings.Contains(page, "example.com:443") {
		t.Error("block page showed the port alongside the host")
	}

	// One response, no subresources: anything the page fetches would leave the
	// tunnel and need its own interception.
	if strings.Contains(page, "<script") {
		t.Error("block page contains script")
	}
	for _, scheme := range []string{`src="http`, `href="http`, `url(http`} {
		if strings.Contains(page, scheme) {
			t.Errorf("block page references an external resource (%s)", scheme)
		}
	}
}

func TestBlockPageEmbedsTheJPEG(t *testing.T) {
	page := string(RenderBlockPage("example.com", time.Now()))

	m := regexp.MustCompile(`data:image/jpeg;base64,([A-Za-z0-9+/=]+)`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no JPEG data URI in the block page")
	}
	decoded, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		t.Fatalf("data URI is not valid base64: %v", err)
	}
	if !bytes.Equal(decoded, panchoJPEG) {
		t.Error("data URI does not carry the embedded asset")
	}
	if !bytes.HasPrefix(decoded, []byte{0xff, 0xd8, 0xff}) {
		t.Error("embedded asset is not a JPEG")
	}
}

func TestBlockPageEscapesTheHost(t *testing.T) {
	// The host comes off the wire. html/template escapes it, but assert it so a
	// future switch to text/template or string concatenation fails loudly.
	page := string(RenderBlockPage("<script>alert(1)</script>", time.Now()))
	if strings.Contains(page, "<script>alert(1)</script>") {
		t.Fatalf("host was not escaped:\n%s", page)
	}
}

func TestBlockPageResponseShape(t *testing.T) {
	at := time.Date(2026, 3, 1, 15, 42, 0, 0, time.UTC)
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)

	resp := newBlockPageResponse(req, "example.com", at, true)
	var buf bytes.Buffer
	if err := resp.Write(&buf); err != nil {
		t.Fatal(err)
	}

	got, err := http.ReadResponse(bufio.NewReader(&buf), req)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()

	// 200, not 403: Safari renders a 200 body but replaces an error status with
	// its own chrome — which is the "proxy failed, go DIRECT" signal.
	if got.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", got.StatusCode)
	}
	if ct := got.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := got.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if got.Close {
		t.Error("keep-alive response was marked Close")
	}
	if n := len(got.Header.Values("Connection")); n > 1 {
		t.Errorf("Connection header appears %d times", n)
	}

	body, _ := io.ReadAll(got.Body)
	if int64(len(body)) != got.ContentLength {
		t.Errorf("body is %d bytes, Content-Length says %d", len(body), got.ContentLength)
	}
	if !bytes.Equal(body, RenderBlockPage("example.com", at)) {
		t.Error("response body is not the rendered block page")
	}
}

func TestBlockPageHeadHasNoBody(t *testing.T) {
	req, _ := http.NewRequest(http.MethodHead, "https://example.com/", nil)
	resp := newBlockPageResponse(req, "example.com", time.Now(), false)

	var buf bytes.Buffer
	if err := resp.Write(&buf); err != nil {
		t.Fatal(err)
	}
	got, err := http.ReadResponse(bufio.NewReader(&buf), req)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()

	body, _ := io.ReadAll(got.Body)
	if len(body) != 0 {
		t.Errorf("HEAD response carried %d body bytes", len(body))
	}
	if got.ContentLength != int64(len(RenderBlockPage("example.com", time.Now()))) {
		t.Errorf("HEAD Content-Length = %d, want the full page length", got.ContentLength)
	}
	if !got.Close {
		t.Error("non-keep-alive response was not marked Close")
	}
}
