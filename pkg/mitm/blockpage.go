package mitm

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"
)

//go:embed assets/pancho.jpg
var panchoJPEG []byte

// panchoDataURI inlines the photo so the block page is exactly one response.
// A subresource request would leave the tunnel and defeat the whole point.
var panchoDataURI = "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(panchoJPEG)

// panchoPlaceholder is substituted with panchoDataURI before the template is
// parsed, so the data URI arrives as template *literal* text. Passing it as an
// action value instead would get HTML-escaped in attribute context, turning
// every base64 "+" into "&#43;" — legal, decoded correctly by browsers, and
// 700 bytes of noise in a page meant to be read by a human debugging it.
const panchoPlaceholder = "__PANCHO_DATA_URI__"

// blockPageHTML is deliberately self-contained: no JavaScript, no external
// stylesheet, no favicon fetch. Served over a forged certificate for the
// destination host, so anything it reaches for would be a second interception.
const blockPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pancho says no</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cg fill='%235c3a1e'%3E%3Cellipse cx='16' cy='22' rx='9' ry='7'/%3E%3Cellipse cx='6' cy='14' rx='4' ry='5'/%3E%3Cellipse cx='12' cy='8' rx='4' ry='5'/%3E%3Cellipse cx='20' cy='8' rx='4' ry='5'/%3E%3Cellipse cx='26' cy='14' rx='4' ry='5'/%3E%3C/g%3E%3C/svg%3E">
<style>
  html { -webkit-text-size-adjust: 100%; }
  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #faf5ec;
    color: #5c3a1e;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    text-align: center;
  }
  main { padding: 2rem 1.5rem 3rem; max-width: 30rem; }
  img { width: 100%; max-width: 20rem; height: auto; border-radius: 1rem; }
  h1 { margin: 1.75rem 0 1rem; font-size: 2rem; font-weight: 600; letter-spacing: -0.01em; }
  p { margin: 0; font-size: 1.125rem; line-height: 1.6; }
  .host { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all; }
  .paused { margin-top: 2rem; font-size: 0.9375rem; opacity: 0.65; }
</style>
</head>
<body>
<main>
  <img src="__PANCHO_DATA_URI__" alt="Pancho, tilting his head">
  <h1>Pancho says no.</h1>
  <p><span class="host">{{ .Host }}</span> is off-limits while your internet is paused.</p>
  <p class="paused">Paused at {{ .PausedAt }}</p>
</main>
</body>
</html>
`

var blockPageTmpl = template.Must(template.New("blockpage").Parse(
	strings.Replace(blockPageHTML, panchoPlaceholder, panchoDataURI, 1),
))

type blockPageData struct {
	Host     string
	PausedAt string
}

// RenderBlockPage returns the full HTML body for a block of host at time at.
func RenderBlockPage(host string, at time.Time) []byte {
	var buf strings.Builder
	data := blockPageData{
		Host:     displayHost(host),
		PausedAt: at.Format("3:04 PM"),
	}
	// The template is a compile-time constant with only string fields, so
	// execution cannot fail.
	_ = blockPageTmpl.Execute(&buf, data)
	return []byte(buf.String())
}

// displayHost strips the :443 that every CONNECT target carries, since showing
// it next to the URL bar would just read as noise.
func displayHost(host string) string {
	if h := normalizeHost(host); h != "" {
		return h
	}
	return host
}

// newBlockPageResponse builds the HTTP response for req.
//
// Status is 200, not 403: Safari renders a 200 body, but replaces an error
// status with its own chrome — and its own chrome is exactly the "the proxy
// failed, retry DIRECT" signal this package exists to avoid.
func newBlockPageResponse(req *http.Request, host string, at time.Time, keepAlive bool) *http.Response {
	body := RenderBlockPage(host, at)

	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		ContentLength: int64(len(body)),
		// Response.Write emits the Connection header from this field; setting
		// it in Header too would duplicate it.
		Close:   !keepAlive,
		Request: req,
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Set("Cache-Control", "no-store")

	if req != nil && req.Method == http.MethodHead {
		resp.Body = http.NoBody
	} else {
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	return resp
}
