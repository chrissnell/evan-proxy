package proxy

import (
	"embed"
	"net/http"
)

//go:embed static/disabled.html
var disabledFS embed.FS

func serveDisabled(w http.ResponseWriter, r *http.Request) {
	data, err := disabledFS.ReadFile("static/disabled.html")
	if err != nil {
		http.Error(w, "proxy is disabled", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write(data)
}
