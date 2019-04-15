package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi"
)

var (
	addrFlag      = flag.String("addr", ":8080", "address to bind the web server to")
	directFlag    = flag.String("direct", "echo:8081", "address to the echo server")
	envoyMTLSFlag = flag.String("envoy-to-envoy-mtls", "localhost:8001", "address to the envoy-to-envoy mTLS endpoint")
	envoyTLSFlag  = flag.String("envoy-to-envoy-tls", "localhost:8002", "address to the envoy-to-envoy TLS endpoint")
	logFlag       = flag.String("log", "", "path to log to (empty=stderr)")

	pageHTML = template.Must(template.New("").Parse(`<html>
<head>
	<link rel="stylesheet" href="/styles.css">
</head>
<body>
	<div class="button-grid-container">
		<div class="grid-item">
			<button onclick="location.assign('/?route=direct');">Direct</button>
		</div>
		<div class="grid-item">
			<button onclick="location.assign('/?route=envoy-to-envoy-mtls');">Envoy &#8594; Envoy (mTLS) </button>
		</div>
		<div class="grid-item">
			<button onclick="location.assign('/?route=envoy-to-envoy-tls');">Envoy &#8594; Envoy (TLS) </button>
		</div>
	</div>
	<br/>
{{- if .WebHeader }}
	<br/>
	<div class="card" id="success">
		<div class="container">
			<h2 class="header-title">Headers Sent by Web Server</h2>
			<div class="header-grid-container">
{{- range $k, $v := .WebHeader }}
				<div class="grid-item">
					<div class="header-key">{{ printf "%-30s: " $k }}</div>
				</div>
				<div class="grid-item">
					<div class="header-value">{{- range $i, $v := $v }}{{ if $i }},{{ end }}{{ $v }}{{ end }}</div>
				</div>
{{- end }}
			</div>
		</div>
		<br/>
	</div>
{{- end }}

{{- if .EchoHeader }}
	<br/>
	<div class="card" id="success">
		<div class="container">
			<h2 class="header-title">Headers Received by Echo Server</h2>
			<div class="header-grid-container">
{{- range $k, $v := .EchoHeader }}
				<div class="grid-item">
					<div class="header-key">{{ printf "%-30s: " $k }}</div>
				</div>
				<div class="grid-item">
					<div class="header-value">{{- range $i, $v := $v }}{{ if $i }},{{ end }}{{ $v }}{{ end }}</div>
				</div>
{{- end }}
			</div>
		</div>
		<br/>
	</div>
{{- end }}

{{- if .Error }}
	<br/>
	<div class="card" id="error">
		<div class="container">
			<h2>Error:</h2>
			<div class="error-text">{{ .Error }}</div>
		</div>
		<br/>
	</div>
{{- end }}
{{- if .Attempt }}
	<div class="footer">Attempt: {{ .Attempt }}</div>
{{- end }}
</body>
</html>
`))
	attempt int32 = 0
)

func serveRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	var host string
	route := r.URL.Query().Get("route")
	switch route {
	case "":
		pageHTML.Execute(w, successParams(0, nil, nil))
		return
	case "direct":
		host = *directFlag
	case "envoy-to-envoy-mtls":
		host = *envoyMTLSFlag
	case "envoy-to-envoy-tls":
		host = *envoyTLSFlag
	default:
		pageHTML.Execute(w, errorParams(attempt, nil, "invalid route value %q", route))
		return
	}

	echoURL := fmt.Sprintf("http://%s", host)

	atomic.AddInt32(&attempt, 1)
	w.Header().Set("Content-Type", "text/html")

	req, err := http.NewRequest("GET", echoURL, nil)
	if err != nil {
		log.Printf("[%s] failed to create request for echo server %q: %v", r.RemoteAddr, route, err)
		pageHTML.Execute(w, errorParams(attempt, nil, "failed to create request: %v", err))
		return
	}
	req.Header.Set("Date", httpDate(time.Now()))
	req.Header.Set("User-Agent", "")
	req.Header.Set("X-Super-Secret-Password", "hunter2")

	log.Printf("[%s] Issuing GET %s", r.RemoteAddr, echoURL)
	resp, err := http.DefaultClient.Do(req)
	req.Header.Del("User-Agent")
	if err != nil {
		log.Printf("[%s] failed to send request to echo server %q: %v", r.RemoteAddr, route, err)
		pageHTML.Execute(w, errorParams(attempt, req.Header, "failed to contact echo server: %v", err))
		return
	}
	defer resp.Body.Close()
	log.Printf("[%s] GOT %s", r.RemoteAddr, echoURL)

	if resp.StatusCode != http.StatusOK {
		body := tryRead(resp.Body)
		log.Printf("[%s] unexpected echo server %q response: %d\n%s", r.RemoteAddr, route, resp.StatusCode, body)
		pageHTML.Execute(w, errorParams(attempt, req.Header, "unexpected echo server response status: %d\n\n%s", resp.StatusCode, body))
		return
	}

	var header http.Header
	if err := json.NewDecoder(resp.Body).Decode(&header); err != nil {
		log.Printf("[%s] failed to parse echo server %q response: %v", r.RemoteAddr, route, err)
		pageHTML.Execute(w, errorParams(attempt, req.Header, "failed to parse echo server response: %v", err))
		return
	}

	header.Del("Accept-Encoding")

	log.Printf("[%s] echo server %q response OK", r.RemoteAddr, route)
	pageHTML.Execute(w, successParams(attempt, req.Header, header))
}

func successParams(attempt int32, webHeader, echoHeader http.Header) map[string]interface{} {
	return map[string]interface{}{
		"Attempt":    attempt,
		"WebHeader":  webHeader,
		"EchoHeader": echoHeader,
	}
}

func errorParams(attempt int32, webHeader http.Header, format string, args ...interface{}) map[string]interface{} {
	return map[string]interface{}{
		"Attempt":   attempt,
		"WebHeader": webHeader,
		"Error":     fmt.Sprintf(format, args...),
	}
}

func tryRead(r io.Reader) string {
	b := make([]byte, 1024)
	n, _ := r.Read(b)
	return string(b[:n])
}

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) (err error) {
	flag.Parse()
	log.SetPrefix("web> ")
	log.SetFlags(log.Ltime)
	if *logFlag != "" {
		logFile, err := os.OpenFile(*logFlag, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("unable to open log file: %v", err)
		}
		defer logFile.Close()
		log.SetOutput(logFile)
	} else {
		log.SetOutput(os.Stdout)
	}
	log.Printf("starting web server...")

	ln, err := net.Listen("tcp", *addrFlag)
	if err != nil {
		return fmt.Errorf("unable to listen: %v", err)
	}
	defer ln.Close()

	r := chi.NewRouter()
	r.Use(noCache)
	r.Get("/styles.css", http.HandlerFunc(serveCSS))
	r.Get("/", http.HandlerFunc(serveRoot))

	log.Printf("listening on %s...", ln.Addr())
	server := &http.Server{
		Handler: r,
	}
	return server.Serve(ln)
}

func noCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Expires", "0")
		h.ServeHTTP(w, r)
	})
}

func httpDate(t time.Time) string {
	return t.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
}
