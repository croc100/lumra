package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/croc100/lumra/internal/engine"
	"github.com/croc100/lumra/internal/evidence"
	"github.com/croc100/lumra/internal/live"
	"github.com/croc100/lumra/internal/probe"
	"github.com/croc100/lumra/internal/report"
	"github.com/croc100/lumra/internal/verdict"
	"github.com/croc100/lumra/internal/watch"
)

// maxTimeline caps the events kept per watched target so a long-running monitor
// can't grow memory without bound. Only state *changes* are recorded, so this is
// generous in practice.
const maxTimeline = 500

// watchState is one continuously-monitored target: its poll interval, when it
// started, the latest observed verdict, and the timeline of state changes.
type watchState struct {
	Target   string        `json:"target"`
	Interval string        `json:"interval"`
	Since    time.Time     `json:"since"`
	Current  verdict.Type  `json:"current"`
	Nature   string        `json:"nature"`
	Events   []watch.Event `json:"events"`
	cancel   context.CancelFunc
}

// watchManager owns all running monitors. Each target runs in its own goroutine
// that appends to the shared timeline under the manager lock.
type watchManager struct {
	mu     sync.Mutex
	m      map[string]*watchState
	parent context.Context
}

func newWatchManager(ctx context.Context) *watchManager {
	return &watchManager{m: map[string]*watchState{}, parent: ctx}
}

// start begins monitoring target every interval. It is a no-op if the target is
// already watched, so the same target can't spawn duplicate monitors.
func (wm *watchManager) start(target string, interval time.Duration) {
	wm.mu.Lock()
	if _, ok := wm.m[target]; ok {
		wm.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(wm.parent)
	st := &watchState{
		Target:   target,
		Interval: interval.String(),
		Since:    time.Now(),
		Current:  verdict.Inconclusive,
		Nature:   string(verdict.NatureUnknown),
		cancel:   cancel,
	}
	wm.m[target] = st
	wm.mu.Unlock()

	mon := watch.New(target, func(c context.Context, t string) *verdict.Verdict {
		// Bound each poll so a hung probe can't stall the monitor loop.
		dctx, dcancel := context.WithTimeout(c, 20*time.Second)
		defer dcancel()
		return engine.Diagnose(dctx, t)
	})
	go mon.Run(ctx, interval, func(e watch.Event) {
		wm.mu.Lock()
		defer wm.mu.Unlock()
		s, ok := wm.m[target]
		if !ok {
			return // stopped while a poll was in flight
		}
		s.Current = e.Type
		if e.Verdict != nil {
			s.Nature = string(e.Verdict.Nature)
		}
		s.Events = append(s.Events, e)
		if len(s.Events) > maxTimeline {
			s.Events = s.Events[len(s.Events)-maxTimeline:]
		}
	})
}

// stop cancels the monitor for target and forgets its timeline.
func (wm *watchManager) stop(target string) {
	wm.mu.Lock()
	s, ok := wm.m[target]
	if ok {
		delete(wm.m, target)
	}
	wm.mu.Unlock()
	if ok {
		s.cancel()
	}
}

// list returns a snapshot of every watched target, newest-started first, with a
// deep copy of each timeline so callers can marshal it without holding the lock.
func (wm *watchManager) list() []watchState {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	out := make([]watchState, 0, len(wm.m))
	for _, s := range wm.m {
		ev := make([]watch.Event, len(s.Events))
		copy(ev, s.Events)
		out = append(out, watchState{
			Target:   s.Target,
			Interval: s.Interval,
			Since:    s.Since,
			Current:  s.Current,
			Nature:   s.Nature,
			Events:   ev,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Since.After(out[j].Since) })
	return out
}

//go:embed webui/index.html
var webUI embed.FS

// flowView is the JSON shape the local cockpit UI consumes. It flattens a
// live.Flow plus its computed Nature and passive-vs-deep verdict into the fields
// the dashboard renders, so the frontend never re-derives classification logic.
type flowView struct {
	Domain     string    `json:"domain"`
	Nature     string    `json:"nature"`
	Verdict    string    `json:"verdict"` // authoritative deep type once analyzed, else ""
	Cause      string    `json:"cause,omitempty"`
	Confidence string    `json:"confidence,omitempty"`
	Attribution string   `json:"attribution,omitempty"`
	Authority  string    `json:"authority,omitempty"`
	Analyzed   bool      `json:"analyzed"`
	Hits       int       `json:"hits"`
	Resets     int       `json:"resets"`
	Version    uint16    `json:"version"`
	Handshake  bool      `json:"handshake"`
	LastSeen   time.Time `json:"last_seen"`
}

// observation is one thing the browser extension saw for a domain. Event is the
// browser-side lifecycle marker; Error carries the Chrome net error string when
// Event is "error", from which we infer the interference kind.
type observation struct {
	Domain string `json:"domain"`
	Event  string `json:"event"` // "request" | "response" | "error"
	Error  string `json:"error,omitempty"`
}

// toEvent maps a browser observation onto the same wire event the passive tap
// emits, so extension-sourced traffic is indistinguishable to the tracker. It
// returns ok=false for observations that carry no useful signal.
func (o observation) toEvent(now time.Time) (live.Event, bool) {
	if o.Domain == "" {
		return live.Event{}, false
	}
	e := live.Event{Domain: o.Domain, At: now}
	switch o.Event {
	case "request":
		e.Kind = live.ClientHello // a domain is being reached
	case "response":
		e.Kind = live.ServerHello // the session got established (reads clear)
	case "error":
		switch {
		case strings.Contains(o.Error, "CERT"):
			// Browser rejected the chain — the passive MITM signal.
			e.Kind = live.Cert
			e.Untrusted = true
			e.Subject = o.Domain
		case strings.Contains(o.Error, "NAME_NOT_RESOLVED"):
			e.Kind = live.DNS
			e.Suspicious = true
			e.Reason = "name did not resolve in the browser"
		default:
			// RESET / TIMED_OUT / REFUSED / SSL_PROTOCOL_ERROR / generic: a
			// connection killed with no established session — a block signature.
			e.Kind = live.Reset
		}
	default:
		return live.Event{}, false
	}
	return e, true
}

// corsHeaders lets the browser extension POST observations cross-origin.
func corsHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("access-control-allow-origin", "*")
	h.Set("access-control-allow-methods", "POST, OPTIONS")
	h.Set("access-control-allow-headers", "content-type")
}

func viewOf(f live.Flow) flowView {
	v := flowView{
		Domain:      f.Domain,
		Nature:      string(f.Nature()),
		Cause:       f.DeepCause,
		Confidence:  string(f.Confidence),
		Attribution: string(f.Attribution),
		Authority:   f.Authority,
		Analyzed:    f.Analyzed,
		Hits:        f.Hits,
		Resets:      f.Resets,
		Version:     f.Version,
		Handshake:   f.Handshake,
		LastSeen:    f.LastSeen,
	}
	if f.Analyzed {
		v.Verdict = string(f.DeepType)
	}
	return v
}

// diagCache remembers the most recent diagnosis per target so evidence exports
// (HTML report, signed bundle, OONI) are generated from exactly the verdict the
// user just saw, not a fresh re-probe that might read differently.
type diagEntry struct {
	v  *verdict.Verdict
	at time.Time
}

type diagCache struct {
	mu sync.Mutex
	m  map[string]diagEntry
}

func newDiagCache() *diagCache { return &diagCache{m: map[string]diagEntry{}} }

func (c *diagCache) put(target string, v *verdict.Verdict, at time.Time) {
	c.mu.Lock()
	c.m[target] = diagEntry{v: v, at: at}
	c.mu.Unlock()
}

// get returns the cached verdict for target, diagnosing fresh (and caching it)
// if we have none yet. The returned time is when the measurement was taken.
func (c *diagCache) get(ctx context.Context, target string) (*verdict.Verdict, time.Time) {
	c.mu.Lock()
	e, ok := c.m[target]
	c.mu.Unlock()
	if ok {
		return e.v, e.at
	}
	now := time.Now()
	v := engine.Diagnose(ctx, target)
	c.put(target, v, now)
	return v, now
}

func snapshotViews(t *live.Tracker) []flowView {
	flows := t.Snapshot()
	out := make([]flowView, 0, len(flows))
	for _, f := range flows {
		out = append(out, viewOf(f))
	}
	return out
}

// runServe launches the passive cockpit as a local web app: a self-hosted
// dashboard on localhost that drives the same engine as the CLI. It is
// serverless by design — no account, no outbound reporting; the page talks only
// to this process. --active opts into background confirmation probes, exactly
// like `lumra live --active`.
func runServe(args []string) {
	addr := "127.0.0.1:7777"
	interval := time.Second
	var active bool
	noOpen := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--active", "-active":
			active = true
		case "--no-open", "-no-open":
			noOpen = true
		case "--addr", "-addr":
			if i+1 < len(args) {
				addr = args[i+1]
				i++
			}
		case "--interval", "-interval":
			if i+1 < len(args) {
				if d, err := time.ParseDuration(args[i+1]); err == nil && d > 0 {
					interval = d
				}
				i++
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tracker := live.NewTracker()

	// tapState tracks whether the passive live tap is running. Unlike `lumra
	// live`, serve does NOT exit when the tap can't start (e.g. no privilege):
	// the dashboard and on-demand diagnosis work without it, so we degrade
	// gracefully and surface the reason in the UI instead.
	var (
		tapMu  sync.Mutex
		tapMsg string // empty while the tap is healthy
	)
	setTap := func(m string) { tapMu.Lock(); tapMsg = m; tapMu.Unlock() }
	getTap := func() string { tapMu.Lock(); defer tapMu.Unlock(); return tapMsg }

	tapErr := make(chan error, 1)
	go func() { tapErr <- live.NewTap().Run(ctx, tracker.Observe) }()

	if active {
		esc := live.NewEscalator(tracker, engine.Diagnose)
		esc.Enforcer = live.NewEnforcer(live.DefaultDir(), probe.ResolveDoH)
		go esc.Run(ctx)
	}

	// Give the tap a moment to fail fast on the common errors (no privilege,
	// unsupported platform) so the banner is accurate on first paint. If it dies
	// later, a background watcher records that too.
	select {
	case err := <-tapErr:
		if err != nil {
			setTap(err.Error())
			fmt.Fprintln(os.Stderr, "lumra serve: live tap disabled —", err)
			fmt.Fprintln(os.Stderr, "  (diagnosis still works; run elevated for the live board)")
		}
	case <-time.After(150 * time.Millisecond):
		go func() {
			if err := <-tapErr; err != nil {
				setTap(err.Error())
			}
		}()
	}

	cache := newDiagCache()
	watches := newWatchManager(ctx)
	mux := http.NewServeMux()

	// The dashboard shell.
	page, err := webUI.ReadFile("webui/index.html")
	if err != nil {
		fmt.Fprintln(os.Stderr, "lumra serve:", err)
		os.Exit(1)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("content-type", "text/html; charset=utf-8")
		_, _ = w.Write(page)
	})

	// Health of the live tap, so the UI can show a banner when the passive board
	// is unavailable (e.g. not run elevated) rather than silently staying empty.
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		msg := getTap()
		writeJSON(w, map[string]any{
			"tap_ok": msg == "",
			"tap":    msg,
			"active": active,
		})
	})

	// One-shot snapshot of the live board.
	mux.HandleFunc("/api/live", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, snapshotViews(tracker))
	})

	// Server-sent events: push the board on every tick so the page stays live
	// without polling. Closes cleanly when the client disconnects or we shut down.
	mux.HandleFunc("/api/stream", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "text/event-stream")
		w.Header().Set("cache-control", "no-cache")
		w.Header().Set("connection", "keep-alive")

		t := time.NewTicker(interval)
		defer t.Stop()
		enc := json.NewEncoder(w)
		send := func() {
			fmt.Fprint(w, "data: ")
			_ = enc.Encode(snapshotViews(tracker)) // Encode writes the trailing newline
			fmt.Fprint(w, "\n")
			flusher.Flush()
		}
		send() // prime immediately so the page fills without waiting a tick
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ctx.Done():
				return
			case <-t.C:
				send()
			}
		}
	})

	// On-demand deep diagnosis of a single target, same as `lumra diagnose`.
	mux.HandleFunc("/api/diagnose", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Target string `json:"target"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Target == "" {
			http.Error(w, "body must be {\"target\": \"...\"}", http.StatusBadRequest)
			return
		}
		dctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		now := time.Now()
		v := engine.Diagnose(dctx, req.Target)
		cache.put(req.Target, v, now)
		writeJSON(w, v)
	})

	// Privilege-free traffic sensor: the browser extension observes every
	// request it makes (webRequest) and streams them here, so the live board
	// populates without the raw-socket tap (which needs elevation). Each
	// observation is mapped to the same wire event the passive tap emits and
	// folded into the very same tracker.
	mux.HandleFunc("/api/observe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions { // CORS preflight from the extension
			corsHeaders(w)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		corsHeaders(w)
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var obs []observation
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&obs); err != nil {
			http.Error(w, "body must be a JSON array of observations", http.StatusBadRequest)
			return
		}
		now := time.Now()
		n := 0
		for _, o := range obs {
			if ev, ok := o.toEvent(now); ok {
				tracker.Observe(ev)
				n++
			}
		}
		writeJSON(w, map[string]any{"ok": true, "accepted": n})
	})

	// Evidence exports — generated from the last cached diagnosis (or a fresh one
	// if none yet), so the downloaded artifact matches the on-screen verdict.
	// These are what makes the local cockpit useful in a lab: a shareable report
	// and a tamper-evident, signed measurement bundle.
	mux.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		if target == "" {
			http.Error(w, "target query required", http.StatusBadRequest)
			return
		}
		dctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		v, at := cache.get(dctx, target)
		html, err := report.HTML(v, at)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		serveDownload(w, "text/html; charset=utf-8", "lumra-"+safeName(target)+".html", html)
	})

	mux.HandleFunc("/api/bundle", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		if target == "" {
			http.Error(w, "target query required", http.StatusBadRequest)
			return
		}
		dctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		v, at := cache.get(dctx, target)
		priv, err := evidence.LoadOrCreateKey()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		b, err := evidence.Sign(v, at, version, priv)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data, err := b.Encode()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		serveDownload(w, "application/json", "lumra-"+safeName(target)+"-bundle.json", data)
	})

	mux.HandleFunc("/api/ooni", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		if target == "" {
			http.Error(w, "target query required", http.StatusBadRequest)
			return
		}
		dctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		v, at := cache.get(dctx, target)
		// Cross-link the OONI report_id to the signed bundle digest, same as the CLI.
		priv, err := evidence.LoadOrCreateKey()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		b, err := evidence.Sign(v, at, version, priv)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data, err := evidence.OONI(v, at, version, b.Digest).Encode()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		serveDownload(w, "application/json", "lumra-"+safeName(target)+"-ooni.json", data)
	})

	// Continuous monitoring: start/stop a per-target watcher and read its
	// blocked-at timeline. Turns the one-shot cockpit into a standing monitor.
	mux.HandleFunc("/api/watches", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, watches.list())
	})
	mux.HandleFunc("/api/watch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Target   string `json:"target"`
			Interval string `json:"interval"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Target == "" {
			http.Error(w, "body must be {\"target\": \"...\", \"interval\": \"30s\"}", http.StatusBadRequest)
			return
		}
		interval := 30 * time.Second
		if req.Interval != "" {
			if d, err := time.ParseDuration(req.Interval); err == nil && d >= time.Second {
				interval = d
			}
		}
		watches.start(req.Target, interval)
		writeJSON(w, map[string]any{"ok": true, "target": req.Target, "interval": interval.String()})
	})
	mux.HandleFunc("/api/watch/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Target string `json:"target"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Target == "" {
			http.Error(w, "body must be {\"target\": \"...\"}", http.StatusBadRequest)
			return
		}
		watches.stop(req.Target)
		writeJSON(w, map[string]any{"ok": true})
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	url := "http://" + addr
	fmt.Printf("lumra cockpit — %s  (mode: %s, Ctrl-C to stop)\n", url, liveMode(active))
	if !noOpen {
		// Open the dashboard in the default browser once the listener is up, so a
		// double-clicked binary lands the user straight on the cockpit. Best-effort:
		// a headless box or missing opener just leaves the printed URL.
		go func() {
			time.Sleep(300 * time.Millisecond)
			openBrowser(url)
		}()
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "lumra serve:", err)
		os.Exit(1)
	}
}

// openBrowser points the OS default browser at url. Best-effort and silent: the
// URL is always printed, so a failure here never blocks using the cockpit.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("content-type", "application/json")
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

// serveDownload sends body as a file the browser saves rather than renders.
func serveDownload(w http.ResponseWriter, contentType, filename string, body []byte) {
	w.Header().Set("content-type", contentType)
	w.Header().Set("content-disposition", "attachment; filename=\""+filename+"\"")
	_, _ = w.Write(body)
}

// safeName reduces a target to a filesystem- and header-safe token for filenames.
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "target"
	}
	return out
}
