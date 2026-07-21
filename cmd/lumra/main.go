// Command lumra diagnoses internet interference for a target and reports the
// type, attribution, and self-produced evidence.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/croc100/lumra/internal/engine"
	"github.com/croc100/lumra/internal/evidence"
	"github.com/croc100/lumra/internal/live"
	"github.com/croc100/lumra/internal/nativemsg"
	"github.com/croc100/lumra/internal/probe"
	"github.com/croc100/lumra/internal/report"
	"github.com/croc100/lumra/internal/verdict"
	"github.com/croc100/lumra/internal/watch"
)

// Build metadata, injected by the release pipeline via -ldflags -X.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n"+
		"  lumra                               (no args: launch the local cockpit and open the browser)\n"+
		"  lumra diagnose <domain> [--json] [--report <file.html>] [--bundle <file.json>] [--ooni <file.json>]\n"+
		"  lumra verify <bundle.json>          (check a signed evidence bundle)\n"+
		"  lumra push <domain> | --bundle <file.json> [--endpoint <url>] [--asn ..] [--country ..]\n"+
		"  lumra watch <domain> [--interval 30s] [--json]\n"+
		"  lumra live [--active]               (passive cockpit; --active adds background confirmation)\n"+
		"  lumra serve [--addr 127.0.0.1:7777] [--active] [--no-open]   (local web cockpit in your browser)\n"+
		"  lumra install-host <extension-id>   (register the browser native host)\n"+
		"  lumra nm-host                       (native-messaging host; run by the browser)\n"+
		"  lumra version")
}

func printVersion() {
	short := commit
	if len(short) > 7 {
		short = short[:7]
	}
	fmt.Printf("lumra %s (%s) %s\n", version, short, date)
}

func main() {
	// No subcommand — the "just run it" path. Double-clicking the binary or
	// running a bare `lumra` launches the local cockpit and opens the browser,
	// so the tool needs no install ceremony. `lumra help` prints the CLI usage.
	if len(os.Args) < 2 {
		runServe(nil)
		return
	}
	switch os.Args[1] {
	case "help", "--help", "-h":
		usage()
	case "version", "--version", "-v":
		printVersion()
	case "diagnose":
		runDiagnose(os.Args[2:])
	case "watch":
		runWatch(os.Args[2:])
	case "live":
		runLive(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	case "push":
		runPush(os.Args[2:])
	case "nm-host":
		// Speaks the browser native-messaging protocol on stdin/stdout.
		if err := nativemsg.Serve(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "nm-host:", err)
			os.Exit(1)
		}
	case "install-host":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		path, err := nativemsg.InstallHost(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "install-host:", err)
			os.Exit(1)
		}
		fmt.Println("native host manifest written:", path)
	default:
		usage()
		os.Exit(2)
	}
}

func runDiagnose(args []string) {
	// Parse permissively: flags may appear before or after the target.
	var target, reportPath, bundlePath, ooniPath string
	var jsonOut bool
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json", "-json":
			jsonOut = true
		case "--report", "-report":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--report needs a file path")
				os.Exit(2)
			}
			i++
			reportPath = args[i]
		case "--bundle", "-bundle":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--bundle needs a file path")
				os.Exit(2)
			}
			i++
			bundlePath = args[i]
		case "--ooni", "-ooni":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--ooni needs a file path")
				os.Exit(2)
			}
			i++
			ooniPath = args[i]
		default:
			if target == "" {
				target = args[i]
			}
		}
	}
	if target == "" {
		usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	now := time.Now()
	v := engine.Diagnose(ctx, target)

	// A signed bundle backs both --bundle and --ooni: the bundle digest becomes
	// the OONI report_id, cross-linking the two artifacts. Sign once if either
	// is requested.
	var bundle *evidence.Bundle
	if bundlePath != "" || ooniPath != "" {
		priv, err := evidence.LoadOrCreateKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, "evidence:", err)
			os.Exit(1)
		}
		bundle, err = evidence.Sign(v, now, version, priv)
		if err != nil {
			fmt.Fprintln(os.Stderr, "evidence:", err)
			os.Exit(1)
		}
	}

	if bundlePath != "" {
		data, err := bundle.Encode()
		if err != nil {
			fmt.Fprintln(os.Stderr, "bundle:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(bundlePath, data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "bundle:", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "signed bundle written:", bundlePath, "("+bundle.Signature.KeyID+")")
	}

	if ooniPath != "" {
		m := evidence.OONI(v, now, version, bundle.Digest)
		data, err := m.Encode()
		if err != nil {
			fmt.Fprintln(os.Stderr, "ooni:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(ooniPath, data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "ooni:", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "OONI measurement written:", ooniPath)
	}

	if reportPath != "" {
		html, err := report.HTML(v, time.Now())
		if err != nil {
			fmt.Fprintln(os.Stderr, "report:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(reportPath, html, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "report:", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "report written:", reportPath)
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
		return
	}
	printVerdict(v)
}

func runVerify(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: lumra verify <bundle.json>")
		os.Exit(2)
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		os.Exit(1)
	}
	b, err := evidence.Decode(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		os.Exit(1)
	}
	pub, err := evidence.Verify(b)
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗ NOT AUTHENTIC —", err)
		os.Exit(1)
	}
	m, err := b.ParseMeasurement()
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		os.Exit(1)
	}
	fmt.Println("✓ authentic — signature verifies and the measurement is intact")
	fmt.Printf("  target:     %s\n", m.Target)
	fmt.Printf("  verdict:    %s (%s)\n", m.Verdict.Type, m.Verdict.Confidence)
	fmt.Printf("  measured:   %s\n", m.MeasuredAt)
	fmt.Printf("  tool:       lumra %s\n", m.ToolVersion)
	fmt.Printf("  signed by:  %s\n", evidence.KeyID(pub))
	fmt.Printf("  digest:     %s\n", b.Digest)
}

// defaultCloudEndpoint is the hosted Lumra Cloud ingest base. Override with
// --endpoint or the LUMRA_CLOUD environment variable.
const defaultCloudEndpoint = "https://app.lumra.crode.net"

// ingestBody is the v1 ingest wire format. Measurement is the verbatim canonical
// bytes that were signed, carried as a JSON string so the server verifies the
// Ed25519 signature over exactly those bytes without re-deriving canonical JSON.
type ingestBody struct {
	Measurement string             `json:"measurement"`
	Digest      string             `json:"digest"`
	Signature   evidence.Signature `json:"signature"`
	ASN         string             `json:"asn,omitempty"`
	Country     string             `json:"country,omitempty"`
}

// runPush submits a signed measurement bundle to a hosted Lumra Cloud endpoint.
// It either diagnoses a target fresh and signs the result, or pushes an existing
// bundle file (--bundle).
func runPush(args []string) {
	var target, bundlePath, endpoint, asn, country string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--bundle", "-bundle":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "--bundle needs a file path")
				os.Exit(2)
			}
			bundlePath = args[i]
		case "--endpoint", "-endpoint":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "--endpoint needs a URL")
				os.Exit(2)
			}
			endpoint = args[i]
		case "--asn", "-asn":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "--asn needs a value")
				os.Exit(2)
			}
			asn = args[i]
		case "--country", "-country":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "--country needs a value")
				os.Exit(2)
			}
			country = args[i]
		default:
			if target == "" {
				target = args[i]
			}
		}
	}
	if endpoint == "" {
		endpoint = os.Getenv("LUMRA_CLOUD")
	}
	if endpoint == "" {
		endpoint = defaultCloudEndpoint
	}

	// Obtain a signed bundle: from a file, or by diagnosing the target now.
	var bundle *evidence.Bundle
	switch {
	case bundlePath != "":
		data, err := os.ReadFile(bundlePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "push:", err)
			os.Exit(1)
		}
		if bundle, err = evidence.Decode(data); err != nil {
			fmt.Fprintln(os.Stderr, "push:", err)
			os.Exit(1)
		}
	case target != "":
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		now := time.Now()
		v := engine.Diagnose(ctx, target)
		priv, err := evidence.LoadOrCreateKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, "push:", err)
			os.Exit(1)
		}
		if bundle, err = evidence.Sign(v, now, version, priv); err != nil {
			fmt.Fprintln(os.Stderr, "push:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: lumra push <domain> | --bundle <file.json>")
		os.Exit(2)
	}

	// Verify locally before shipping — never push a bundle we can't stand behind.
	if _, err := evidence.Verify(bundle); err != nil {
		fmt.Fprintln(os.Stderr, "push: refusing to send an unverifiable bundle:", err)
		os.Exit(1)
	}
	canonical, err := bundle.CanonicalMeasurement()
	if err != nil {
		fmt.Fprintln(os.Stderr, "push:", err)
		os.Exit(1)
	}

	body, err := json.Marshal(ingestBody{
		Measurement: string(canonical),
		Digest:      bundle.Digest,
		Signature:   bundle.Signature,
		ASN:         asn,
		Country:     country,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "push:", err)
		os.Exit(1)
	}

	url := strings.TrimRight(endpoint, "/") + "/v1/ingest"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintln(os.Stderr, "push:", err)
		os.Exit(1)
	}
	req.Header.Set("content-type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "push:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 400 {
		fmt.Fprintf(os.Stderr, "push failed (%s): %s\n", resp.Status, strings.TrimSpace(string(respBody)))
		os.Exit(1)
	}
	fmt.Printf("pushed to %s — %s\n", url, strings.TrimSpace(string(respBody)))
}

func runWatch(args []string) {
	var target string
	var jsonOut bool
	interval := 30 * time.Second
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json", "-json":
			jsonOut = true
		case "--interval", "-interval":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--interval needs a duration, e.g. 30s")
				os.Exit(2)
			}
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil || d <= 0 {
				fmt.Fprintln(os.Stderr, "invalid --interval:", args[i])
				os.Exit(2)
			}
			interval = d
		default:
			if target == "" {
				target = args[i]
			}
		}
	}
	if target == "" {
		usage()
		os.Exit(2)
	}

	// Cancel on Ctrl-C / SIGTERM so the ticker loop exits cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	enc := json.NewEncoder(os.Stdout)
	if !jsonOut {
		fmt.Fprintf(os.Stderr, "watching %s every %s (Ctrl-C to stop)\n", target, interval)
	}

	m := watch.New(target, func(c context.Context, t string) *verdict.Verdict {
		// Bound each individual diagnosis so a hung probe can't stall the loop.
		dctx, cancel := context.WithTimeout(c, 20*time.Second)
		defer cancel()
		return engine.Diagnose(dctx, t)
	})
	m.Run(ctx, interval, func(e watch.Event) {
		if jsonOut {
			_ = enc.Encode(e)
			return
		}
		printEvent(e)
	})
}

func printEvent(e watch.Event) {
	ts := e.At.Format("15:04:05")
	switch e.Kind {
	case watch.Start:
		fmt.Printf("[%s] ● baseline: %s\n", ts, e.Type)
	case watch.Blocked:
		fmt.Printf("[%s] %s (%s)\n", ts, natureLine(e.Verdict.Nature), e.Type)
	case watch.Recovered:
		fmt.Printf("[%s] ✓ recovered (was %s)\n", ts, e.Prev)
	case watch.Changed:
		fmt.Printf("[%s] ⟳ changed: %s → %s\n", ts, e.Prev, e.Type)
	}
}

// runLive starts the passive tap and renders a continuously refreshed board of
// every domain the host is talking to, each with a control/surveillance/clear
// badge. It is Lumra's cockpit: the live view of your own internet.
func runLive(args []string) {
	interval := time.Second
	var active bool
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--active", "-active":
			active = true
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
	tapErr := make(chan error, 1)
	go func() { tapErr <- live.NewTap().Run(ctx, tracker.Observe) }()

	// Default is pure passive: the board reflects only what the tap observes on
	// the wire — no connection Lumra opens itself. --active opts in to background
	// confirmation, where Lumra makes its own separate probe connections to reach
	// an authoritative verdict and apply the protective lever. Either way the
	// user's own traffic is only ever watched, never intercepted or forwarded.
	if active {
		esc := live.NewEscalator(tracker, engine.Diagnose)
		esc.Enforcer = live.NewEnforcer(live.DefaultDir(), probe.ResolveDoH)
		go esc.Run(ctx)
	}

	// Give the tap a moment to fail fast on the common errors (no privilege,
	// unsupported platform) so we print a clean message instead of a blank board.
	select {
	case err := <-tapErr:
		if err != nil {
			fmt.Fprintln(os.Stderr, "lumra live:", err)
			os.Exit(1)
		}
	case <-time.After(150 * time.Millisecond):
	}

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		fmt.Print("\033[H\033[2J") // clear screen, cursor home
		fmt.Print(live.RenderBoard(tracker.Snapshot(), time.Now()))
		fmt.Printf("\n  mode: %s · Ctrl-C to stop\n", liveMode(active))
		select {
		case <-ctx.Done():
			return
		case err := <-tapErr:
			if err != nil {
				fmt.Fprintln(os.Stderr, "lumra live:", err)
				os.Exit(1)
			}
			return
		case <-t.C:
		}
	}
}

// liveMode labels the cockpit's observation mode for the footer.
func liveMode(active bool) string {
	if active {
		return "passive tap + active confirmation"
	}
	return "passive — watching only, no probes"
}

// natureLine renders the folded, user-facing character of a verdict: what is
// actually happening to the connection, in one intuitive sentence.
func natureLine(n verdict.Nature) string {
	switch n {
	case verdict.NatureControl:
		return "🚫 BLOCKED — your access is being prevented (censorship)"
	case verdict.NatureSurveillance:
		return "👁 WATCHED — your encrypted connection is being intercepted"
	case verdict.NatureDegradation:
		return "🐢 SLOWED — this target is being deliberately throttled"
	case verdict.NatureFault:
		return "⚠ FAULT — a genuine outage, not interference"
	case verdict.NatureNone:
		return "✅ CLEAR — no interference detected"
	default:
		return "❔ UNCLEAR — not enough signal to characterise"
	}
}

func printVerdict(v *verdict.Verdict) {
	fmt.Printf("Target:      %s\n", v.Target)
	fmt.Printf("%s\n\n", natureLine(v.Nature))
	fmt.Printf("Verdict:     %s", v.Type)
	if v.Confidence != "" {
		fmt.Printf("            (confidence: %s)", v.Confidence)
	}
	fmt.Println()
	if v.Attribution != "" {
		attr := string(v.Attribution)
		if v.Authority != "" {
			attr += " / " + v.Authority
		}
		fmt.Printf("Attribution: %s\n", attr)
	}
	if v.Cause != "" {
		fmt.Printf("\n%s\n", v.Cause)
	}
	if len(v.Evidence) > 0 {
		fmt.Println("\nEvidence:")
		for _, e := range v.Evidence {
			fmt.Printf("  %s %-5s %s\n", mark(e.Outcome), e.Probe, e.Detail)
		}
	}
}

func mark(o verdict.Outcome) string {
	switch o {
	case verdict.Pass:
		return "✓"
	case verdict.Fail:
		return "✗"
	default:
		return "ⓘ"
	}
}
