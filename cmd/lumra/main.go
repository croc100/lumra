// Command lumra diagnoses internet interference for a target and reports the
// type, attribution, and self-produced evidence.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/croc100/lumra/internal/engine"
	"github.com/croc100/lumra/internal/nativemsg"
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
		"  lumra diagnose <domain> [--json] [--report <file.html>]\n"+
		"  lumra watch <domain> [--interval 30s] [--json]\n"+
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
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "--version", "-v":
		printVersion()
	case "diagnose":
		runDiagnose(os.Args[2:])
	case "watch":
		runWatch(os.Args[2:])
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
	var target, reportPath string
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

	v := engine.Diagnose(ctx, target)

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
