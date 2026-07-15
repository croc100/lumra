// Command lumra diagnoses internet interference for a target and reports the
// type, attribution, and self-produced evidence.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/croc100/lumra/internal/engine"
	"github.com/croc100/lumra/internal/nativemsg"
	"github.com/croc100/lumra/internal/verdict"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n"+
		"  lumra diagnose <domain> [--json]\n"+
		"  lumra install-host <extension-id>   (register the browser native host)\n"+
		"  lumra nm-host                       (native-messaging host; run by the browser)")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "diagnose":
		runDiagnose(os.Args[2:])
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
	// Parse permissively: --json may appear before or after the target.
	var target string
	var jsonOut bool
	for _, a := range args {
		switch a {
		case "--json", "-json":
			jsonOut = true
		default:
			if target == "" {
				target = a
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

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
		return
	}
	printVerdict(v)
}

func printVerdict(v *verdict.Verdict) {
	fmt.Printf("Target:      %s\n", v.Target)
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
