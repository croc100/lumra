// Command lumra diagnoses internet interference for a target and reports the
// type, attribution, and self-produced evidence.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/croc100/lumra/internal/probe"
	"github.com/croc100/lumra/internal/verdict"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: lumra diagnose <domain> [--json]")
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "diagnose" {
		usage()
		os.Exit(2)
	}

	// Parse the rest permissively: --json may appear before or after the target.
	var target string
	var jsonOut bool
	for _, a := range os.Args[2:] {
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

	v := diagnose(ctx, target)

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
		return
	}
	printVerdict(v)
}

// diagnose runs the available detectors and folds them into one verdict.
// MVP: DNS analysis. TCP/RST, TLS/SNI, and TTL attribution land next.
func diagnose(ctx context.Context, target string) *verdict.Verdict {
	v := &verdict.Verdict{Target: target, Type: verdict.OK, Confidence: verdict.Low}

	dns := probe.DNS(ctx, target)
	dns.Contribute(v)

	// Probe TLS/SNI against a ground-truth IP so a poisoned DNS answer does not
	// send us to a sinkhole.
	if ip := pickIP(dns); ip != "" {
		probe.TLS(ctx, target, ip).Contribute(v)
	} else {
		v.Add("TLS", verdict.Info, "skipped: no ground-truth IP to probe")
	}

	if v.Type == verdict.OK {
		v.Cause = "No interference detected by the probes run so far."
	}
	return v
}

// pickIP chooses the address to probe: DoH ground truth first, then any
// plaintext answer as a fallback.
func pickIP(dns *probe.DNSFinding) string {
	if len(dns.GroundTruth) > 0 {
		return dns.GroundTruth[0]
	}
	for _, src := range []string{"system", "public-cloudflare", "public-google"} {
		if ips := dns.Answers[src]; len(ips) > 0 {
			return ips[0]
		}
	}
	return ""
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
		return "✓" // ✓
	case verdict.Fail:
		return "✗" // ✗
	default:
		return "ⓘ" // ⓘ
	}
}
