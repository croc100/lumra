// Package engine runs Lumra's probe pipeline and folds the results into a single
// verdict. Both the CLI and the native-messaging host call Diagnose.
package engine

import (
	"context"

	"github.com/croc100/lumra/internal/probe"
	"github.com/croc100/lumra/internal/verdict"
)

// Diagnose runs the available detectors against target and returns one verdict.
// Probes are ordered so later ones can refine or override earlier ones; control
// is applied last so a dead local network overrides target-specific findings.
func Diagnose(ctx context.Context, target string) *verdict.Verdict {
	v := &verdict.Verdict{Target: target, Type: verdict.OK, Confidence: verdict.Low}

	// Baseline connectivity first; its verdict is applied last so it can override.
	control := probe.Control(ctx)

	dns := probe.DNS(ctx, target)
	dns.Contribute(v)

	// Probe TLS/SNI and RST attribution against a ground-truth IP so a poisoned
	// DNS answer does not send us to a sinkhole.
	if ip := pickIP(dns); ip != "" {
		probe.TLS(ctx, target, ip).Contribute(v)
		// Surveillance axis: a middlebox stripping TLS 1.3 to keep the SNI/cert
		// readable. Runs after TLS so a hard block (MITM/SNI) takes precedence.
		probe.Downgrade(ctx, target, ip).Contribute(v)
		probe.RST(ctx, ip).Contribute(v)
		// Throughput last of the target-IP probes: only a weaker throttling
		// signal, and it must not mask a hard block found above.
		probe.Throttle(ctx, target, ip).Contribute(v)
	} else {
		v.Add("TLS", verdict.Info, "skipped: no ground-truth IP to probe")
	}

	// Self-identifying block page (HTTP): names the operator when present.
	probe.BlockPage(ctx, target).Contribute(v)

	// Apply control last: a dead local network overrides target-specific findings.
	control.Contribute(v)

	if v.Type == verdict.OK {
		v.Cause = "No interference detected by the probes run so far."
	}
	// Derive the user-facing character once the final Type is settled.
	v.Nature = verdict.NatureOf(v.Type)
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
