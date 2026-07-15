package probe

import (
	"context"
	"fmt"

	"github.com/croc100/lumra/internal/verdict"
)

// guessInitialTTL infers the sender's original IP TTL by rounding the observed
// value up to the nearest common default (64: Linux/macOS, 128: Windows,
// 255: many network appliances).
func guessInitialTTL(observed uint8) uint8 {
	switch {
	case observed == 0:
		return 0
	case observed <= 64:
		return 64
	case observed <= 128:
		return 128
	default:
		return 255
	}
}

// hopsAway estimates how many router hops away a packet's sender is, from the
// TTL remaining when it reached us.
func hopsAway(observed uint8) int {
	init := guessInitialTTL(observed)
	if init == 0 {
		return -1
	}
	return int(init) - int(observed)
}

// attributeInjectedRST decides where an injected RST originates, given the TTL
// of the injected RST and the TTL of a legitimate packet from the true server.
// An injector materially closer than the server sits inside the path (domestic
// backbone) rather than at the destination. hopMargin is how many hops closer
// the injector must be to call it in-network.
const hopMargin = 3

func attributeInjectedRST(serverTTL, rstTTL uint8) verdict.Attribution {
	sh, rh := hopsAway(serverTTL), hopsAway(rstTTL)
	if sh < 0 || rh < 0 {
		return verdict.AttrUnknown
	}
	if rh+hopMargin <= sh {
		return verdict.AttrInNetwork
	}
	return verdict.AttrUnknown // consistent with the server → not clearly injected in-path
}

// RSTFinding holds the raw-capture result for RST attribution.
type RSTFinding struct {
	Available bool  // capture ran (needs raw-socket privilege)
	Injected  bool  // an RST was observed that did not originate from the server
	ServerTTL uint8 // TTL of a legitimate packet from the destination
	RSTTTL    uint8 // TTL of the injected RST
	Note      string
}

// RST attempts to observe TCP RST injection to ip:443 and measure the injecting
// middlebox's distance via TTL. Raw packet capture requires elevated privilege
// (root / cap_net_raw) and kernel-RST suppression; when unavailable it degrades
// to reporting that attribution could not be measured.
func RST(ctx context.Context, ip string) *RSTFinding {
	return captureRST(ctx, ip)
}

// Contribute folds RST attribution into the verdict, refining attribution for an
// already-detected block (e.g. SNI_FILTERING → in_network).
func (f *RSTFinding) Contribute(v *verdict.Verdict) {
	if !f.Available {
		v.Add("HOP", verdict.Info, "attribution not measured: "+f.Note)
		return
	}
	if !f.Injected {
		v.Add("HOP", verdict.Info, "no injected RST observed")
		return
	}
	attr := attributeInjectedRST(f.ServerTTL, f.RSTTTL)
	sh, rh := hopsAway(f.ServerTTL), hopsAway(f.RSTTTL)
	v.Add("HOP", verdict.Info, fmt.Sprintf(
		"RST injected ~%d hops away; destination ~%d hops → %s", rh, sh, attrLabel(attr)))
	if attr == verdict.AttrInNetwork && v.Attribution == verdict.AttrUnknown {
		v.Attribution = verdict.AttrInNetwork
	}
	// A bare RST_INJECTION verdict is only justified once we confirm the RST is
	// injected and in-path, and no stronger type (SNI/DNS) already explains it.
	if v.Type == verdict.OK {
		v.Type = verdict.RSTInjection
		v.Confidence = verdict.Medium
		v.Cause = "A TCP RST was injected from within the network path, closer than " +
			"the destination — the connection is being reset by a middlebox."
	}
}

func attrLabel(a verdict.Attribution) string {
	if a == verdict.AttrInNetwork {
		return "in-network"
	}
	return "inconclusive"
}
