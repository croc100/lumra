package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

// Throttling is measured relatively: a target that is reachable and completes
// handshakes but sustains a throughput far below a capable control path — with a
// stable rate rather than bursty loss — is the signature of deliberate,
// target-selective rate limiting, as opposed to ordinary congestion (which slows
// the control path too) or a hard block (which the TLS/RST probes already catch).
const (
	throttleMaxBytes  = 3 << 20                 // read at most 3 MB per arm
	throttleMaxDur    = 2500 * time.Millisecond // steady-state sampling window per arm
	throttleMinSample = 96 << 10                // need >=96 KB transferred to trust a rate
	throttleFloorBps  = 256 << 10               // target steady-state below this is suspicious (bytes/s)
	throttleRatio     = 5.0                     // control must be >=5x target to call it selective
)

// throttleControls are large, effectively-unblockable objects used only to
// establish what throughput the line is capable of right now. The best observed
// rate is the baseline; blocking all of these would break the wider internet.
var throttleControls = []string{
	"https://speed.cloudflare.com/__down?bytes=5000000",
	"https://www.google.com/",
}

// ThrottleFinding compares sustained throughput to the target against a capable
// control baseline.
type ThrottleFinding struct {
	Domain       string
	IP           string
	TargetRate   float64 // steady-state bytes/sec to the target (0 = not measured)
	ControlRate  float64 // best steady-state bytes/sec across control anchors
	TargetBytes  int64
	ControlBytes int64
	Measured     bool // both arms produced a trustworthy rate
	Throttled    bool
	Note         string
}

// Throttle downloads a byte budget from the target (pinned to a ground-truth IP
// so a poisoned answer cannot skew the measurement) and from a control anchor,
// then classifies the result. It performs real transfers and is the heaviest
// probe; the engine runs it only when the target is otherwise reachable.
func Throttle(ctx context.Context, domain, ip string) *ThrottleFinding {
	f := &ThrottleFinding{Domain: domain, IP: ip}

	tgtURL := "https://" + domain + "/"
	f.TargetBytes, f.TargetRate = measureRate(ctx, tgtURL, ip)

	for _, c := range throttleControls {
		if b, r := measureRate(ctx, c, ""); r > f.ControlRate {
			f.ControlBytes, f.ControlRate = b, r
		}
	}

	f.Measured, f.Throttled, f.Note = assessThrottle(f.TargetRate, f.ControlRate)
	return f
}

// assessThrottle is the pure classification step, split out so it can be tested
// without a network. measured is true only when both arms yielded a rate; a rate
// of 0 means that arm did not transfer enough to trust.
func assessThrottle(targetRate, controlRate float64) (measured, throttled bool, note string) {
	switch {
	case targetRate == 0 && controlRate == 0:
		return false, false, "insufficient transfer on both target and control to assess throttling"
	case targetRate == 0:
		return false, false, "target did not serve enough data to measure throughput"
	case controlRate == 0:
		return false, false, "no capable control baseline available to compare against"
	case targetRate >= throttleFloorBps:
		return true, false, fmt.Sprintf("target throughput ~%s is healthy", humanRate(targetRate))
	case controlRate < throttleFloorBps:
		return true, false, fmt.Sprintf(
			"target ~%s and control ~%s both low — congestion, not target-selective throttling",
			humanRate(targetRate), humanRate(controlRate))
	case controlRate >= throttleRatio*targetRate:
		return true, true, fmt.Sprintf(
			"target ~%s vs control ~%s (%.0fx faster) — target-selective rate limiting",
			humanRate(targetRate), humanRate(controlRate), controlRate/targetRate)
	default:
		return true, false, fmt.Sprintf(
			"target ~%s below floor but control ~%s not decisively faster — inconclusive",
			humanRate(targetRate), humanRate(controlRate))
	}
}

// measureRate fetches url and returns the bytes read and the steady-state rate
// (bytes/sec), timing from the first byte so connection setup and TTFB are
// excluded. When pinIP is set the connection is dialed to that address while the
// URL's host is kept for SNI/Host. Returns rate 0 when too little was transferred
// to trust the measurement.
func measureRate(ctx context.Context, url, pinIP string) (int64, float64) {
	tr := &http.Transport{DisableKeepAlives: true, ForceAttemptHTTP2: true}
	if pinIP != "" {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				port = "443"
			}
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, net.JoinHostPort(pinIP, port))
		}
		// We are timing bytes, not trusting the peer; a cert mismatch is not
		// interference and must not abort the transfer.
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := &http.Client{Transport: tr}

	reqCtx, cancel := context.WithTimeout(ctx, throttleMaxDur+6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0
	}
	req.Header.Set("User-Agent", "lumra/diagnose")

	resp, err := client.Do(req)
	if err != nil {
		return 0, 0
	}
	defer resp.Body.Close()

	buf := make([]byte, 32<<10)
	var read int64
	var start time.Time
	deadline := time.Now().Add(throttleMaxDur)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if start.IsZero() {
				start = time.Now() // clock starts at the first byte
			}
			read += int64(n)
		}
		if read >= throttleMaxBytes || time.Now().After(deadline) || rerr != nil {
			break
		}
	}

	if start.IsZero() || read < throttleMinSample {
		return read, 0
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		elapsed = 0.001
	}
	return read, float64(read) / elapsed
}

// humanRate formats a bytes/sec value as KB/s or MB/s.
func humanRate(bps float64) string {
	switch {
	case bps >= 1<<20:
		return fmt.Sprintf("%.1f MB/s", bps/(1<<20))
	default:
		return fmt.Sprintf("%.0f KB/s", bps/(1<<10))
	}
}

// Contribute folds the throughput finding into the verdict. Throttling is a
// weaker signal than a hard block, so it only sets the verdict type when no
// stronger interference has already been concluded.
func (f *ThrottleFinding) Contribute(v *verdict.Verdict) {
	if !f.Measured {
		v.Add("RATE", verdict.Info, f.Note)
		return
	}
	if f.Throttled {
		v.Add("RATE", verdict.Fail, f.Note)
		if v.Type == verdict.OK || v.Type == verdict.Inconclusive || v.Type == "" {
			v.Type = verdict.Throttling
			v.Confidence = verdict.Medium
			v.Attribution = verdict.AttrInNetwork
			v.Cause = "The target is reachable but its sustained throughput is far below " +
				"a capable control path, at a stable rate — the signature of deliberate, " +
				"target-selective throttling rather than ordinary congestion."
		}
		return
	}
	v.Add("RATE", verdict.Pass, f.Note)
}
