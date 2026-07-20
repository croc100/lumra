// Package verdict defines Lumra's shared result model: the interference types,
// attribution axis, confidence levels, and evidence records that every detector
// contributes to and the CLI/extension render.
package verdict

// Type is the kind of interference Lumra concludes is present.
type Type string

const (
	OK            Type = "OK"             // no interference detected
	DNSTampering  Type = "DNS_TAMPERING"  // DNS answer poisoned/manipulated
	SNIFiltering  Type = "SNI_FILTERING"  // TLS blocked based on SNI
	RSTInjection  Type = "RST_INJECTION"  // middlebox injects TCP RST
	IPBlocking    Type = "IP_BLOCKING"    // destination IP blackholed/dropped
	TLSMITM       Type = "TLS_MITM"       // certificate substitution
	TLSDowngrade  Type = "TLS_DOWNGRADE"  // TLS 1.3 stripped to force a readable handshake
	ECHBlocking   Type = "ECH_BLOCKING"   // Encrypted ClientHello reset to keep the SNI visible
	DoHBlocking   Type = "DOH_BLOCKING"   // the encrypted-DNS (DoH) channel itself is being blocked
	BlockPage     Type = "BLOCK_PAGE"     // block/notice page injected
	QUICBlocking  Type = "QUIC_BLOCKING"  // UDP/443 QUIC blocked to force traffic onto filterable TCP
	Throttling    Type = "THROTTLING"     // target-selective rate limiting
	LocalIssue    Type = "LOCAL_ISSUE"    // the user's own network is at fault
	GenuineOutage Type = "GENUINE_OUTAGE" // the target itself is down
	Inconclusive  Type = "INCONCLUSIVE"   // not enough signal to decide
)

// Nature is the human-intuitive character of the interference: what someone is
// doing to the connection, regardless of the specific mechanism. It folds the
// eleven interference Types onto the axis a user actually cares about — am I
// being blocked, watched, slowed, or is nothing wrong. It is derived purely
// from Type via NatureOf; it is never measured independently.
type Nature string

const (
	NatureNone         Nature = "none"         // no interference
	NatureControl      Nature = "control"      // access is being prevented (censorship)
	NatureSurveillance Nature = "surveillance" // the connection is being intercepted/read
	NatureDegradation  Nature = "degradation"  // access works but is deliberately worsened
	NatureFault        Nature = "fault"        // a genuine fault (local network or target down)
	NatureUnknown      Nature = "unknown"      // not enough signal to characterise
)

// NatureOf folds an interference Type onto its user-facing character. The split
// is by intent: blocking mechanisms prevent access (control); certificate
// substitution and other in-path reads observe it (surveillance).
func NatureOf(t Type) Nature {
	switch t {
	case OK:
		return NatureNone
	case DNSTampering, SNIFiltering, RSTInjection, IPBlocking, BlockPage, DoHBlocking:
		return NatureControl
	case TLSMITM, TLSDowngrade, ECHBlocking:
		return NatureSurveillance
	case Throttling, QUICBlocking:
		return NatureDegradation
	case LocalIssue, GenuineOutage:
		return NatureFault
	default: // Inconclusive and any future type
		return NatureUnknown
	}
}

// Attribution reports where the interference originates. It is measured, never
// asserted from third-party lists.
type Attribution string

const (
	AttrUnknown        Attribution = ""                // not determined
	AttrInNetwork      Attribution = "in_network"      // inside the domestic path, before international transit
	AttrDestination    Attribution = "destination"     // the target server itself
	AttrLocal          Attribution = "local"           // the user's own network
	AttrSelfIdentified Attribution = "self_identified" // block infra named itself (see Authority)
)

// Confidence grades how strongly the evidence supports the verdict. Only High
// verdicts are stated as conclusions; lower grades are reported as "possible".
type Confidence string

const (
	High   Confidence = "high"
	Medium Confidence = "medium"
	Low    Confidence = "low"
)

// Outcome marks whether a single piece of evidence supports interference,
// looks clean, or is informational context.
type Outcome string

const (
	Pass Outcome = "pass" // clean signal (no interference on this axis)
	Fail Outcome = "fail" // interference signal
	Info Outcome = "info" // contextual observation (e.g. hop distance)
)

// Evidence is one observed fact contributing to a verdict. Each is something
// Lumra measured directly, not something it was told.
type Evidence struct {
	Probe   string  `json:"probe"` // short tag, e.g. "DNS", "TLS", "HOP"
	Outcome Outcome `json:"outcome"`
	Detail  string  `json:"detail"`
}

// Verdict is the complete result for one target.
type Verdict struct {
	Target      string      `json:"target"`
	Type        Type        `json:"type"`
	Nature      Nature      `json:"nature"`
	Confidence  Confidence  `json:"confidence"`
	Attribution Attribution `json:"attribution,omitempty"`
	Authority   string      `json:"authority,omitempty"` // set when Attribution is self_identified, e.g. "KCSC"
	Cause       string      `json:"cause"`
	Evidence    []Evidence  `json:"evidence"`
}

// Add appends an evidence record.
func (v *Verdict) Add(probe string, outcome Outcome, detail string) {
	v.Evidence = append(v.Evidence, Evidence{Probe: probe, Outcome: outcome, Detail: detail})
}
