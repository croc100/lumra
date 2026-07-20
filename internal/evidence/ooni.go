package evidence

import (
	"encoding/json"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

// OONI-style export. The OONI measurement schema (data_format_version 0.2.0) is
// the lingua franca of open censorship measurement: a machine-readable record
// journalists, researchers, and aggregators already ingest. Lumra emits a
// compatible envelope so a diagnosis can flow into that ecosystem — while
// staying honest about what it does NOT collect. Lumra deliberately does not
// geolocate the prober or capture its ASN/country (that would fingerprint the
// user under a censoring authority), so those fields are left empty rather than
// guessed.
//
// test_name is namespaced "lumra_interference" to avoid claiming to be a
// canonical OONI nettest; the interference detail lives in test_keys.

const ooniFormatVersion = "0.2.0"

// OONIMeasurement is the exported record. Field names and types follow the OONI
// data format so standard tooling can parse it.
type OONIMeasurement struct {
	DataFormatVersion string         `json:"data_format_version"`
	Input             string         `json:"input"` // the measured target
	MeasurementStart  string         `json:"measurement_start_time"`
	ProbeASN          string         `json:"probe_asn"`          // empty: not collected (privacy)
	ProbeCC           string         `json:"probe_cc"`           // empty: not collected (privacy)
	ProbeNetworkName  string         `json:"probe_network_name"` // empty: not collected (privacy)
	ReportID          string         `json:"report_id"`
	ResolverASN       string         `json:"resolver_asn"`
	SoftwareName      string         `json:"software_name"`
	SoftwareVersion   string         `json:"software_version"`
	TestName          string         `json:"test_name"`
	TestStartTime     string         `json:"test_start_time"`
	TestKeys          OONITestKeys   `json:"test_keys"`
	Annotations       map[string]any `json:"annotations"`
}

// OONITestKeys carries Lumra's interference conclusion in the test_keys slot.
type OONITestKeys struct {
	// Blocking mirrors OONI's convention: false when no interference, otherwise
	// a short mechanism label (e.g. "dns", "tcp_ip", "tls", "http-diff").
	Blocking         any                 `json:"blocking"`
	Accessible       bool                `json:"accessible"`
	InterferenceType verdict.Type        `json:"interference_type"`
	Nature           verdict.Nature      `json:"nature"`
	Attribution      verdict.Attribution `json:"attribution,omitempty"`
	Authority        string              `json:"authority,omitempty"`
	Confidence       verdict.Confidence  `json:"confidence"`
	Cause            string              `json:"cause"`
	Evidence         []verdict.Evidence  `json:"evidence"`
}

// ooniBlocking maps an interference Type onto OONI's coarse blocking label.
func ooniBlocking(t verdict.Type) any {
	switch t {
	case verdict.OK:
		return false
	case verdict.DNSTampering:
		return "dns"
	case verdict.IPBlocking, verdict.RSTInjection:
		return "tcp_ip"
	case verdict.SNIFiltering, verdict.TLSMITM, verdict.TLSDowngrade:
		return "tls"
	case verdict.BlockPage:
		return "http-diff"
	case verdict.Throttling:
		return "throttling"
	default:
		return false
	}
}

// OONI renders a verdict as an OONI-style measurement. reportID ties the record
// to its signed bundle (use the bundle digest) so the two can be cross-checked.
func OONI(v *verdict.Verdict, at time.Time, softwareVersion, reportID string) *OONIMeasurement {
	ts := at.UTC().Format("2006-01-02 15:04:05")
	return &OONIMeasurement{
		DataFormatVersion: ooniFormatVersion,
		Input:             v.Target,
		MeasurementStart:  ts,
		ReportID:          reportID,
		SoftwareName:      "lumra",
		SoftwareVersion:   softwareVersion,
		TestName:          "lumra_interference",
		TestStartTime:     ts,
		TestKeys: OONITestKeys{
			Blocking:         ooniBlocking(v.Type),
			Accessible:       v.Type == verdict.OK,
			InterferenceType: v.Type,
			Nature:           v.Nature,
			Attribution:      v.Attribution,
			Authority:        v.Authority,
			Confidence:       v.Confidence,
			Cause:            v.Cause,
			Evidence:         v.Evidence,
		},
		Annotations: map[string]any{
			"engine":              "lumra",
			"measured_not_listed": true,
		},
	}
}

// Encode serializes an OONI measurement to indented JSON.
func (m *OONIMeasurement) Encode() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}
