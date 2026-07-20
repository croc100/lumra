package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

func sampleVerdict() *verdict.Verdict {
	v := &verdict.Verdict{
		Target:      "example.com",
		Type:        verdict.DNSTampering,
		Nature:      verdict.NatureControl,
		Confidence:  verdict.High,
		Attribution: verdict.AttrSelfIdentified,
		Authority:   "KCSC",
		Cause:       "DNS answer replaced with a sinkhole address.",
	}
	v.Add("DNS", verdict.Fail, "answer 0.0.0.0 is a sinkhole")
	v.Add("TLS", verdict.Info, "not reached")
	return v
}

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := mustKey(t)
	at := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)

	b, err := Sign(sampleVerdict(), at, "1.2.3", priv)
	if err != nil {
		t.Fatal(err)
	}
	// Serialize and decode to exercise the RawMessage round-trip.
	data, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := Verify(got)
	if err != nil {
		t.Fatalf("verify failed on untampered bundle: %v", err)
	}
	if !pub.Equal(priv.Public()) {
		t.Fatal("verified public key does not match signer")
	}

	m, err := got.ParseMeasurement()
	if err != nil {
		t.Fatal(err)
	}
	if m.Target != "example.com" || m.ToolVersion != "1.2.3" {
		t.Fatalf("measurement fields wrong: %+v", m)
	}
	if m.MeasuredAt != "2026-07-20T10:00:00Z" {
		t.Fatalf("measured_at = %q", m.MeasuredAt)
	}
}

func TestVerifyDetectsTamperedMeasurement(t *testing.T) {
	priv := mustKey(t)
	b, err := Sign(sampleVerdict(), time.Now(), "1.0.0", priv)
	if err != nil {
		t.Fatal(err)
	}
	// Flip the verdict inside the signed measurement bytes.
	tampered := strings.Replace(string(b.Measurement), "DNS_TAMPERING", "OK", 1)
	if tampered == string(b.Measurement) {
		t.Fatal("test setup: substitution did not change bytes")
	}
	b.Measurement = json.RawMessage(tampered)

	if _, err := Verify(b); err == nil {
		t.Fatal("verify accepted a tampered measurement")
	}
}

func TestVerifyDetectsWrongKey(t *testing.T) {
	b, err := Sign(sampleVerdict(), time.Now(), "1.0.0", mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	// Swap in a different public key (and matching key_id) — signature must fail.
	otherPub := mustKey(t).Public().(ed25519.PublicKey)
	b.Signature.PublicKey = base64.StdEncoding.EncodeToString(otherPub)
	b.Signature.KeyID = KeyID(otherPub)

	if _, err := Verify(b); err == nil {
		t.Fatal("verify accepted a bundle re-signed to a foreign key")
	}
}

func TestVerifyDetectsDigestMismatch(t *testing.T) {
	b, err := Sign(sampleVerdict(), time.Now(), "1.0.0", mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	b.Digest = "sha256:deadbeef"
	if _, err := Verify(b); err == nil {
		t.Fatal("verify accepted a bundle with a wrong digest")
	}
}

func TestOONIExport(t *testing.T) {
	v := sampleVerdict()
	m := OONI(v, time.Now(), "1.0.0", "sha256:abc")
	if m.TestKeys.Blocking != "dns" {
		t.Fatalf("blocking = %v, want dns", m.TestKeys.Blocking)
	}
	if m.TestKeys.Accessible {
		t.Fatal("accessible should be false for tampering")
	}
	if m.ProbeCC != "" || m.ProbeASN != "" {
		t.Fatal("prober geo fields must stay empty (privacy)")
	}
	data, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatal("OONI output is not valid JSON")
	}

	// A clean verdict reports blocking:false, accessible:true.
	ok := &verdict.Verdict{Target: "example.com", Type: verdict.OK, Nature: verdict.NatureNone}
	om := OONI(ok, time.Now(), "1.0.0", "x")
	if om.TestKeys.Blocking != false || !om.TestKeys.Accessible {
		t.Fatalf("clean verdict mismapped: blocking=%v accessible=%v", om.TestKeys.Blocking, om.TestKeys.Accessible)
	}
}
