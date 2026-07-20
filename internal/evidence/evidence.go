// Package evidence turns a Lumra verdict into a signed, tamper-evident
// measurement bundle. A diagnosis is only as useful as it is believable: a
// journalist or court needs to know the evidence was produced at a given time
// and has not been altered since. A bundle carries the measurement, a SHA-256
// digest over its canonical bytes, and an Ed25519 signature over that digest —
// so anyone can recompute the digest and verify the signature against the
// embedded public key, with no trust in Lumra's infrastructure.
//
// Lumra signs what it measured; it never asserts trust. The public key is
// carried in the bundle by fingerprint so a verifier can pin it out of band.
package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

// BundleVersion is the schema version of the signed envelope.
const BundleVersion = "1"

// Measurement is the exact content that gets signed. It is serialized with
// deterministic field order (struct order is stable in encoding/json) and the
// resulting bytes are preserved verbatim in the bundle as a RawMessage, so the
// digest and signature always cover the identical bytes that were signed.
type Measurement struct {
	Bundle      string           `json:"bundle_version"`
	Tool        string           `json:"tool"`
	ToolVersion string           `json:"tool_version"`
	MeasuredAt  string           `json:"measured_at"` // RFC3339, UTC
	Target      string           `json:"target"`
	Verdict     *verdict.Verdict `json:"verdict"`
}

// Signature is the detached Ed25519 signature over the canonical measurement.
type Signature struct {
	Alg       string `json:"alg"`        // "ed25519"
	PublicKey string `json:"public_key"` // base64 raw public key
	KeyID     string `json:"key_id"`     // short SHA-256 fingerprint of the public key
	Value     string `json:"value"`      // base64 signature over the canonical measurement bytes
}

// Bundle is the complete signed envelope. Measurement is stored as raw bytes so
// a round-trip through JSON never perturbs what the signature covers.
type Bundle struct {
	Measurement json.RawMessage `json:"measurement"`
	Digest      string          `json:"digest"` // "sha256:<hex>" over Measurement
	Signature   Signature       `json:"signature"`
}

// KeyID returns the short fingerprint used to identify a public key in a bundle.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + hex.EncodeToString(sum[:])[:16]
}

// Sign produces a signed bundle for v, measured at the given time, with the
// supplied tool version string. The private key signs the canonical measurement
// bytes directly (Ed25519 hashes internally); the digest is carried for a quick
// human tamper-check independent of the signature.
func Sign(v *verdict.Verdict, at time.Time, toolVersion string, priv ed25519.PrivateKey) (*Bundle, error) {
	if v == nil {
		return nil, errors.New("evidence: nil verdict")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("evidence: invalid private key")
	}
	m := Measurement{
		Bundle:      BundleVersion,
		Tool:        "lumra",
		ToolVersion: toolVersion,
		MeasuredAt:  at.UTC().Format(time.RFC3339),
		Target:      v.Target,
		Verdict:     v,
	}
	canonical, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("evidence: marshal measurement: %w", err)
	}
	sum := sha256.Sum256(canonical)
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, canonical)
	return &Bundle{
		Measurement: canonical,
		Digest:      "sha256:" + hex.EncodeToString(sum[:]),
		Signature: Signature{
			Alg:       "ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(pub),
			KeyID:     KeyID(pub),
			Value:     base64.StdEncoding.EncodeToString(sig),
		},
	}, nil
}

// Verify recomputes the digest and checks the signature against the public key
// embedded in the bundle. It returns the trusted public key on success so the
// caller can pin or display its fingerprint. A valid signature proves the
// measurement bytes are exactly what the key's holder signed — the caller still
// decides whether to trust that key.
func Verify(b *Bundle) (ed25519.PublicKey, error) {
	if b == nil {
		return nil, errors.New("evidence: nil bundle")
	}
	if b.Signature.Alg != "ed25519" {
		return nil, fmt.Errorf("evidence: unsupported signature alg %q", b.Signature.Alg)
	}
	pub, err := base64.StdEncoding.DecodeString(b.Signature.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("evidence: invalid public key")
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature.Value)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("evidence: invalid signature encoding")
	}
	// Re-derive the canonical measurement bytes from the parsed struct rather
	// than trusting the stored formatting: indented JSON in the bundle file is
	// not byte-identical to what was signed, but the struct round-trips
	// deterministically, so canonical(measurement) reproduces the signed bytes.
	canonical, err := canonicalMeasurement(b.Measurement)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	if want := "sha256:" + hex.EncodeToString(sum[:]); want != b.Digest {
		return nil, fmt.Errorf("evidence: digest mismatch — measurement was altered")
	}
	if KeyID(pub) != b.Signature.KeyID {
		return nil, errors.New("evidence: key_id does not match public key")
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return nil, errors.New("evidence: signature does not verify — bundle is not authentic")
	}
	return ed25519.PublicKey(pub), nil
}

// Decode parses a serialized bundle.
func Decode(data []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("evidence: decode bundle: %w", err)
	}
	return &b, nil
}

// Encode serializes a bundle to indented JSON.
func (b *Bundle) Encode() ([]byte, error) {
	return json.MarshalIndent(b, "", "  ")
}

// CanonicalMeasurement returns the exact bytes Sign covered for this bundle —
// the verbatim signed message — regardless of how the bundle's measurement was
// later reformatted (e.g. indented on disk). Callers pushing a bundle to a
// verifier that checks the signature over raw bytes must transmit these bytes.
func (b *Bundle) CanonicalMeasurement() ([]byte, error) {
	return canonicalMeasurement(b.Measurement)
}

// canonicalMeasurement reproduces the exact bytes that Sign covers, by parsing
// the (possibly reformatted) measurement JSON back into the struct and
// re-marshaling it with deterministic field order.
func canonicalMeasurement(raw json.RawMessage) ([]byte, error) {
	var m Measurement
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("evidence: parse measurement: %w", err)
	}
	return json.Marshal(m)
}

// ParseMeasurement returns the typed measurement carried in the bundle.
func (b *Bundle) ParseMeasurement() (*Measurement, error) {
	var m Measurement
	if err := json.Unmarshal(b.Measurement, &m); err != nil {
		return nil, fmt.Errorf("evidence: parse measurement: %w", err)
	}
	return &m, nil
}
