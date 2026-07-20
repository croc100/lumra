package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// keyDir is the Lumra-managed directory holding the signing identity.
func keyDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".lumra", "keys"), nil
}

const privName = "signing_ed25519"

// LoadOrCreateKey returns the host's persistent Ed25519 signing key, generating
// and storing one on first use. The private key lives in ~/.lumra/keys with
// 0600 permissions; it is the machine's stable identity across bundles so that
// a series of measurements can be tied to the same prober.
func LoadOrCreateKey() (ed25519.PrivateKey, error) {
	dir, err := keyDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, privName)
	if data, err := os.ReadFile(path); err == nil {
		return parsePrivate(data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	enc := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(path, []byte(enc+"\n"), 0o600); err != nil {
		return nil, err
	}
	// Store the public key alongside for easy out-of-band sharing/pinning.
	pubEnc := base64.StdEncoding.EncodeToString(pub)
	_ = os.WriteFile(path+".pub", []byte(KeyID(pub)+" "+pubEnc+"\n"), 0o644)
	return priv, nil
}

func parsePrivate(data []byte) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("evidence: decode signing key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("evidence: stored signing key has wrong size")
	}
	return ed25519.PrivateKey(raw), nil
}
