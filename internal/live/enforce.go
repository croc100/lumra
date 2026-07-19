package live

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Resolver returns tamper-resistant ground-truth addresses for a domain.
// probe.ResolveDoH satisfies it; tests inject a fake.
type Resolver func(ctx context.Context, domain string) ([]string, error)

// Enforcer turns the declarative control levers into a real, applied effect —
// the automatic "control your internet" step. Today it enforces one lever:
// ActionUseDoH. When a domain is diagnosed as DNS-tampered, the Enforcer
// re-resolves it over DoH and writes the verified address into a Lumra-managed
// hosts-format override file, so the correct mapping actually takes hold instead
// of merely being recommended. The file is Lumra's own; pointing the system at
// it (or having warren consume it) is a separate, user-controlled step, keeping
// Lumra from silently rerouting traffic.
type Enforcer struct {
	dir     string
	resolve Resolver

	mu        sync.Mutex
	overrides map[string][]string // domain -> verified IPs
}

// NewEnforcer builds an Enforcer writing to dir (created on first write).
func NewEnforcer(dir string, r Resolver) *Enforcer {
	return &Enforcer{dir: dir, resolve: r, overrides: make(map[string][]string)}
}

// DefaultDir is the Lumra-managed directory for enforcement artifacts.
func DefaultDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".lumra")
	}
	return ".lumra"
}

// HostsPath is the managed override file the Enforcer maintains.
func (e *Enforcer) HostsPath() string { return filepath.Join(e.dir, "hosts") }

// Enforce applies action for domain and returns a short human-readable summary
// of what was done, or ok=false when the action has no enforcement step. Only
// ActionUseDoH is enforced today; the others remain advisory.
func (e *Enforcer) Enforce(ctx context.Context, domain string, action Action) (string, bool) {
	if action != ActionUseDoH {
		return "", false
	}
	ips, err := e.resolve(ctx, domain)
	if err != nil || len(ips) == 0 {
		return "DoH re-resolve failed; override not written", false
	}
	e.mu.Lock()
	e.overrides[domain] = ips
	snapshot := e.render()
	e.mu.Unlock()

	if err := e.write(snapshot); err != nil {
		return "override write failed: " + err.Error(), false
	}
	return fmt.Sprintf("→ %s (DoH override written to %s)", ips[0], e.HostsPath()), true
}

// render builds the managed hosts-file body from the current overrides. Caller
// holds the lock.
func (e *Enforcer) render() string {
	domains := make([]string, 0, len(e.overrides))
	for d := range e.overrides {
		domains = append(domains, d)
	}
	sort.Strings(domains)

	var b strings.Builder
	b.WriteString("# Managed by lumra live — DoH-verified overrides for tampered domains.\n")
	b.WriteString("# Regenerated automatically; do not edit by hand.\n")
	fmt.Fprintf(&b, "# updated %s\n", time.Now().UTC().Format(time.RFC3339))
	for _, d := range domains {
		// One host line per domain, using the first verified address.
		fmt.Fprintf(&b, "%s\t%s\n", e.overrides[d][0], d)
	}
	return b.String()
}

// write atomically replaces the managed hosts file so a reader never sees a
// half-written file.
func (e *Enforcer) write(body string) error {
	if err := os.MkdirAll(e.dir, 0o755); err != nil {
		return err
	}
	tmp := e.HostsPath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, e.HostsPath())
}
