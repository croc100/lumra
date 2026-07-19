package live

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestEnforceWritesDoHOverride(t *testing.T) {
	dir := t.TempDir()
	e := NewEnforcer(dir, func(_ context.Context, domain string) ([]string, error) {
		return []string{"93.184.216.34", "93.184.216.35"}, nil
	})

	summary, ok := e.Enforce(context.Background(), "poisoned.example", ActionUseDoH)
	if !ok {
		t.Fatalf("enforce should apply, got summary=%q", summary)
	}
	body, err := os.ReadFile(e.HostsPath())
	if err != nil {
		t.Fatalf("hosts file not written: %v", err)
	}
	line := "93.184.216.34\tpoisoned.example"
	if !strings.Contains(string(body), line) {
		t.Errorf("override missing %q in:\n%s", line, body)
	}
}

func TestEnforceSkipsNonDoHActions(t *testing.T) {
	e := NewEnforcer(t.TempDir(), func(context.Context, string) ([]string, error) {
		t.Fatal("resolver must not be called for a non-DoH action")
		return nil, nil
	})
	for _, a := range []Action{ActionNone, ActionRequire13, ActionCaution, ActionBlocked} {
		if _, ok := e.Enforce(context.Background(), "x", a); ok {
			t.Errorf("action %q should not enforce", a)
		}
	}
}

func TestEnforceResolveFailureNoFile(t *testing.T) {
	dir := t.TempDir()
	e := NewEnforcer(dir, func(context.Context, string) ([]string, error) {
		return nil, errors.New("doh blocked")
	})
	if _, ok := e.Enforce(context.Background(), "x", ActionUseDoH); ok {
		t.Error("resolve failure should not report success")
	}
	if _, err := os.Stat(e.HostsPath()); !os.IsNotExist(err) {
		t.Error("no hosts file should be written on resolve failure")
	}
}

func TestEnforceAccumulatesDomains(t *testing.T) {
	e := NewEnforcer(t.TempDir(), func(_ context.Context, d string) ([]string, error) {
		return []string{"10.0.0.1"}, nil
	})
	e.Enforce(context.Background(), "a.example", ActionUseDoH)
	e.Enforce(context.Background(), "b.example", ActionUseDoH)
	body, _ := os.ReadFile(e.HostsPath())
	if !strings.Contains(string(body), "a.example") || !strings.Contains(string(body), "b.example") {
		t.Errorf("both overrides should persist:\n%s", body)
	}
}
