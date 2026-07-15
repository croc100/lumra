package nativemsg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// HostName is the native-messaging host id the extension connects to.
const HostName = "net.crode.lumra"

// hostManifest is the JSON structure Chrome expects at the host location.
type hostManifest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Path           string   `json:"path"`
	Type           string   `json:"type"`
	AllowedOrigins []string `json:"allowed_origins"`
}

// InstallHost writes the native-messaging host manifest so Chrome can launch
// this binary as the Lumra core for the given extension ID. It points the
// manifest at the currently running executable.
func InstallHost(extensionID string) (string, error) {
	if extensionID == "" {
		return "", fmt.Errorf("extension id required (see chrome://extensions)")
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, _ = filepath.EvalSymlinks(exe)

	dir, err := chromeHostDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	m := hostManifest{
		Name:           HostName,
		Description:    "Lumra native diagnosis core",
		Path:           exe,
		Type:           "stdio",
		AllowedOrigins: []string{fmt.Sprintf("chrome-extension://%s/", extensionID)},
	}
	data, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, HostName+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// chromeHostDir returns Chrome's per-user NativeMessagingHosts directory.
func chromeHostDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "NativeMessagingHosts"), nil
	case "linux":
		return filepath.Join(home, ".config", "google-chrome", "NativeMessagingHosts"), nil
	case "windows":
		return "", fmt.Errorf("on Windows, register the host under HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\%s — see extension/host/README.md", HostName)
	default:
		return "", fmt.Errorf("unsupported OS %q", runtime.GOOS)
	}
}
