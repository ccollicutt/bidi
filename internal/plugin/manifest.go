// Package plugin defines the signed, language-neutral native plugin contract.
package plugin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const APIVersion = 1
const MaxArtifactSize int64 = 128 << 20

var identifier = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
var version = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Artifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Format string `json:"format"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type Action struct {
	Name           string          `json:"name"`
	Description    string          `json:"description,omitempty"`
	InputSchema    json.RawMessage `json:"input_schema"`
	OutputSchema   json.RawMessage `json:"output_schema"`
	TimeoutSeconds int             `json:"timeout_seconds"`
	MaxResultBytes int             `json:"max_result_bytes"`
	ReadOnly       bool            `json:"read_only"`
}
type Capabilities struct {
	FilesystemRead []string `json:"filesystem_read"`
	Network        []string `json:"network"`
	MemoryBytes    int64    `json:"memory_bytes,omitempty"`
	CPUSeconds     int      `json:"cpu_seconds,omitempty"`
}
type Manifest struct {
	ManifestVersion int          `json:"manifest_version"`
	PluginID        string       `json:"plugin_id"`
	Version         string       `json:"version"`
	APIVersion      int          `json:"api_version"`
	PublisherKeyID  string       `json:"publisher_key_id"`
	Artifacts       []Artifact   `json:"artifacts"`
	Actions         []Action     `json:"actions"`
	Capabilities    Capabilities `json:"capabilities"`
	Signature       string       `json:"signature,omitempty"`
}

// CanonicalBytes is the compact JSON encoding of the typed manifest with signature omitted.
// Struct field order is fixed; encoding/json sorts all map keys recursively.
func (m Manifest) CanonicalBytes() ([]byte, error) { m.Signature = ""; return json.Marshal(m) }
func (m *Manifest) Sign(key ed25519.PrivateKey) error {
	b, e := m.CanonicalBytes()
	if e != nil {
		return e
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))
	return nil
}
func Parse(raw []byte) (Manifest, error) {
	var m Manifest
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return m, errors.New("trailing or invalid JSON")
	}
	return m, nil
}
func (m Manifest) Verify(keys map[string]ed25519.PublicKey, revoked map[string]bool, allowedPaths []string, allowedNetwork []string) error {
	if m.ManifestVersion != 1 || m.APIVersion != APIVersion {
		return errors.New("unsupported manifest or plugin API version")
	}
	if !identifier.MatchString(m.PluginID) || !version.MatchString(m.Version) || !identifier.MatchString(m.PublisherKeyID) {
		return errors.New("invalid plugin identity, version, or publisher")
	}
	key := keys[m.PublisherKeyID]
	if len(key) != ed25519.PublicKeySize || revoked[m.PublisherKeyID] {
		return errors.New("untrusted or revoked publisher")
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return errors.New("invalid signature encoding")
	}
	b, err := m.CanonicalBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, b, sig) {
		return errors.New("invalid publisher signature")
	}
	if len(m.Artifacts) == 0 || len(m.Actions) == 0 {
		return errors.New("manifest has no artifact or action")
	}
	seenTargets := map[string]bool{}
	for _, a := range m.Artifacts {
		target := a.OS + "/" + a.Arch
		if seenTargets[target] || a.Size <= 0 || a.Size > MaxArtifactSize || !digest.MatchString(a.SHA256) {
			return errors.New("invalid or duplicate artifact")
		}
		seenTargets[target] = true
		if a.OS != "linux" || (a.Arch != "amd64" && a.Arch != "arm64") || a.Format != "elf" {
			return errors.New("unsupported artifact target or format")
		}
	}
	seenActions := map[string]bool{}
	for _, a := range m.Actions {
		if !strings.HasPrefix(a.Name, m.PluginID+".") || seenActions[a.Name] || a.TimeoutSeconds < 1 || a.TimeoutSeconds > 60 || a.MaxResultBytes < 1 || a.MaxResultBytes > 32768 || !a.ReadOnly {
			return fmt.Errorf("invalid action %q", a.Name)
		}
		seenActions[a.Name] = true
		if _, err := CompileSchema(a.InputSchema); err != nil {
			return fmt.Errorf("input schema %s: %w", a.Name, err)
		}
		if _, err := CompileSchema(a.OutputSchema); err != nil {
			return fmt.Errorf("output schema %s: %w", a.Name, err)
		}
	}
	for _, p := range m.Capabilities.FilesystemRead {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("invalid filesystem capability: %s", p)
		}
		if !contains(allowedPaths, p) {
			return fmt.Errorf("filesystem capability denied: %s", p)
		}
	}
	for _, n := range m.Capabilities.Network {
		if !contains(allowedNetwork, n) {
			return fmt.Errorf("network capability denied: %s", n)
		}
	}
	if m.Capabilities.MemoryBytes < 0 || m.Capabilities.MemoryBytes > 256<<20 || m.Capabilities.CPUSeconds < 0 || m.Capabilities.CPUSeconds > 60 {
		return errors.New("resource capability exceeds ceiling")
	}
	return nil
}
func contains(items []string, v string) bool {
	for _, item := range items {
		if item == v {
			return true
		}
	}
	return false
}
func (m Manifest) ArtifactForLocal() (Artifact, error) {
	return m.ArtifactFor(runtime.GOOS, runtime.GOARCH)
}
func (m Manifest) ArtifactFor(osName, archName string) (Artifact, error) {
	for _, a := range m.Artifacts {
		if a.OS == osName && a.Arch == archName {
			return a, nil
		}
	}
	return Artifact{}, errors.New("no artifact for local platform")
}
func (m Manifest) Action(name string) (Action, bool) {
	for _, a := range m.Actions {
		if a.Name == name {
			return a, true
		}
	}
	return Action{}, false
}
func Hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func CompileSchema(raw json.RawMessage) (*jsonschema.Schema, error) {
	if len(raw) == 0 {
		return nil, errors.New("missing schema")
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, errors.New("schema must be object")
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("schema.json", v); err != nil {
		return nil, err
	}
	return c.Compile("schema.json")
}
