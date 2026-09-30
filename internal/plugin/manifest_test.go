package plugin

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func signedFixtureWithKey(t *testing.T) (Manifest, map[string]ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{ManifestVersion: 1, PluginID: "echo", Version: "1.0.0", APIVersion: 1, PublisherKeyID: "test-key", Artifacts: []Artifact{{OS: "linux", Arch: "amd64", Format: "elf", Size: 10, SHA256: strings.Repeat("a", 64)}}, Actions: []Action{{Name: "echo.repeat", InputSchema: json.RawMessage(`{"type":"object","required":["text"],"properties":{"text":{"type":"string"}},"additionalProperties":false}`), OutputSchema: json.RawMessage(`{"type":"object","required":["text"],"properties":{"text":{"type":"string"}},"additionalProperties":false}`), TimeoutSeconds: 5, MaxResultBytes: 1024, ReadOnly: true}}}
	if err := m.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return m, map[string]ed25519.PublicKey{"test-key": pub}, priv
}
func signedFixture(t *testing.T) (Manifest, map[string]ed25519.PublicKey) {
	m, keys, _ := signedFixtureWithKey(t)
	return m, keys
}
func TestManifestTrustAndPolicy(t *testing.T) {
	m, keys, priv := signedFixtureWithKey(t)
	if err := m.Verify(keys, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Manifest){
		"tampered artifact":        func(m *Manifest) { m.Artifacts[0].SHA256 = strings.Repeat("b", 64) },
		"unsupported API":          func(m *Manifest) { m.APIVersion = 2 },
		"duplicate action":         func(m *Manifest) { m.Actions = append(m.Actions, m.Actions[0]) },
		"invalid schema":           func(m *Manifest) { m.Actions[0].InputSchema = json.RawMessage(`{"type":"nonesuch"}`) },
		"capability beyond policy": func(m *Manifest) { m.Capabilities.Network = []string{"example.org:443"} },
		"wrong platform":           func(m *Manifest) { m.Artifacts[0].OS = "windows" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			copy := m
			copy.Artifacts = append([]Artifact(nil), m.Artifacts...)
			copy.Actions = append([]Action(nil), m.Actions...)
			mutate(&copy)
			expected := map[string]string{"tampered artifact": "invalid publisher signature", "unsupported API": "unsupported manifest", "duplicate action": "invalid action", "invalid schema": "input schema", "capability beyond policy": "network capability denied", "wrong platform": "unsupported artifact"}[name]
			if name != "tampered artifact" {
				if err := copy.Sign(priv); err != nil {
					t.Fatal(err)
				}
			}
			if err := copy.Verify(keys, nil, nil, nil); err == nil || !strings.Contains(err.Error(), expected) {
				t.Fatalf("wanted %q, got %v", expected, err)
			}
		})
	}
	if err := m.Verify(keys, map[string]bool{"test-key": true}, nil, nil); err == nil {
		t.Fatal("accepted revoked key")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(keys, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
}
