package plugin

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestChunkedInstallResumeAndVerifiedActivation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux plugin test")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binary := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, ChunkSize*2+17)...)
	m := Manifest{ManifestVersion: 1, PluginID: "echo", Version: "1.0.0", APIVersion: 1, PublisherKeyID: "test-key", Artifacts: []Artifact{{OS: runtime.GOOS, Arch: runtime.GOARCH, Format: "elf", Size: int64(len(binary)), SHA256: Hash(binary)}}, Actions: []Action{{Name: "echo.repeat", InputSchema: json.RawMessage(`{"type":"object"}`), OutputSchema: json.RawMessage(`{"type":"object"}`), TimeoutSeconds: 2, MaxResultBytes: 1024, ReadOnly: true}}}
	if err := m.Sign(priv); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(m)
	dir := filepath.Join(t.TempDir(), "plugins")
	policy := Policy{Keys: map[string]ed25519.PublicKey{"test-key": pub}, Plugins: map[string]bool{"echo": true}, Storage: dir}
	manager, err := NewManager(policy)
	if err != nil {
		t.Fatal(err)
	}
	hash, offset, err := manager.Begin(raw)
	if err != nil || offset != 0 {
		t.Fatalf("begin: %s %d %v", hash, offset, err)
	}
	offset, done, err := manager.Chunk(hash, 0, binary[:ChunkSize], false)
	if err != nil || done || offset != ChunkSize {
		t.Fatalf("first chunk: %d %v %v", offset, done, err)
	}
	manager2, err := NewManager(policy)
	if err != nil {
		t.Fatal(err)
	}
	hash, resume, err := manager2.Begin(raw)
	if err != nil || resume != ChunkSize {
		t.Fatalf("resume: %d %v", resume, err)
	}
	for resume < int64(len(binary)) {
		end := resume + ChunkSize
		if end > int64(len(binary)) {
			end = int64(len(binary))
		}
		resume, done, err = manager2.Chunk(hash, resume, binary[resume:end], end == int64(len(binary)))
		if err != nil {
			t.Fatal(err)
		}
	}
	if !done {
		t.Fatal("artifact not installed")
	}
	if got := manager2.Installed()["echo"]; len(got) != 1 || got[0] != "1.0.0" {
		t.Fatalf("installed: %v", got)
	}
	if err := manager2.Activate("echo", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if manager2.Active()["echo"] != "1.0.0" {
		t.Fatal("verified plugin not activated")
	}
	altered := m
	altered.Artifacts = []Artifact{{OS: runtime.GOOS, Arch: runtime.GOARCH, Format: "elf", Size: int64(len(binary)), SHA256: strings.Repeat("a", 64)}}
	_ = altered.Sign(priv)
	alteredRaw, _ := json.Marshal(altered)
	if _, _, err := manager2.Begin(alteredRaw); err == nil {
		t.Fatal("allowed overwrite of immutable version")
	}
	path := filepath.Join(dir, "echo", "1.0.0", "artifact")
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager2.Begin(raw); err == nil {
		t.Fatal("accepted corrupted installed artifact")
	}
}
