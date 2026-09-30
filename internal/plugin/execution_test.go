package plugin

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExecutionFailureBoundsAndSchemas(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	code := `package main
import("encoding/json";"os";"time")
func main(){var r struct {CommandID string ` + "`json:\"command_id\"`" + `; Input struct {Mode string ` + "`json:\"mode\"`" + `}}; json.NewDecoder(os.Stdin).Decode(&r)
switch r.Input.Mode {case "timeout":time.Sleep(10*time.Second);case "crash":os.Exit(2);case "oversize":os.Stdout.Write(make([]byte,4096));case "bad-output":json.NewEncoder(os.Stdout).Encode(map[string]any{"command_id":r.CommandID,"output":"wrong"});default:json.NewEncoder(os.Stdout).Encode(map[string]any{"command_id":r.CommandID,"output":map[string]any{}})}}`
	if err := os.WriteFile(source, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "fixture")
	if out, err := exec.Command("go", "build", "-o", binary, source).CombinedOutput(); err != nil {
		t.Fatalf("build: %s %v", out, err)
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	manifest, keys, priv := signedFixtureWithKey(t)
	manifest.Artifacts = []Artifact{{OS: runtime.GOOS, Arch: runtime.GOARCH, Format: "elf", Size: int64(len(data)), SHA256: Hash(data)}}
	manifest.Actions[0].InputSchema = json.RawMessage(`{"type":"object","required":["mode"],"properties":{"mode":{"type":"string"}},"additionalProperties":false}`)
	manifest.Actions[0].OutputSchema = json.RawMessage(`{"type":"object"}`)
	manifest.Actions[0].TimeoutSeconds = 1
	if err := manifest.Sign(priv); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(manifest)
	manager, err := NewManager(Policy{Keys: keys, Plugins: map[string]bool{"echo": true}, Storage: filepath.Join(dir, "plugins")})
	if err != nil {
		t.Fatal(err)
	}
	hash, _, err := manager.Begin(raw)
	if err != nil {
		t.Fatal(err)
	}
	for offset := 0; offset < len(data); {
		end := offset + ChunkSize
		if end > len(data) {
			end = len(data)
		}
		if _, _, err := manager.Chunk(hash, int64(offset), data[offset:end], end == len(data)); err != nil {
			t.Fatal(err)
		}
		offset = end
	}
	if err := manager.Activate("echo", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, action, input, want string }{
		{"timeout", "echo.repeat", `{"mode":"timeout"}`, "plugin timed out"},
		{"crash", "echo.repeat", `{"mode":"crash"}`, "plugin failed"},
		{"oversize", "echo.repeat", `{"mode":"oversize"}`, "plugin output exceeds limit"},
		{"output schema", "echo.repeat", `{"mode":"bad-output"}`, "output schema rejected result"},
		{"input schema", "echo.repeat", `{}`, "input schema rejected request"},
		{"undeclared action", "echo.absent", `{}`, "action absent from verified manifest"},
		{"healthy after failures", "echo.repeat", `{"mode":"ok"}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, got := manager.Execute(context.Background(), "echo", tc.action, "command", json.RawMessage(tc.input))
			if got != tc.want {
				t.Fatalf("wanted %q got %q", tc.want, got)
			}
		})
	}
	// A crash after the last chunk is durable but before publication must recover.
	manifest.Version = "2.0.0"
	if err := manifest.Sign(priv); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(manifest)
	if err := os.WriteFile(manager.partPath(hash), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, offset, err := manager.Begin(raw); err != nil || offset != int64(len(data)) {
		t.Fatalf("completed partial recovery: %d %v", offset, err)
	}
	if err := manager.Activate("echo", "2.0.0"); err != nil {
		t.Fatal(err)
	}
}
