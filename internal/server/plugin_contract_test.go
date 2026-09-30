package server_test

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestStatusAndEchoExecutableContract(t *testing.T) {
	for _, tc := range []struct {
		id, action string
		input      map[string]string
		want       string
	}{
		{"status", "status.get", map[string]string{"agent": "agent-1"}, "agent=agent-1"},
		{"echo", "echo.repeat", map[string]string{"text": "hello"}, "hello"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), tc.id)
			build := exec.Command("go", "build", "-o", binary, "../../examples/"+tc.id)
			if output, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build: %s: %v", output, err)
			}
			request, _ := json.Marshal(map[string]any{"api_version": 1, "action": tc.action, "command_id": "command-123", "input": tc.input})
			run := exec.Command(binary)
			run.Stdin = bytes.NewReader(request)
			raw, err := run.Output()
			if err != nil {
				t.Fatal(err)
			}
			var response struct {
				CommandID string `json:"command_id"`
				Output    struct {
					Text string `json:"text"`
				} `json:"output"`
				Error string `json:"error"`
			}
			if err := json.Unmarshal(raw, &response); err != nil {
				t.Fatal(err)
			}
			if response.CommandID != "command-123" || response.Error != "" || !bytes.Contains([]byte(response.Output.Text), []byte(tc.want)) {
				t.Fatalf("unexpected result: %s", raw)
			}
		})
	}
}
