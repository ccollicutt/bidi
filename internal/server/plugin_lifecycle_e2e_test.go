package server_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ccollicutt/bidi/internal/client"
	"github.com/ccollicutt/bidi/internal/plugin"
	"github.com/ccollicutt/bidi/internal/server"
)

func TestExamplePluginsLifecycleOverMTLS(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native executable tests currently target Linux")
	}
	ca, serverCert, serverKey, agentCert, agentKey := testCertificates(t)
	healthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer healthServer.Close()
	serviceAddress := strings.TrimPrefix(healthServer.URL, "http://")
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]map[string]string, 0, 2)
	for _, id := range []string{"status", "echo", "host-facts", "disk-usage", "service-health", "uptime"} {
		binary := filepath.Join(dir, id)
		var cmd *exec.Cmd
		if id == "host-facts" {
			cmd = exec.Command("gcc", "-O2", "-o", binary, "../../examples/host-facts/main.c")
		} else {
			cmd = exec.Command("go", "build", "-o", binary, "../../examples/"+id)
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %s: %v", id, out, err)
		}
		data, err := os.ReadFile(binary)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "manifests", id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		m, err := plugin.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		m.PublisherKeyID = "test-key"
		if id == "service-health" {
			m.Capabilities.Network = []string{serviceAddress}
		}
		m.Artifacts = []plugin.Artifact{{OS: runtime.GOOS, Arch: runtime.GOARCH, Format: "elf", Size: int64(len(data)), SHA256: plugin.Hash(data)}}
		if err := m.Sign(priv); err != nil {
			t.Fatal(err)
		}
		signed, _ := json.Marshal(m)
		manifestPath := filepath.Join(dir, id+".json")
		if err := os.WriteFile(manifestPath, signed, 0600); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, map[string]string{"manifest": manifestPath, "artifact": binary})
	}
	for _, releaseVersion := range []string{"2.0.0", "3.0.0"} {
		raw, err := os.ReadFile(filepath.Join(dir, "echo.json"))
		if err != nil {
			t.Fatal(err)
		}
		m, err := plugin.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		m.Version = releaseVersion
		if err := m.Sign(priv); err != nil {
			t.Fatal(err)
		}
		if releaseVersion == "3.0.0" {
			m.Signature = "invalid"
		}
		signed, _ := json.Marshal(m)
		path := filepath.Join(dir, "echo-"+releaseVersion+".json")
		if err := os.WriteFile(path, signed, 0600); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, map[string]string{"manifest": path, "artifact": filepath.Join(dir, "echo")})
	}
	versions := map[string]string{"status": "1.0.0", "echo": "1.0.0", "host-facts": "1.0.0", "disk-usage": "1.0.0", "service-health": "1.0.0"}
	catalog := map[string]any{"releases": entries, "desired": map[string]any{"agent-1": versions}, "active": map[string]any{"agent-1": versions}}
	catalogRaw, _ := json.Marshal(catalog)
	catalogPath := filepath.Join(dir, "catalog.json")
	if err := os.WriteFile(catalogPath, catalogRaw, 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var serverLog, auditLog, clientLog safeLog
	s := server.New(server.Config{Address: addr, CAFile: ca, CertFile: serverCert, KeyFile: serverKey, CatalogPath: catalogPath, Permissions: map[string][]string{"agent-1": {"status", "echo", "host-facts.snapshot", "disk-usage.measure", "service-health.check", "uptime.get"}}, Logger: log.New(&serverLog, "", 0), Audit: log.New(&auditLog, "", 0)})
	serverDone := make(chan error, 1)
	go func() { serverDone <- s.Run(ctx) }()
	waitFor(t, "server listener", func() bool { return strings.Contains(serverLog.String(), "listening on") })
	manager, err := plugin.NewManager(plugin.Policy{Keys: map[string]ed25519.PublicKey{"test-key": pub}, Plugins: map[string]bool{"status": true, "echo": true, "host-facts": true, "disk-usage": true, "service-health": true, "uptime": true}, FilesystemRead: []string{"/tmp"}, Network: []string{serviceAddress}, Services: map[string]plugin.ServiceTarget{"local-http": {Address: serviceAddress, Path: "/health"}}, Storage: filepath.Join(dir, "plugins")})
	if err != nil {
		t.Fatal(err)
	}
	clientDone := make(chan error, 1)
	go func() {
		clientDone <- client.Run(ctx, client.Config{Address: addr, CAFile: ca, CertFile: agentCert, KeyFile: agentKey, Name: "agent-1", Plugins: manager, Logger: log.New(&clientLog, "", 0)})
	}()
	defer func() {
		if t.Failed() {
			t.Logf("server: %s\nclient: %s\naudit: %s", serverLog.String(), clientLog.String(), auditLog.String())
		}
	}()
	waitForPluginInstall(t, "five active plugins", func() bool { return len(manager.Active()) == 5 })
	waitFor(t, "server activation results", func() bool { return strings.Count(auditLog.String(), `"event":"plugin_activate_result"`) == 5 })
	for _, id := range []string{"status", "echo", "host-facts", "disk-usage", "service-health"} {
		if !strings.Contains(clientLog.String(), "installed plugin: "+id+" 1.0.0") || !strings.Contains(clientLog.String(), "activated plugin: "+id+" 1.0.0") {
			t.Fatalf("missing lifecycle logs for %s: %s", id, clientLog.String())
		}
	}
	statusID, err := s.Send("agent-1", "status", "")
	if err != nil {
		t.Fatal(err)
	}
	echoID, err := s.Send("agent-1", "echo", "hello plugin")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "status result", func() bool {
		return strings.Contains(auditLog.String(), `"id":"`+statusID+`"`) && strings.Contains(serverLog.String(), "agent=agent-1 os="+runtime.GOOS)
	})
	waitFor(t, "echo result", func() bool {
		return strings.Contains(auditLog.String(), `"id":"`+echoID+`"`) && strings.Contains(serverLog.String(), "hello plugin")
	})
	if len(s.Agents()) != 1 {
		t.Fatal("agent disconnected")
	}
	hostID, err := s.Send("agent-1", "host-facts.snapshot", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	diskID, err := s.Send("agent-1", "disk-usage.measure", `{"path":"/tmp"}`)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "host facts result", func() bool {
		return strings.Contains(auditLog.String(), `"id":"`+hostID+`"`) && strings.Contains(serverLog.String(), "hostname")
	})
	waitFor(t, "disk usage result", func() bool {
		return strings.Contains(auditLog.String(), `"id":"`+diskID+`"`) && strings.Contains(serverLog.String(), "total_bytes")
	})
	healthID, err := s.Send("agent-1", "service-health.check", `{"service_id":"local-http"}`)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "service health result", func() bool {
		return strings.Contains(auditLog.String(), `"id":"`+healthID+`"`) && strings.Contains(serverLog.String(), `"status":204`)
	})
	if err := s.SetDesired("agent-1", "echo", "2.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate("agent-1", "echo", "2.0.0"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "echo update", func() bool {
		return manager.Active()["echo"] == "2.0.0" && strings.Contains(auditLog.String(), `"plugin_version":"2.0.0"`)
	})
	if err := s.SetDesired("agent-1", "echo", "3.0.0"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "invalid signature rejection", func() bool {
		return strings.Contains(auditLog.String(), `"plugin_version":"3.0.0"`) && strings.Contains(auditLog.String(), "invalid signature")
	})
	if manager.Active()["echo"] != "2.0.0" {
		t.Fatal("failed update changed active version")
	}
	if err := s.Rollback("agent-1", "echo"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "echo rollback", func() bool {
		return manager.Active()["echo"] == "1.0.0" && strings.Contains(auditLog.String(), `"event":"plugin_rollback_result"`)
	})
	if err := s.SetDesired("agent-1", "uptime", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate("agent-1", "uptime", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "new plugin activation", func() bool {
		return manager.Active()["uptime"] == "1.0.0" && strings.Count(auditLog.String(), `"event":"plugin_activate_result"`) == 7
	})
	controlPath := filepath.Join(dir, "control.sock")
	listenerControl, err := s.ListenControl(ctx, controlPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listenerControl.Close()
	info, err := os.Stat(controlPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("operator socket permissions: %v %v", info, err)
	}
	controlConn, err := net.Dial("unix", controlPath)
	if err != nil {
		t.Fatal(err)
	}
	defer controlConn.Close()
	_ = controlConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(controlConn).Encode(server.ControlRequest{Operation: "run", Agent: "agent-1", Action: "uptime"}); err != nil {
		t.Fatal(err)
	}
	var controlResult server.ControlResult
	if err := json.NewDecoder(controlConn).Decode(&controlResult); err != nil {
		t.Fatal(err)
	}
	if controlResult.Error != "" || controlResult.ID == "" {
		t.Fatalf("operator result: %+v", controlResult)
	}
	waitFor(t, "new plugin result", func() bool {
		return strings.Contains(serverLog.String(), "result "+controlResult.ID) && strings.Contains(serverLog.String(), "uptime_seconds")
	})
	if err := s.SetDesired("agent-1", "status", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "installed version reuse log", func() bool {
		return strings.Contains(clientLog.String(), "plugin already installed: status 1.0.0") && strings.Contains(clientLog.String(), "plugin already active: status 1.0.0")
	})
	if strings.Count(clientLog.String(), "installed plugin: status 1.0.0") != 1 {
		t.Fatal("reused plugin logged as a new installation")
	}
	listConn, err := net.Dial("unix", controlPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listConn.Close()
	_ = listConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(listConn).Encode(server.ControlRequest{Operation: "plugins", Agent: "agent-1"}); err != nil {
		t.Fatal(err)
	}
	var inventory server.ControlResult
	if err := json.NewDecoder(listConn).Decode(&inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.Error != "" || len(inventory.Plugins) != 7 {
		t.Fatalf("plugin list: %+v", inventory)
	}
	foundActive, foundsPrevious := false, false
	for _, p := range inventory.Plugins {
		if p.PluginID == "echo" && p.Version == "1.0.0" && p.Active && p.Desired {
			foundActive = true
		}
		if p.PluginID == "echo" && p.Version == "2.0.0" && !p.Active && !p.Desired {
			foundsPrevious = true
		}
	}
	if !foundActive || !foundsPrevious {
		t.Fatalf("plugin list lost active or previous versions: %+v", inventory.Plugins)
	}
	cancel()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
	select {
	case err := <-clientDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client did not stop")
	}
}

func waitForPluginInstall(t *testing.T, description string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}
