package server_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"crypto/tls"
	"crypto/x509"
	"github.com/ccollicutt/bidi/internal/client"
	"github.com/ccollicutt/bidi/internal/plugin"
	"github.com/ccollicutt/bidi/internal/server"
	"github.com/ccollicutt/bidi/internal/wire"
)

func TestTransferDisconnectResumeAndDifferentAgentVersions(t *testing.T) {
	ca, cert, key, agentCert, agentKey := testCertificates(t)
	dir := t.TempDir()
	binary := filepath.Join(dir, "echo")
	if out, err := exec.Command("go", "build", "-o", binary, "../../examples/echo").CombinedOutput(); err != nil {
		t.Fatalf("build: %s %v", out, err)
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	releases := []map[string]string{}
	for _, v := range []string{"1.0.0", "2.0.0"} {
		raw, err := os.ReadFile("../../examples/manifests/echo.json")
		if err != nil {
			t.Fatal(err)
		}
		m, err := plugin.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		m.Version = v
		m.PublisherKeyID = "test-key"
		m.Artifacts = []plugin.Artifact{{OS: runtime.GOOS, Arch: runtime.GOARCH, Format: "elf", Size: int64(len(data)), SHA256: plugin.Hash(data)}}
		if err := m.Sign(priv); err != nil {
			t.Fatal(err)
		}
		raw, _ = json.Marshal(m)
		path := filepath.Join(dir, v+".json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		releases = append(releases, map[string]string{"manifest": path, "artifact": binary})
	}
	assigned := map[string]map[string]string{"agent-1": {"echo": "1.0.0"}, "agent-2": {"echo": "2.0.0"}}
	catalog, _ := json.Marshal(map[string]any{"releases": releases, "desired": assigned, "active": assigned})
	catalogPath := filepath.Join(dir, "catalog.json")
	if err := os.WriteFile(catalogPath, catalog, 0600); err != nil {
		t.Fatal(err)
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reservation.Addr().String()
	reservation.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var serverLog, auditLog safeLog
	s := server.New(server.Config{Address: addr, CAFile: ca, CertFile: cert, KeyFile: key, CatalogPath: catalogPath, Permissions: map[string][]string{"agent-1": {"echo"}, "agent-2": {"echo"}}, Logger: log.New(&serverLog, "", 0), Audit: log.New(&auditLog, "", 0)})
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	waitFor(t, "listener", func() bool { return strings.Contains(serverLog.String(), "listening on") })
	storage := filepath.Join(dir, "agent-1")
	manager, err := plugin.NewManager(plugin.Policy{Keys: map[string]ed25519.PublicKey{"test-key": pub}, Plugins: map[string]bool{"echo": true}, Storage: storage})
	if err != nil {
		t.Fatal(err)
	}
	// Start a real authenticated transfer, persist one chunk, then cut the socket.
	roots := x509.NewCertPool()
	caRaw, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	if !roots.AppendCertsFromPEM(caRaw) {
		t.Fatal("bad CA")
	}
	identity, err := tls.LoadX509KeyPair(agentCert, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{identity}}
	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	peer := wire.NewPeer(conn)
	if err := peer.Send(wire.Message{Type: "hello", Text: "agent-1"}); err != nil {
		t.Fatal(err)
	}
	if err := peer.Send(wire.Message{Type: "capabilities", OS: runtime.GOOS, Arch: runtime.GOARCH, APIVersion: 1}); err != nil {
		t.Fatal(err)
	}
	var hash string
	for {
		msg, err := peer.Receive()
		if err != nil {
			t.Fatal(err)
		}
		if msg.Type == "plugin_manifest" {
			hash, _, err = manager.Begin(msg.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := peer.Send(wire.Message{Type: "plugin_chunk_request", PluginID: "echo", Version: "1.0.0", Hash: hash}); err != nil {
				t.Fatal(err)
			}
		}
		if msg.Type == "plugin_chunk" {
			chunk, err := base64.StdEncoding.DecodeString(msg.Data)
			if err != nil {
				t.Fatal(err)
			}
			offset, finished, err := manager.Chunk(hash, msg.Offset, chunk, msg.Final)
			if err != nil || finished || offset != plugin.ChunkSize {
				t.Fatalf("partial: %d %v %v", offset, finished, err)
			}
			break
		}
	}
	conn.Close()
	manager.ResetTransfers()
	waitFor(t, "disconnect", func() bool { return len(s.Agents()) == 0 })
	var logs [2]safeLog
	clients := make(chan error, 2)
	for i, name := range []string{"agent-1", "agent-2"} {
		m := manager
		c, k := agentCert, agentKey
		if i == 1 {
			c = filepath.Join(filepath.Dir(agentCert), "agent-2.crt")
			k = filepath.Join(filepath.Dir(agentKey), "agent-2.key")
			m, err = plugin.NewManager(plugin.Policy{Keys: map[string]ed25519.PublicKey{"test-key": pub}, Plugins: map[string]bool{"echo": true}, Storage: filepath.Join(dir, name)})
			if err != nil {
				t.Fatal(err)
			}
		}
		cfg := client.Config{Address: addr, CAFile: ca, CertFile: c, KeyFile: k, Name: name, Plugins: m, Logger: log.New(&logs[i], "", 0)}
		go func() { clients <- client.Run(ctx, cfg) }()
	}
	waitForPluginInstall(t, "both versions active", func() bool {
		for name, want := range assigned {
			rows, err := s.Plugins(name)
			if err != nil || len(rows) != 1 || !rows[0].Active || rows[0].Version != want["echo"] {
				return false
			}
		}
		return true
	})
	if !strings.Contains(logs[0].String(), "offset 32768") {
		t.Fatalf("transfer did not resume: %s", logs[0].String())
	}
	for _, name := range []string{"agent-1", "agent-2"} {
		id, err := s.Send(name, "echo", "hello")
		if err != nil {
			t.Fatal(err)
		}
		waitFor(t, "echo result", func() bool { return strings.Contains(serverLog.String(), "result "+id) })
	}
	if _, err := s.Send("agent-1", "status", "{}"); err == nil {
		t.Fatal("unauthorized action accepted")
	}
	cancel()
	for i := 0; i < 2; i++ {
		select {
		case err := <-clients:
			if err != nil && err != io.EOF {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("client failed to stop")
		}
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server failed to stop")
	}
}
