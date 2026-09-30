package server_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ccollicutt/bidi/internal/client"
	"github.com/ccollicutt/bidi/internal/plugin"
	"github.com/ccollicutt/bidi/internal/server"
)

type safeLog struct {
	mu sync.Mutex
	bytes.Buffer
}

func (l *safeLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.Buffer.Write(p)
}
func (l *safeLog) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.Buffer.String() }

func testCertificates(t *testing.T) (ca, serverCert, serverKey, agentCert, agentKey string) {
	t.Helper()
	dir := t.TempDir()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPriv.Public(), caPriv)
	if err != nil {
		t.Fatal(err)
	}
	caParsed, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, block *pem.Block, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(block), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ca = write("ca.pem", &pem.Block{Type: "CERTIFICATE", Bytes: caDER}, 0644)
	issue := func(name string, serial int64, usage x509.ExtKeyUsage, ips []net.IP) (string, string) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature, IPAddresses: ips}
		der, err := x509.CreateCertificate(rand.Reader, template, caParsed, priv.Public(), caPriv)
		if err != nil {
			t.Fatal(err)
		}
		key, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		return write(name+".crt", &pem.Block{Type: "CERTIFICATE", Bytes: der}, 0644), write(name+".key", &pem.Block{Type: "PRIVATE KEY", Bytes: key}, 0600)
	}
	serverCert, serverKey = issue("server", 2, x509.ExtKeyUsageServerAuth, []net.IP{net.ParseIP("127.0.0.1")})
	agentCert, agentKey = issue("agent-1", 3, x509.ExtKeyUsageClientAuth, nil)
	issue("agent-2", 4, x509.ExtKeyUsageClientAuth, nil)
	return
}

func waitFor(t *testing.T, description string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func TestBidirectionalTrafficUsesOneConnection(t *testing.T) {
	ca, serverCert, serverKey, agentCert, agentKey := testCertificates(t)
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reservation.Addr().String()
	reservation.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var serverLog, auditLog, clientLog safeLog
	s := server.New(server.Config{Address: addr, CAFile: ca, CertFile: serverCert, KeyFile: serverKey, Logger: log.New(&serverLog, "", 0), Audit: log.New(&auditLog, "", 0), Permissions: map[string][]string{"agent-1": {"status", "echo"}}})
	serverDone := make(chan error, 1)
	go func() { serverDone <- s.Run(ctx) }()
	waitFor(t, "server listener", func() bool { return strings.Contains(serverLog.String(), "listening on") })
	input := make(chan string, 1)
	clientDone := make(chan error, 1)
	go func() {
		clientDone <- client.Run(ctx, client.Config{Address: addr, CAFile: ca, CertFile: agentCert, KeyFile: agentKey, Name: "agent-1", Logger: log.New(&clientLog, "", 0), Input: input})
	}()
	waitFor(t, "agent connection", func() bool { return len(s.Agents()) == 1 })
	connections := s.Connections()
	if len(connections) != 1 || connections[0].Agent != "agent-1" || connections[0].RemoteAddress == "" || connections[0].LocalAddress == "" || connections[0].CertificateSerial != "3" {
		t.Fatalf("unexpected connection details: %+v", connections)
	}
	input <- "from-agent"
	if err := s.SendMessage("agent-1", "plain-message-from-server"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Send("agent-1", "echo", "from-server"); err == nil {
		t.Fatal("echo ran without an active plugin")
	}
	waitFor(t, "agent to server message", func() bool { return strings.Contains(serverLog.String(), "agent agent-1: from-agent") })
	waitFor(t, "server to agent message", func() bool {
		return strings.Contains(clientLog.String(), "server: plain-message-from-server")
	})
	audit := auditLog.String()
	if got := strings.Count(audit, `"event":"connected"`); got != 1 {
		t.Fatalf("used %d connections, want one; audit:\n%s", got, audit)
	}
	if got := len(s.Agents()); got != 1 {
		t.Fatalf("agent disconnected during exchange: %d active", got)
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

func TestPluginTransferOverMTLSAndExecutionFailure(t *testing.T) {
	ca, serverCert, serverKey, agentCert, agentKey := testCertificates(t)
	dir := t.TempDir()
	artifact := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 100000)...)
	artifactPath := filepath.Join(dir, "artifact")
	if err := os.WriteFile(artifactPath, artifact, 0600); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := plugin.Manifest{ManifestVersion: 1, PluginID: "echo", Version: "1.0.0", APIVersion: 1, PublisherKeyID: "test-key", Artifacts: []plugin.Artifact{{OS: runtime.GOOS, Arch: runtime.GOARCH, Format: "elf", Size: int64(len(artifact)), SHA256: plugin.Hash(artifact)}}, Actions: []plugin.Action{{Name: "echo.repeat", InputSchema: json.RawMessage(`{"type":"object","required":["text"],"properties":{"text":{"type":"string"}},"additionalProperties":false}`), OutputSchema: json.RawMessage(`{"type":"object","required":["text"],"properties":{"text":{"type":"string"}},"additionalProperties":false}`), TimeoutSeconds: 5, MaxResultBytes: 1024, ReadOnly: true}}}
	if err := m.Sign(priv); err != nil {
		t.Fatal(err)
	}
	manifestRaw, _ := json.Marshal(m)
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestRaw, 0600); err != nil {
		t.Fatal(err)
	}
	catalog := map[string]any{"releases": []map[string]string{{"manifest": manifestPath, "artifact": artifactPath}}, "desired": map[string]any{"agent-1": map[string]string{"echo": "1.0.0"}}, "active": map[string]any{"agent-1": map[string]string{"echo": "1.0.0"}}}
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
	s := server.New(server.Config{Address: addr, CAFile: ca, CertFile: serverCert, KeyFile: serverKey, CatalogPath: catalogPath, Permissions: map[string][]string{"agent-1": {"echo"}}, Logger: log.New(&serverLog, "", 0), Audit: log.New(&auditLog, "", 0)})
	serverDone := make(chan error, 1)
	go func() { serverDone <- s.Run(ctx) }()
	waitFor(t, "server listener", func() bool { return strings.Contains(serverLog.String(), "listening on") })
	manager, err := plugin.NewManager(plugin.Policy{Keys: map[string]ed25519.PublicKey{"test-key": pub}, Plugins: map[string]bool{"echo": true}, Storage: filepath.Join(dir, "plugins")})
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
	waitFor(t, "chunked plugin install", func() bool {
		return strings.Contains(auditLog.String(), `"event":"plugin_install_result"`) && strings.Contains(auditLog.String(), `"error":""`)
	})
	if got := manager.Installed()["echo"]; len(got) != 1 || got[0] != "1.0.0" {
		t.Fatalf("installed versions: %v", got)
	}
	waitFor(t, "activation result", func() bool { return strings.Contains(auditLog.String(), `"event":"plugin_activate_result"`) })
	id, err := s.Send("agent-1", "echo", "hello")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bounded execution failure", func() bool {
		return strings.Contains(serverLog.String(), "result "+id) && strings.Contains(serverLog.String(), "plugin failed")
	})
	if len(s.Agents()) != 1 {
		t.Fatal("plugin execution error disconnected agent")
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
