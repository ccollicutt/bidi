package client

import (
	"context"
	"io"
	"log"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/ccollicutt/bidi/internal/plugin"
	"github.com/ccollicutt/bidi/internal/traffic"
	"github.com/ccollicutt/bidi/internal/wire"
)

// Short deadlines expose reuse of an expired deadline during catalog refresh.
type shortWriteDeadline struct{ net.Conn }

func (c shortWriteDeadline) SetWriteDeadline(_ time.Time) error {
	return c.Conn.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
}
func TestCatalogRefreshRenewsWriteDeadline(t *testing.T) {
	manager, err := plugin.NewManager(plugin.Policy{Storage: filepath.Join(t.TempDir(), "plugins")})
	if err != nil {
		t.Fatal(err)
	}
	agentConn, serverConn := net.Pipe()
	defer agentConn.Close()
	defer serverConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	counter, err := traffic.NewConn(shortWriteDeadline{agentConn})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- session(ctx, counter, Config{Name: "agent-1", Plugins: manager, Logger: log.New(io.Discard, "", 0), CatalogRefresh: 80 * time.Millisecond}, counter)
	}()
	peer := wire.NewPeer(serverConn)
	_ = serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for _, want := range []string{"hello", "capabilities", "catalog_request"} {
		m, err := peer.Receive()
		if err != nil {
			t.Fatalf("receive %s: %v", want, err)
		}
		if m.Type != want {
			t.Fatalf("got %s, want %s", m.Type, want)
		}
	}
	cancel()
	agentConn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session did not stop")
	}
}

func TestHeartbeatCarriesCumulativeTraffic(t *testing.T) {
	agentConn, serverConn := net.Pipe()
	defer agentConn.Close()
	defer serverConn.Close()
	counter, err := traffic.NewConn(agentConn)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- session(ctx, counter, Config{Name: "agent-1", Logger: log.New(io.Discard, "", 0)}, counter)
	}()
	serverConn.SetDeadline(time.Now().Add(2 * time.Second))
	peer := wire.NewPeer(serverConn)
	hello, err := peer.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if hello.Traffic == nil || hello.Traffic.SessionID == "" {
		t.Fatal("missing initial traffic session")
	}
	var previous uint64
	for _, id := range []string{"one", "two"} {
		if err := peer.Send(wire.Message{Type: "ping", ID: id}); err != nil {
			t.Fatal(err)
		}
		pong, err := peer.Receive()
		if err != nil {
			t.Fatal(err)
		}
		if pong.Type != "pong" || pong.ID != id || pong.Traffic == nil {
			t.Fatalf("pong: %+v", pong)
		}
		if pong.Traffic.SessionID != hello.Traffic.SessionID || pong.Traffic.ReceivedBytes <= previous || pong.Traffic.SentBytes == 0 {
			t.Fatalf("counts: %+v", pong.Traffic)
		}
		previous = pong.Traffic.ReceivedBytes
	}
	cancel()
	agentConn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session did not stop")
	}
}
