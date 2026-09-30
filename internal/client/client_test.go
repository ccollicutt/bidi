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
	done := make(chan error, 1)
	go func() {
		done <- session(ctx, shortWriteDeadline{agentConn}, Config{Name: "agent-1", Plugins: manager, Logger: log.New(io.Discard, "", 0), CatalogRefresh: 80 * time.Millisecond})
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
