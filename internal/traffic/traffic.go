// Package traffic counts encrypted bytes on an agent's TCP connection.
package traffic

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync/atomic"
	"time"
)

// Snapshot is cumulative for one connection. Counts include TLS records and the
// handshake, but exclude TCP/IP headers and retransmissions. Sent means agent to
// server. The reporting heartbeat itself is included in a subsequent snapshot.
type Snapshot struct {
	SessionID      string  `json:"session_id"`
	SentBytes      uint64  `json:"sent_bytes"`
	ReceivedBytes  uint64  `json:"received_bytes"`
	ElapsedSeconds float64 `json:"elapsed_seconds"`
}

type Conn struct {
	net.Conn
	id             string
	started        time.Time
	sent, received atomic.Uint64
}

func NewConn(conn net.Conn) (*Conn, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	return &Conn{Conn: conn, id: hex.EncodeToString(id[:]), started: time.Now()}, nil
}
func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.received.Add(uint64(n))
	return n, err
}
func (c *Conn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.sent.Add(uint64(n))
	return n, err
}
func (c *Conn) Snapshot() *Snapshot {
	return &Snapshot{SessionID: c.id, SentBytes: c.sent.Load(), ReceivedBytes: c.received.Load(), ElapsedSeconds: time.Since(c.started).Seconds()}
}
