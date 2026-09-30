// Package wire defines the bounded JSON protocol used in both directions.
package wire

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

const MaxMessage = 64 * 1024

// Message carries chat, requests, and results on a single TLS connection.
type Message struct {
	Type           string              `json:"type"`
	ID             string              `json:"id,omitempty"`
	Action         string              `json:"action,omitempty"`
	Text           string              `json:"text,omitempty"`
	Error          string              `json:"error,omitempty"`
	PluginID       string              `json:"plugin_id,omitempty"`
	Version        string              `json:"version,omitempty"`
	Hash           string              `json:"hash,omitempty"`
	CatalogVersion string              `json:"catalog_version,omitempty"`
	OS             string              `json:"os,omitempty"`
	Arch           string              `json:"arch,omitempty"`
	APIVersion     int                 `json:"api_version,omitempty"`
	Offset         int64               `json:"offset,omitempty"`
	Final          bool                `json:"final,omitempty"`
	Data           string              `json:"data,omitempty"`
	Manifest       json.RawMessage     `json:"manifest,omitempty"`
	Installed      map[string][]string `json:"installed,omitempty"`
	Active         map[string]string   `json:"active,omitempty"`
}

// Peer serializes writes while allowing a concurrent read loop.
type Peer struct {
	reader *bufio.Reader
	writer *bufio.Writer
	mu     sync.Mutex
}

// NewPeer wraps a full-duplex connection.
func NewPeer(rw io.ReadWriter) *Peer {
	return &Peer{reader: bufio.NewReader(rw), writer: bufio.NewWriter(rw)}
}

// Send writes one bounded newline-delimited JSON message.
func (p *Peer) Send(m Message) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(data) > MaxMessage {
		return errors.New("message exceeds 64 KiB")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err = p.writer.Write(data); err != nil {
		return err
	}
	if err = p.writer.WriteByte('\n'); err != nil {
		return err
	}
	return p.writer.Flush()
}

// Receive reads and validates one complete message.
func (p *Peer) Receive() (Message, error) {
	var m Message
	var line []byte
	for {
		part, err := p.reader.ReadSlice('\n')
		line = append(line, part...)
		if len(line) > MaxMessage+1 {
			return m, errors.New("message exceeds 64 KiB")
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return m, err
		}
		break
	}
	if len(line) > MaxMessage+1 {
		return m, errors.New("message exceeds 64 KiB")
	}
	if err := json.Unmarshal(line, &m); err != nil {
		return m, fmt.Errorf("invalid JSON: %w", err)
	}
	if m.Type == "" {
		return m, errors.New("missing message type")
	}
	return m, nil
}
