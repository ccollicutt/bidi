// Package server accepts mutually authenticated agent sessions.
package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ccollicutt/bidi/internal/wire"
)

const idleTimeout = 90 * time.Second
const queueSize = 32

func nextHeartbeat() time.Duration {
	return time.Duration(25+mrand.Intn(11)) * time.Second
}

type Config struct {
	Address, CAFile, CertFile, KeyFile string
	Logger                             *log.Logger
	Audit                              *log.Logger
	// Permissions maps certificate common names to their allowed actions.
	Permissions     map[string][]string
	CatalogPath     string
	PermissionsPath string
}

type Server struct {
	cfg            Config
	mu             sync.RWMutex
	agents         map[string]*agent
	pending        map[string]pendingCommand
	catalog        map[string]map[string]pluginRelease
	desired        map[string]map[string]string
	activeDesired  map[string]map[string]string
	catalogVersion string
}
type pendingCommand struct {
	agent, action string
	at            time.Time
}
type agent struct {
	name           string
	conn           net.Conn
	peer           *wire.Peer
	outgoing       chan wire.Message
	connected      time.Time
	serial         string
	platformOS     string
	platformArch   string
	installed      map[string][]string
	active         map[string]string
	pluginOffers   []wire.Message
	pluginInFlight bool
	traffic        *TrafficReading
}

// ConnectionInfo describes an active authenticated agent connection.
type ConnectionInfo struct {
	Agent             string
	RemoteAddress     string
	LocalAddress      string
	CertificateSerial string
	ConnectedAt       time.Time
	Traffic           *TrafficReading
}

func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.Audit == nil {
		cfg.Audit = cfg.Logger
	}
	return &Server{cfg: cfg, agents: make(map[string]*agent), pending: make(map[string]pendingCommand), catalog: make(map[string]map[string]pluginRelease), desired: make(map[string]map[string]string), activeDesired: make(map[string]map[string]string)}
}
func (s *Server) audit(event string, fields map[string]string) {
	record := map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "event": event}
	for k, v := range fields {
		record[k] = v
	}
	b, _ := json.Marshal(record)
	s.cfg.Audit.Print(string(b))
}
func secureKey(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("private key %s must be a regular file readable only by its owner (mode 0600)", path)
	}
	return nil
}
func (s *Server) Run(ctx context.Context) error {
	if s.cfg.CatalogPath != "" {
		if err := s.LoadCatalog(s.cfg.CatalogPath); err != nil {
			return err
		}
	}
	if err := secureKey(s.cfg.KeyFile); err != nil {
		return err
	}
	pem, err := os.ReadFile(s.cfg.CAFile)
	if err != nil {
		return fmt.Errorf("read CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("CA file has no certificates")
	}
	cert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("load server certificate: %w", err)
	}
	ln, err := tls.Listen("tcp", s.cfg.Address, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots})
	if err != nil {
		return err
	}
	defer ln.Close()
	s.cfg.Logger.Printf("listening on %s", ln.Addr())
	go func() {
		<-ctx.Done()
		ln.Close()
		s.mu.RLock()
		defer s.mu.RUnlock()
		for _, a := range s.agents {
			a.conn.Close()
		}
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}
func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		s.audit("authentication_failed", map[string]string{"error": err.Error()})
		return
	}
	cert := tlsConn.ConnectionState().PeerCertificates[0]
	peer := wire.NewPeer(conn)
	hello, err := peer.Receive()
	if err != nil {
		s.audit("authentication_failed", map[string]string{"error": err.Error()})
		return
	}
	name := strings.TrimSpace(hello.Text)
	if hello.Type != "hello" || name == "" || name != cert.Subject.CommonName {
		s.audit("authentication_failed", map[string]string{"identity": cert.Subject.CommonName, "reason": "hello identity mismatch"})
		return
	}
	s.mu.RLock()
	_, provisioned := s.cfg.Permissions[name]
	s.mu.RUnlock()
	if !provisioned {
		s.audit("authentication_failed", map[string]string{"identity": name, "reason": "unprovisioned agent"})
		return
	}
	conn.SetDeadline(time.Time{})
	a := &agent{name: name, conn: conn, peer: peer, outgoing: make(chan wire.Message, queueSize), connected: time.Now(), serial: cert.SerialNumber.String()}
	s.mu.Lock()
	if old := s.agents[name]; old != nil {
		old.conn.Close()
	}
	s.agents[name] = a
	s.mu.Unlock()
	s.audit("connected", map[string]string{"agent": name, "certificate_serial": cert.SerialNumber.String()})
	s.recordTraffic(a, hello.Traffic)
	defer func() {
		s.mu.Lock()
		if s.agents[name] == a {
			delete(s.agents, name)
		}
		for id, p := range s.pending {
			if p.agent == name {
				delete(s.pending, id)
				s.audit("command_lost", map[string]string{"agent": name, "id": id, "action": p.action})
			}
		}
		s.mu.Unlock()
		s.audit("disconnected", map[string]string{"agent": name})
	}()
	stopWriter := make(chan struct{})
	defer close(stopWriter)
	go func() {
		heartbeat := time.NewTimer(nextHeartbeat())
		defer heartbeat.Stop()
		for {
			var m wire.Message
			select {
			case m = <-a.outgoing:
			case <-heartbeat.C:
				m = wire.Message{Type: "ping"}
				heartbeat.Reset(nextHeartbeat())
			case <-stopWriter:
				return
			}
			a.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := a.peer.Send(m); err != nil {
				a.conn.Close()
				return
			}
		}
	}()
	for {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))
		m, err := peer.Receive()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.cfg.Logger.Printf("agent %s: %v", name, err)
			}
			return
		}
		switch m.Type {
		case "message":
			s.cfg.Logger.Printf("agent %s: %s", name, m.Text)
			s.audit("message_received", map[string]string{"agent": name, "text": m.Text})
		case "result":
			s.mu.Lock()
			p, ok := s.pending[m.ID]
			if ok && p.agent == name && p.action == m.Action {
				delete(s.pending, m.ID)
			}
			s.mu.Unlock()
			if !ok || p.agent != name || p.action != m.Action {
				s.audit("invalid_result", map[string]string{"agent": name, "id": m.ID, "action": m.Action})
				continue
			}
			s.audit("command_result", map[string]string{"agent": name, "id": m.ID, "action": m.Action, "result": m.Text, "error": m.Error, "plugin_id": m.PluginID, "plugin_version": m.Version})
			if m.Error != "" {
				s.cfg.Logger.Printf("result %s from %s (%s): error: %s", m.ID, name, m.Action, m.Error)
			} else {
				s.cfg.Logger.Printf("result %s from %s (%s): %s", m.ID, name, m.Action, m.Text)
			}
		case "ping":
			s.recordTraffic(a, m.Traffic)
			select {
			case a.outgoing <- wire.Message{Type: "pong", ID: m.ID}:
			default:
				s.audit("queue_full", map[string]string{"agent": name})
				return
			}
		case "pong":
			s.recordTraffic(a, m.Traffic)
		case "capabilities", "catalog_request", "plugin_chunk_request", "plugin_install_result", "plugin_activate_result", "plugin_rollback_result":
			s.handlePluginMessage(a, m)
		default:
			s.audit("invalid_message", map[string]string{"agent": name, "type": m.Type})
		}
	}
}
func (s *Server) Agents() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.agents))
	for name := range s.agents {
		out = append(out, name)
	}
	return out
}

// Connections returns a snapshot of active authenticated agent sockets.
func (s *Server) Connections() []ConnectionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ConnectionInfo, 0, len(s.agents))
	for _, a := range s.agents {
		out = append(out, ConnectionInfo{
			Agent:             a.name,
			RemoteAddress:     a.conn.RemoteAddr().String(),
			LocalAddress:      a.conn.LocalAddr().String(),
			CertificateSerial: a.serial,
			ConnectedAt:       a.connected,
			Traffic:           a.traffic,
		})
	}
	return out
}
func allowed(actions []string, action string) bool {
	for _, a := range actions {
		if a == action {
			return true
		}
	}
	return false
}

// SendMessage queues plain text for the agent to display. It is never executed.
func (s *Server) SendMessage(name, text string) error {
	if text == "" || len(text) > wire.MaxMessage/2 {
		return errors.New("message must contain 1 to 32768 bytes")
	}
	s.mu.RLock()
	a := s.agents[name]
	if a == nil {
		s.mu.RUnlock()
		return fmt.Errorf("agent %q is not connected", name)
	}
	select {
	case a.outgoing <- wire.Message{Type: "message", Text: text}:
		s.mu.RUnlock()
		s.audit("message_queued", map[string]string{"agent": name, "text": text})
		return nil
	default:
		s.mu.RUnlock()
		s.audit("queue_full", map[string]string{"agent": name, "type": "message"})
		return errors.New("agent outgoing queue is full")
	}
}

func (s *Server) Send(name, action, text string) (string, error) {
	requestedAction := action
	if action == "status" {
		action = "status.get"
	} else if action == "echo" {
		action = "echo.repeat"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.agents[name]
	if a == nil {
		return "", fmt.Errorf("agent %q is not connected", name)
	}
	if !strings.Contains(action, ".") {
		v := a.active[action]
		release, exists := s.catalog[action][v]
		if !exists {
			return "", fmt.Errorf("plugin %q is not active on agent %q", action, name)
		}
		if len(release.manifest.Actions) != 1 {
			var names []string
			for _, spec := range release.manifest.Actions {
				names = append(names, spec.Name)
			}
			return "", fmt.Errorf("plugin %q has multiple actions; choose one: %s", action, strings.Join(names, ", "))
		}
		action = release.manifest.Actions[0].Name
		requestedAction = action
	}
	if text == "" && action != "echo.repeat" {
		text = "{}"
	}
	if !allowed(s.cfg.Permissions[name], action) && !allowed(s.cfg.Permissions[name], requestedAction) {
		s.audit("command_denied", map[string]string{"agent": name, "action": action})
		return "", fmt.Errorf("action %q is not authorized for agent %q", action, name)
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(raw[:])
	for pendingID, p := range s.pending {
		if time.Since(p.at) > 2*time.Minute {
			delete(s.pending, pendingID)
			s.audit("command_timeout", map[string]string{"agent": p.agent, "id": pendingID, "action": p.action})
		}
	}
	pendingCount := 0
	for _, p := range s.pending {
		if p.agent == name {
			pendingCount++
		}
	}
	if pendingCount >= queueSize {
		return "", errors.New("too many outstanding commands for agent")
	}
	pluginID := strings.SplitN(action, ".", 2)[0]
	version := s.activeDesired[name][pluginID]
	if version == "" {
		return "", fmt.Errorf("plugin %q is not active for agent %q", pluginID, name)
	}
	if a.active[pluginID] != version {
		return "", fmt.Errorf("plugin %q version %q is not active on agent %q", pluginID, version, name)
	}
	if _, ok := s.catalog[pluginID][version].manifest.Action(action); !ok {
		return "", fmt.Errorf("action %q is absent from catalog manifest", action)
	}
	m := wire.Message{Type: "request", ID: id, Action: action, Text: text, PluginID: pluginID, Version: version}
	select {
	case a.outgoing <- m:
		s.pending[id] = pendingCommand{agent: name, action: action, at: time.Now()}
		s.audit("command_queued", map[string]string{"agent": name, "id": id, "action": action, "plugin_id": pluginID, "plugin_version": version})
		return id, nil
	default:
		s.audit("queue_full", map[string]string{"agent": name, "action": action})
		return "", errors.New("agent command queue is full")
	}
}
