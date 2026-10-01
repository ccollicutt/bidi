// Package client runs an outbound-only agent connection.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ccollicutt/bidi/internal/plugin"
	"github.com/ccollicutt/bidi/internal/traffic"
	"github.com/ccollicutt/bidi/internal/wire"
)

// Config holds client connection and identity settings.
type Config struct {
	Address, CAFile, CertFile, KeyFile, Name string
	Logger                                   *log.Logger
	Input                                    <-chan string
	Plugins                                  *plugin.Manager
	CatalogRefresh                           time.Duration
}

// Run maintains an outbound TLS connection until the context is canceled.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Name == "" {
		return errors.New("agent name is required")
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return fmt.Errorf("read CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("CA file has no certificates")
	}
	info, err := os.Stat(cfg.KeyFile)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("agent private key must be a regular file with mode 0600")
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("load client certificate: %w", err)
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	serverName, _, err := net.SplitHostPort(cfg.Address)
	if err != nil {
		return fmt.Errorf("server address: %w", err)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{cert}, ServerName: serverName}
	delay := time.Second
	for ctx.Err() == nil {
		dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
		raw, err := dialer.DialContext(ctx, "tcp", cfg.Address)
		if err == nil {
			counter, counterErr := traffic.NewConn(raw)
			if counterErr != nil {
				raw.Close()
				return counterErr
			}
			conn := tls.Client(counter, tlsCfg)
			handshakeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = conn.HandshakeContext(handshakeCtx)
			cancel()
			if err == nil {
				cfg.Logger.Printf("connected to %s", cfg.Address)
				delay = time.Second
				err = session(ctx, conn, cfg, counter)
			}
			conn.Close()
		}
		if ctx.Err() != nil {
			break
		}
		cfg.Logger.Printf("disconnected: %v; retrying in %s", err, delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
	return nil
}

func session(ctx context.Context, conn net.Conn, cfg Config, counter *traffic.Conn) error {
	if cfg.Plugins != nil {
		defer cfg.Plugins.ResetTransfers()
	}
	peer := wire.NewPeer(conn)
	send := func(message wire.Message) error {
		if message.Type == "hello" || message.Type == "ping" || message.Type == "pong" {
			message.Traffic = counter.Snapshot()
		}
		if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		return peer.Send(message)
	}
	if err := send(wire.Message{Type: "hello", Text: cfg.Name}); err != nil {
		return err
	}
	if cfg.Plugins != nil {
		if err := send(wire.Message{Type: "capabilities", OS: runtime.GOOS, Arch: runtime.GOARCH, APIVersion: plugin.APIVersion, Installed: cfg.Plugins.Installed(), Active: cfg.Plugins.Active()}); err != nil {
			return err
		}
	}
	done := make(chan error, 1)
	var transferHash string
	var transferPlugin, transferVersion string
	var catalogVersion atomic.Value
	catalogVersion.Store("")
	go func() {
		for {
			conn.SetReadDeadline(time.Now().Add(90 * time.Second))
			m, err := peer.Receive()
			if err != nil {
				done <- err
				return
			}
			switch m.Type {
			case "message":
				cfg.Logger.Printf("server: %s", m.Text)
			case "request":
				cfg.Logger.Printf("request %s (%s): %q", m.ID, m.Action, m.Text)
				result := wire.Message{Type: "result", ID: m.ID, Action: m.Action}
				if cfg.Plugins == nil {
					result.Error = "plugin unavailable"
				} else {
					active := cfg.Plugins.Active()
					if active[m.PluginID] != m.Version || !strings.HasPrefix(m.Action, m.PluginID+".") {
						result.Error = "plugin version or action denied"
					} else {
						input := json.RawMessage(m.Text)
						if m.Action == "status.get" {
							input, _ = json.Marshal(map[string]string{"agent": cfg.Name})
						} else if m.Action == "echo.repeat" {
							input, _ = json.Marshal(map[string]string{"text": m.Text})
						}
						output, v, execErr := cfg.Plugins.Execute(ctx, m.PluginID, m.Action, m.ID, input)
						result.Version = v
						result.PluginID = m.PluginID
						result.Error = execErr
						if execErr == "" {
							if m.Action == "echo.repeat" {
								var value struct {
									Text string `json:"text"`
								}
								_ = json.Unmarshal(output, &value)
								result.Text = value.Text
							} else if m.Action == "status.get" {
								var value struct {
									Text string `json:"text"`
								}
								_ = json.Unmarshal(output, &value)
								result.Text = value.Text
							} else {
								result.Text = string(output)
							}
						}
					}
				}
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := send(result); err != nil {
					done <- err
					return
				}
				if result.Error != "" {
					cfg.Logger.Printf("result %s (%s): error: %s", result.ID, result.Action, result.Error)
				} else {
					cfg.Logger.Printf("result %s (%s): %q", result.ID, result.Action, result.Text)
				}
			case "ping":
				cfg.Logger.Print("heartbeat: ping received from server")
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := send(wire.Message{Type: "pong", ID: m.ID}); err != nil {
					done <- err
					return
				}
			case "pong":
				cfg.Logger.Print("heartbeat: pong received from server")
			case "catalog_version":
				if cfg.Plugins != nil {
					changed := catalogVersion.Load().(string) != m.CatalogVersion
					catalogVersion.Store(m.CatalogVersion)
					if changed {
						cfg.Logger.Printf("catalog version: %s", m.CatalogVersion)
					}
				}
			case "plugin_manifest":
				if cfg.Plugins == nil {
					continue
				}
				parsed, parseErr := plugin.Parse(m.Manifest)
				if parseErr != nil || parsed.PluginID != m.PluginID || parsed.Version != m.Version {
					cfg.Logger.Printf("plugin install failed: %s %s: manifest identity mismatch", m.PluginID, m.Version)
					send(wire.Message{Type: "plugin_install_result", PluginID: m.PluginID, Version: m.Version, Error: "manifest identity mismatch"})
					continue
				}
				hash, offset, e := cfg.Plugins.Begin(m.Manifest)
				if e != nil {
					cfg.Logger.Printf("plugin install failed: %s %s: %v", m.PluginID, m.Version, e)
					send(wire.Message{Type: "plugin_install_result", PluginID: m.PluginID, Version: m.Version, Error: e.Error()})
					continue
				}
				transferHash = hash
				transferPlugin = m.PluginID
				transferVersion = m.Version
				if info := cfg.Plugins.Installed(); containsVersion(info[m.PluginID], m.Version) {
					cfg.Logger.Printf("plugin already installed: %s %s (verified)", m.PluginID, m.Version)
					send(wire.Message{Type: "plugin_install_result", PluginID: m.PluginID, Version: m.Version, Hash: hash})
					continue
				}
				cfg.Logger.Printf("downloading plugin: %s %s (offset %d)", m.PluginID, m.Version, offset)
				send(wire.Message{Type: "plugin_chunk_request", PluginID: m.PluginID, Version: m.Version, Hash: hash, Offset: offset})
			case "plugin_chunk":
				if cfg.Plugins == nil || m.Hash != transferHash || m.PluginID != transferPlugin || m.Version != transferVersion {
					continue
				}
				data, e := base64.StdEncoding.DecodeString(m.Data)
				if e != nil {
					cfg.Logger.Printf("plugin install failed: %s %s: invalid chunk encoding", m.PluginID, m.Version)
					send(wire.Message{Type: "plugin_install_result", PluginID: m.PluginID, Version: m.Version, Error: "invalid chunk encoding"})
					continue
				}
				offset, installed, e := cfg.Plugins.Chunk(m.Hash, m.Offset, data, m.Final)
				if e != nil {
					cfg.Logger.Printf("plugin install failed: %s %s: %v", m.PluginID, m.Version, e)
					send(wire.Message{Type: "plugin_install_result", PluginID: m.PluginID, Version: m.Version, Hash: m.Hash, Error: e.Error()})
					continue
				}
				if installed {
					cfg.Logger.Printf("installed plugin: %s %s (signature and artifact verified)", m.PluginID, m.Version)
					send(wire.Message{Type: "plugin_install_result", PluginID: m.PluginID, Version: m.Version, Hash: m.Hash})
				} else {
					send(wire.Message{Type: "plugin_chunk_request", PluginID: m.PluginID, Version: m.Version, Hash: m.Hash, Offset: offset})
				}
			case "plugin_activate":
				if cfg.Plugins == nil {
					send(wire.Message{Type: "plugin_activate_result", PluginID: m.PluginID, Version: m.Version, Error: "plugins disabled"})
					continue
				}
				alreadyActive := cfg.Plugins.Active()[m.PluginID] == m.Version
				e := cfg.Plugins.Activate(m.PluginID, m.Version)
				response := wire.Message{Type: "plugin_activate_result", PluginID: m.PluginID, Version: m.Version}
				if e != nil {
					response.Error = e.Error()
					cfg.Logger.Printf("plugin activation failed: %s %s: %v", m.PluginID, m.Version, e)
				} else if alreadyActive {
					cfg.Logger.Printf("plugin already active: %s %s", m.PluginID, m.Version)
				} else {
					cfg.Logger.Printf("activated plugin: %s %s", m.PluginID, m.Version)
				}
				send(response)
			case "plugin_rollback":
				if cfg.Plugins == nil {
					send(wire.Message{Type: "plugin_rollback_result", PluginID: m.PluginID, Error: "plugins disabled"})
					continue
				}
				v, e := cfg.Plugins.Rollback(m.PluginID)
				response := wire.Message{Type: "plugin_rollback_result", PluginID: m.PluginID, Version: v}
				if e != nil {
					response.Error = e.Error()
					cfg.Logger.Printf("plugin rollback failed: %s: %v", m.PluginID, e)
				} else {
					cfg.Logger.Printf("rolled back plugin: %s %s", m.PluginID, v)
				}
				send(response)
			default:
				cfg.Logger.Printf("unknown server message: %s", m.Type)
			}
		}
	}()
	heartbeat := time.NewTimer(nextHeartbeat())
	defer heartbeat.Stop()
	refresh := cfg.CatalogRefresh
	if refresh <= 0 {
		refresh = time.Minute
	}
	catalogTicker := time.NewTicker(refresh)
	defer catalogTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-done:
			if errors.Is(err, io.EOF) {
				return err
			}
			return fmt.Errorf("receive: %w", err)
		case <-heartbeat.C:
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := send(wire.Message{Type: "ping"}); err != nil {
				return err
			}
			cfg.Logger.Print("heartbeat: ping sent to server")
			heartbeat.Reset(nextHeartbeat())
		case <-catalogTicker.C:
			if cfg.Plugins != nil {
				if err := send(wire.Message{Type: "catalog_request", CatalogVersion: catalogVersion.Load().(string)}); err != nil {
					return err
				}
			}
		case line, ok := <-cfg.Input:
			if !ok {
				cfg.Input = nil
				continue
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := send(wire.Message{Type: "message", Text: line}); err != nil {
				return err
			}
		}
	}
}

func nextHeartbeat() time.Duration {
	return time.Duration(45+rand.Intn(31)) * time.Second
}
func containsVersion(versions []string, want string) bool {
	for _, v := range versions {
		if v == want {
			return true
		}
	}
	return false
}
