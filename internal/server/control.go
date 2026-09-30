package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"time"
)

// ControlRequest is a local operator command. The socket is accessible only to its owner.
type ControlRequest struct {
	Operation string `json:"operation"`
	Agent     string `json:"agent"`
	Action    string `json:"action,omitempty"`
	Input     string `json:"input,omitempty"`
	Plugin    string `json:"plugin,omitempty"`
	Version   string `json:"version,omitempty"`
}
type ControlResult struct {
	ID      string       `json:"id,omitempty"`
	Plugins []PluginInfo `json:"plugins,omitempty"`
	Error   string       `json:"error,omitempty"`
}

// ListenControl opens an optional local operator socket. It never binds an agent port.
func (s *Server) ListenControl(ctx context.Context, path string) (net.Listener, error) {
	if _, err := os.Lstat(path); err == nil {
		return nil, errors.New("control socket path already exists")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	go func() { <-ctx.Done(); listener.Close() }()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go s.control(conn)
		}
	}()
	return listener, nil
}
func (s *Server) control(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var req ControlRequest
	var result ControlResult
	decoder := json.NewDecoder(io.LimitReader(conn, 64*1024))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&req)
	if err == nil {
		switch req.Operation {
		case "plugins":
			result.Plugins, err = s.Plugins(req.Agent)
		case "run":
			result.ID, err = s.Send(req.Agent, req.Action, req.Input)
		case "install":
			err = s.SetDesired(req.Agent, req.Plugin, req.Version)
		case "activate":
			err = s.Activate(req.Agent, req.Plugin, req.Version)
		case "rollback":
			err = s.Rollback(req.Agent, req.Plugin)
		case "reload":
			err = s.reloadDevelopmentPolicy()
		default:
			err = errors.New("unknown control operation")
		}
	}
	if err != nil {
		result.Error = err.Error()
	}
	_ = json.NewEncoder(conn).Encode(result)
}
func (s *Server) reloadDevelopmentPolicy() error {
	if s.cfg.PermissionsPath != "" {
		raw, err := os.ReadFile(s.cfg.PermissionsPath)
		if err != nil {
			return err
		}
		var grants map[string][]string
		if err := json.Unmarshal(raw, &grants); err != nil {
			return err
		}
		s.mu.Lock()
		s.cfg.Permissions = grants
		s.mu.Unlock()
	}
	if s.cfg.CatalogPath == "" {
		return errors.New("no catalog configured")
	}
	return s.LoadCatalog(s.cfg.CatalogPath)
}
