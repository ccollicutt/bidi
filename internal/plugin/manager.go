package plugin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const ChunkSize = 32 * 1024

type Policy struct {
	Keys           map[string]ed25519.PublicKey
	Revoked        map[string]bool
	Plugins        map[string]bool
	FilesystemRead []string
	Network        []string
	Services       map[string]ServiceTarget
	Storage        string
}
type ServiceTarget struct {
	Address string `json:"address"`
	Path    string `json:"path"`
}
type transfer struct {
	manifest Manifest
	artifact Artifact
	file     *os.File
	offset   int64
	at       time.Time
}
type Manager struct {
	mu        sync.Mutex
	policy    Policy
	active    map[string]string
	previous  map[string]string
	transfers map[string]*transfer
}

func NewManager(p Policy) (*Manager, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("native plugins currently support Linux executables")
	}
	if p.Storage == "" {
		return nil, errors.New("plugin storage is required")
	}
	if err := os.MkdirAll(p.Storage, 0700); err != nil {
		return nil, err
	}
	info, err := os.Stat(p.Storage)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("plugin storage must not be group or world writable")
	}
	m := &Manager{policy: p, active: map[string]string{}, previous: map[string]string{}, transfers: map[string]*transfer{}}
	raw, err := os.ReadFile(filepath.Join(p.Storage, "active.json"))
	if err == nil {
		var state struct {
			Active   map[string]string `json:"active"`
			Previous map[string]string `json:"previous"`
		}
		if err := json.Unmarshal(raw, &state); err != nil {
			return nil, err
		}
		m.active = state.Active
		m.previous = state.Previous
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	for id, v := range m.active {
		if !identifier.MatchString(id) || !version.MatchString(v) {
			return nil, errors.New("invalid active state")
		}
	}
	if m.active == nil {
		m.active = map[string]string{}
	}
	if m.previous == nil {
		m.previous = map[string]string{}
	}
	for id, v := range m.previous {
		if !identifier.MatchString(id) || !version.MatchString(v) {
			return nil, errors.New("invalid previous state")
		}
	}
	return m, nil
}
func (m *Manager) installedPath(id, v string) string { return filepath.Join(m.policy.Storage, id, v) }
func (m *Manager) partPath(hash string) string {
	return filepath.Join(m.policy.Storage, "transfers", hash+".part")
}
func (m *Manager) Begin(raw []byte) (string, int64, error) {
	manifest, err := Parse(raw)
	if err != nil {
		return "", 0, err
	}
	if err := manifest.Verify(m.policy.Keys, m.policy.Revoked, m.policy.FilesystemRead, m.policy.Network); err != nil {
		return "", 0, err
	}
	if !m.policy.Plugins[manifest.PluginID] {
		return "", 0, errors.New("plugin not locally allowlisted")
	}
	artifact, err := manifest.ArtifactForLocal()
	if err != nil {
		return "", 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.verifyInstalled(manifest, artifact); err == nil {
		return artifact.SHA256, artifact.Size, nil
	}
	if _, err := os.Stat(filepath.Join(m.installedPath(manifest.PluginID, manifest.Version), "manifest.json")); err == nil {
		return "", 0, errors.New("published version is immutable or installed artifact is corrupt")
	} else if !os.IsNotExist(err) {
		return "", 0, err
	}
	if len(m.transfers) >= 2 {
		return "", 0, errors.New("too many concurrent transfers")
	}
	for _, t := range m.transfers {
		if t.manifest.PluginID == manifest.PluginID && t.manifest.Version == manifest.Version {
			return "", 0, errors.New("version already transferring")
		}
	}
	if err := os.MkdirAll(filepath.Join(m.policy.Storage, "transfers"), 0700); err != nil {
		return "", 0, err
	}
	f, err := os.OpenFile(m.partPath(artifact.SHA256), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", 0, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return "", 0, err
	}
	offset := info.Size()
	if offset > artifact.Size {
		f.Truncate(0)
		offset = 0
	}
	m.transfers[artifact.SHA256] = &transfer{manifest: manifest, artifact: artifact, file: f, offset: offset, at: time.Now()}
	if offset == artifact.Size {
		if err := m.finishTransfer(artifact.SHA256); err != nil {
			return "", 0, err
		}
	}
	return artifact.SHA256, offset, nil
}
func (m *Manager) Chunk(hash string, offset int64, data []byte, final bool) (int64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.transfers[hash]
	if t == nil {
		return 0, false, errors.New("unknown transfer")
	}
	if time.Since(t.at) > 10*time.Minute {
		m.closeTransfer(hash)
		return 0, false, errors.New("transfer expired")
	}
	if len(data) == 0 || len(data) > ChunkSize || offset != t.offset || offset+int64(len(data)) > t.artifact.Size {
		return t.offset, false, errors.New("invalid chunk offset or size")
	}
	if _, err := t.file.WriteAt(data, offset); err != nil {
		return t.offset, false, err
	}
	t.offset += int64(len(data))
	t.at = time.Now()
	if !final {
		if t.offset == t.artifact.Size {
			return t.offset, false, errors.New("missing final chunk")
		}
		return t.offset, false, nil
	}
	if t.offset != t.artifact.Size {
		return t.offset, false, errors.New("premature final chunk")
	}
	if err := m.finishTransfer(hash); err != nil {
		return t.offset, false, err
	}
	return t.offset, true, nil
}

// Publish a complete directory in one rename. Keep the download until publication
// succeeds so an interrupted install can be retried without downloading again.
func (m *Manager) finishTransfer(hash string) error {
	t := m.transfers[hash]
	if err := t.file.Sync(); err != nil {
		return err
	}
	raw, err := os.ReadFile(m.partPath(hash))
	if err != nil {
		return err
	}
	if Hash(raw) != hash || len(raw) < 4 || !bytes.Equal(raw[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		m.closeTransfer(hash)
		os.Remove(m.partPath(hash))
		return errors.New("artifact hash mismatch or artifact is not ELF")
	}
	dest := m.installedPath(t.manifest.PluginID, t.manifest.Version)
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".install-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	manifestBytes, err := json.Marshal(t.manifest)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, "artifact"), raw, 0500); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, "manifest.json"), manifestBytes, 0600); err != nil {
		return err
	}
	for _, name := range []string{"artifact", "manifest.json", "."} {
		f, err := os.Open(filepath.Join(stage, name))
		if err != nil {
			return err
		}
		err = f.Sync()
		f.Close()
		if err != nil {
			return err
		}
	}
	if err := os.Rename(stage, dest); err != nil {
		return err
	}
	m.closeTransfer(hash)
	os.Remove(m.partPath(hash))
	return nil
}

func (m *Manager) closeTransfer(hash string) {
	if t := m.transfers[hash]; t != nil {
		t.file.Close()
		delete(m.transfers, hash)
	}
}

// ResetTransfers closes open handles while retaining verified offsets for reconnect.
func (m *Manager) ResetTransfers() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for hash := range m.transfers {
		m.closeTransfer(hash)
	}
}
func (m *Manager) verifyInstalled(manifest Manifest, artifact Artifact) error {
	dest := m.installedPath(manifest.PluginID, manifest.Version)
	raw, err := os.ReadFile(filepath.Join(dest, "manifest.json"))
	if err != nil {
		return err
	}
	existing, err := Parse(raw)
	if err != nil {
		return err
	}
	a, err := existing.ArtifactForLocal()
	if err != nil {
		return err
	}
	if a.SHA256 != artifact.SHA256 || existing.Signature != manifest.Signature {
		return errors.New("published version is immutable")
	}
	bin, err := os.ReadFile(filepath.Join(dest, "artifact"))
	if err != nil {
		return err
	}
	if int64(len(bin)) != artifact.Size || Hash(bin) != artifact.SHA256 {
		return errors.New("installed artifact hash mismatch")
	}
	return nil
}
func (m *Manager) Installed() map[string][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string][]string{}
	entries, _ := os.ReadDir(m.policy.Storage)
	for _, id := range entries {
		if !id.IsDir() || !identifier.MatchString(id.Name()) {
			continue
		}
		versions, _ := os.ReadDir(filepath.Join(m.policy.Storage, id.Name()))
		for _, v := range versions {
			if !v.IsDir() || !version.MatchString(v.Name()) {
				continue
			}
			if _, err := m.load(id.Name(), v.Name()); err == nil {
				out[id.Name()] = append(out[id.Name()], v.Name())
			}
		}
	}
	return out
}
func (m *Manager) Active() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]string{}
	for k, v := range m.active {
		out[k] = v
	}
	return out
}
func (m *Manager) load(id, v string) (Manifest, error) {
	var zero Manifest
	if !identifier.MatchString(id) || !version.MatchString(v) {
		return zero, errors.New("invalid identity")
	}
	raw, err := os.ReadFile(filepath.Join(m.installedPath(id, v), "manifest.json"))
	if err != nil {
		return zero, err
	}
	manifest, err := Parse(raw)
	if err != nil {
		return zero, err
	}
	if manifest.PluginID != id || manifest.Version != v {
		return zero, errors.New("manifest identity mismatch")
	}
	if err := manifest.Verify(m.policy.Keys, m.policy.Revoked, m.policy.FilesystemRead, m.policy.Network); err != nil {
		return zero, err
	}
	artifact, err := manifest.ArtifactForLocal()
	if err != nil {
		return zero, err
	}
	if err := m.verifyInstalled(manifest, artifact); err != nil {
		return zero, err
	}
	return manifest, nil
}
func (m *Manager) Activate(id, v string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.policy.Plugins[id] {
		return errors.New("plugin not locally allowlisted")
	}
	manifest, err := m.load(id, v)
	if err != nil {
		return err
	}
	if err := m.validateServices(manifest); err != nil {
		return err
	}
	old := m.active[id]
	previous := m.previous[id]
	if old == v {
		return nil
	}
	m.active[id] = v
	if old != "" {
		m.previous[id] = old
	}
	if err := m.saveActive(); err != nil {
		if previous == "" {
			delete(m.previous, id)
		} else {
			m.previous[id] = previous
		}
		if old == "" {
			delete(m.active, id)
		} else {
			m.active[id] = old
		}
		return err
	}
	return nil
}
func (m *Manager) validateServices(manifest Manifest) error {
	for _, address := range manifest.Capabilities.Network {
		found := false
		for _, target := range m.policy.Services {
			if target.Address == address && strings.HasPrefix(target.Path, "/") {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("network destination %s has no configured service", address)
		}
	}
	return nil
}
func (m *Manager) Rollback(id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.previous[id]
	if v == "" {
		return "", errors.New("no previous version")
	}
	if !m.policy.Plugins[id] {
		return "", errors.New("plugin not locally allowlisted")
	}
	manifest, err := m.load(id, v)
	if err != nil {
		return "", err
	}
	if err := m.validateServices(manifest); err != nil {
		return "", err
	}
	current := m.active[id]
	m.active[id] = v
	m.previous[id] = current
	if err := m.saveActive(); err != nil {
		m.active[id] = current
		m.previous[id] = v
		return "", err
	}
	return v, nil
}
func (m *Manager) saveActive() error {
	raw, err := json.Marshal(struct {
		Active   map[string]string `json:"active"`
		Previous map[string]string `json:"previous"`
	}{m.active, m.previous})
	if err != nil {
		return err
	}
	path := filepath.Join(m.policy.Storage, "active.json")
	if err := os.WriteFile(path+".tmp", raw, 0600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// Execute launches one verified native executable directly with a fixed argument vector.
func (m *Manager) Execute(ctx context.Context, id, action, commandID string, input json.RawMessage) (json.RawMessage, string, string) {
	m.mu.Lock()
	v := m.active[id]
	manifest, err := m.load(id, v)
	m.mu.Unlock()
	if v == "" || err != nil {
		return nil, "", "plugin unavailable"
	}
	spec, ok := manifest.Action(action)
	if !ok {
		return nil, v, "action absent from verified manifest"
	}
	schema, err := CompileSchema(spec.InputSchema)
	if err != nil {
		return nil, v, "invalid input schema"
	}
	var value any
	if err := json.Unmarshal(input, &value); err != nil {
		return nil, v, "invalid input JSON"
	}
	if err := schema.Validate(value); err != nil {
		return nil, v, "input schema rejected request"
	}
	if err := m.validateServices(manifest); err != nil {
		return nil, v, "service capability unavailable"
	}
	artifact, _ := manifest.ArtifactForLocal()
	if err := m.verifyInstalled(manifest, artifact); err != nil {
		return nil, v, "artifact verification failed"
	}
	request, _ := json.Marshal(map[string]any{"api_version": APIVersion, "action": action, "command_id": commandID, "input": value})
	ctx, cancel := context.WithTimeout(ctx, time.Duration(spec.TimeoutSeconds)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(m.installedPath(id, v), "artifact"))
	cmd.WaitDelay = time.Second
	services := map[string]ServiceTarget{}
	for serviceID, target := range m.policy.Services {
		if contains(manifest.Capabilities.Network, target.Address) {
			services[serviceID] = target
		}
	}
	serviceConfig, _ := json.Marshal(services)
	cmd.Env = []string{"BIDI_SERVICES_JSON=" + string(serviceConfig)}
	cmd.Stdin = bytes.NewReader(append(request, '\n'))
	var stdout, stderr limitedBuffer
	stdout.max = spec.MaxResultBytes + 1024
	stderr.max = 4096
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, v, "plugin timed out"
		}
		return nil, v, "plugin failed"
	}
	if stdout.exceeded {
		return nil, v, "plugin output exceeds limit"
	}
	var response struct {
		CommandID string          `json:"command_id"`
		Output    json.RawMessage `json:"output"`
		Error     string          `json:"error"`
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	if err := decoder.Decode(&response); err != nil {
		return nil, v, "invalid plugin result"
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, v, "multiple plugin results"
	}
	if response.CommandID != commandID {
		return nil, v, "plugin command ID mismatch"
	}
	if response.Error != "" {
		return nil, v, response.Error
	}
	if len(response.Output) == 0 || len(response.Output) > spec.MaxResultBytes {
		return nil, v, "plugin output exceeds limit"
	}
	schema, err = CompileSchema(spec.OutputSchema)
	if err != nil {
		return nil, v, "invalid output schema"
	}
	if err := json.Unmarshal(response.Output, &value); err != nil {
		return nil, v, "invalid output JSON"
	}
	if err := schema.Validate(value); err != nil {
		return nil, v, "output schema rejected result"
	}
	return response.Output, v, ""
}

type limitedBuffer struct {
	bytes.Buffer
	max      int
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len()+n > b.max {
		b.exceeded = true
		p = p[:max(0, b.max-b.Len())]
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}

// Hide Buffer.ReadFrom so exec's io.Copy cannot bypass the output bound.
func (b *limitedBuffer) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(struct{ io.Writer }{b}, r)
}
