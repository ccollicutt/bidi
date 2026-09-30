package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ccollicutt/bidi/internal/plugin"
	"github.com/ccollicutt/bidi/internal/wire"
)

type pluginRelease struct {
	manifest  plugin.Manifest
	raw       json.RawMessage
	artifacts map[string][]byte
}
type catalogFile struct {
	Releases []struct {
		Manifest  string            `json:"manifest"`
		Artifact  string            `json:"artifact"`
		Artifacts map[string]string `json:"artifacts"`
	} `json:"releases"`
	Desired map[string]map[string]string `json:"desired"`
	Active  map[string]map[string]string `json:"active"`
}

// LoadCatalog loads reviewable release and per-agent desired-state entries.
func (s *Server) LoadCatalog(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc catalogFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	s.mu.RLock()
	permissions := s.cfg.Permissions
	s.mu.RUnlock()
	catalog := map[string]map[string]pluginRelease{}
	resolve := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(filepath.Dir(path), p)
	}
	for _, entry := range doc.Releases {
		manifestRaw, err := os.ReadFile(resolve(entry.Manifest))
		if err != nil {
			return err
		}
		m, err := plugin.Parse(manifestRaw)
		if err != nil {
			return err
		}
		paths := entry.Artifacts
		if len(paths) == 0 && entry.Artifact != "" {
			a, err := m.ArtifactForLocal()
			if err != nil {
				return err
			}
			paths = map[string]string{a.OS + "/" + a.Arch: entry.Artifact}
		}
		artifacts := map[string][]byte{}
		for _, a := range m.Artifacts {
			target := a.OS + "/" + a.Arch
			artifactPath := paths[target]
			if artifactPath == "" {
				return fmt.Errorf("missing catalog artifact %s for %s %s", target, m.PluginID, m.Version)
			}
			data, err := os.ReadFile(resolve(artifactPath))
			if err != nil {
				return err
			}
			if int64(len(data)) != a.Size || plugin.Hash(data) != a.SHA256 {
				return fmt.Errorf("catalog artifact mismatch for %s %s %s", m.PluginID, m.Version, target)
			}
			artifacts[target] = data
		}
		if catalog[m.PluginID] == nil {
			catalog[m.PluginID] = map[string]pluginRelease{}
		}
		if _, exists := catalog[m.PluginID][m.Version]; exists {
			return errors.New("duplicate catalog release")
		}
		catalog[m.PluginID][m.Version] = pluginRelease{m, manifestRaw, artifacts}
	}
	for agent, plugins := range doc.Desired {
		if _, ok := permissions[agent]; !ok {
			return fmt.Errorf("unprovisioned catalog agent %q", agent)
		}
		for id, v := range plugins {
			if _, ok := catalog[id][v]; !ok {
				return fmt.Errorf("unknown desired release %s %s", id, v)
			}
		}
	}
	for agent, plugins := range doc.Active {
		if _, ok := permissions[agent]; !ok {
			return fmt.Errorf("unprovisioned active agent %q", agent)
		}
		for id, v := range plugins {
			if _, ok := catalog[id][v]; !ok {
				return fmt.Errorf("unknown active release %s %s", id, v)
			}
		}
	}
	s.mu.Lock()
	s.catalog = catalog
	s.desired = doc.Desired
	s.activeDesired = doc.Active
	s.catalogVersion = plugin.Hash(raw)
	for _, a := range s.agents {
		s.offerCatalogLocked(a)
	}
	s.mu.Unlock()
	return nil
}
func (s *Server) offerCatalogLocked(a *agent) {
	s.queuePluginLocked(a, wire.Message{Type: "catalog_version", CatalogVersion: s.catalogVersion})
	a.pluginOffers = nil
	a.pluginInFlight = false
	ids := make([]string, 0, len(s.desired[a.name]))
	for id := range s.desired[a.name] {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		v := s.desired[a.name][id]
		if active := s.activeDesired[a.name][id]; active != "" && active != v {
			release := s.catalog[id][active]
			a.pluginOffers = append(a.pluginOffers, wire.Message{Type: "plugin_manifest", PluginID: id, Version: active, Manifest: release.raw, CatalogVersion: s.catalogVersion})
		}
		release := s.catalog[id][v]
		a.pluginOffers = append(a.pluginOffers, wire.Message{Type: "plugin_manifest", PluginID: id, Version: v, Manifest: release.raw, CatalogVersion: s.catalogVersion})
	}
	s.offerNextLocked(a)
}
func (s *Server) offerNextLocked(a *agent) {
	if a.pluginInFlight || len(a.pluginOffers) == 0 {
		return
	}
	next := a.pluginOffers[0]
	a.pluginOffers = a.pluginOffers[1:]
	a.pluginInFlight = true
	s.queuePluginLocked(a, next)
}
func (s *Server) queuePluginLocked(a *agent, m wire.Message) {
	select {
	case a.outgoing <- m:
	default:
		s.audit("queue_full", map[string]string{"agent": a.name, "type": m.Type})
	}
}
func (s *Server) handlePluginMessage(a *agent, m wire.Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch m.Type {
	case "capabilities":
		if m.APIVersion != plugin.APIVersion || m.OS != "linux" || (m.Arch != "amd64" && m.Arch != "arm64") {
			s.audit("plugin_capability_rejected", map[string]string{"agent": a.name})
			return
		}
		a.platformOS = m.OS
		a.platformArch = m.Arch
		a.installed = m.Installed
		a.active = m.Active
		s.offerCatalogLocked(a)
	case "catalog_request":
		if a.platformOS != "" && m.CatalogVersion != s.catalogVersion {
			s.offerCatalogLocked(a)
		} else if a.platformOS != "" {
			s.queuePluginLocked(a, wire.Message{Type: "catalog_version", CatalogVersion: s.catalogVersion})
		}
	case "plugin_chunk_request":
		release, ok := s.catalog[m.PluginID][m.Version]
		if !ok || (s.desired[a.name][m.PluginID] != m.Version && s.activeDesired[a.name][m.PluginID] != m.Version) {
			s.audit("plugin_transfer_denied", map[string]string{"agent": a.name, "plugin_id": m.PluginID})
			return
		}
		artifact, err := release.manifest.ArtifactFor(a.platformOS, a.platformArch)
		if err != nil || artifact.SHA256 != m.Hash || m.Offset < 0 || m.Offset >= artifact.Size {
			s.audit("plugin_transfer_denied", map[string]string{"agent": a.name, "plugin_id": m.PluginID})
			return
		}
		end := m.Offset + plugin.ChunkSize
		if end > artifact.Size {
			end = artifact.Size
		}
		data := base64.StdEncoding.EncodeToString(release.artifacts[a.platformOS+"/"+a.platformArch][m.Offset:end])
		s.queuePluginLocked(a, wire.Message{Type: "plugin_chunk", PluginID: m.PluginID, Version: m.Version, Hash: m.Hash, Offset: m.Offset, Data: data, Final: end == artifact.Size})
	case "plugin_install_result":
		a.pluginInFlight = false
		fields := map[string]string{"agent": a.name, "plugin_id": m.PluginID, "plugin_version": m.Version, "hash": m.Hash, "error": m.Error}
		s.audit("plugin_install_result", fields)
		if m.Error == "" {
			if a.installed == nil {
				a.installed = map[string][]string{}
			}
			found := false
			for _, v := range a.installed[m.PluginID] {
				if v == m.Version {
					found = true
					break
				}
			}
			if !found {
				a.installed[m.PluginID] = append(a.installed[m.PluginID], m.Version)
			}
		}
		if m.Error == "" && s.activeDesired[a.name][m.PluginID] == m.Version {
			s.queuePluginLocked(a, wire.Message{Type: "plugin_activate", PluginID: m.PluginID, Version: m.Version, ID: m.ID})
		}
		s.offerNextLocked(a)
	case "plugin_activate_result":
		s.audit("plugin_activate_result", map[string]string{"agent": a.name, "plugin_id": m.PluginID, "plugin_version": m.Version, "error": m.Error})
		if m.Error == "" {
			if a.active == nil {
				a.active = map[string]string{}
			}
			a.active[m.PluginID] = m.Version
			if err := s.saveCatalogLocked(); err != nil {
				s.audit("catalog_save_failed", map[string]string{"error": err.Error()})
			}
		}
	case "plugin_rollback_result":
		s.audit("plugin_rollback_result", map[string]string{"agent": a.name, "plugin_id": m.PluginID, "plugin_version": m.Version, "error": m.Error})
		if m.Error == "" {
			if _, ok := s.catalog[m.PluginID][m.Version]; !ok {
				s.audit("plugin_rollback_rejected", map[string]string{"agent": a.name, "plugin_id": m.PluginID})
				return
			}
			if a.active == nil {
				a.active = map[string]string{}
			}
			a.active[m.PluginID] = m.Version
			s.activeDesired[a.name][m.PluginID] = m.Version
			s.desired[a.name][m.PluginID] = m.Version
			if err := s.saveCatalogLocked(); err != nil {
				s.audit("catalog_save_failed", map[string]string{"error": err.Error()})
			}
		}
	default:
		s.audit("invalid_message", map[string]string{"agent": a.name, "type": strings.TrimSpace(m.Type)})
	}
}

// SetDesired assigns one published release to an agent and notifies it.
func (s *Server) SetDesired(agentName, id, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.cfg.Permissions[agentName]; !ok {
		return errors.New("unprovisioned agent")
	}
	release, ok := s.catalog[id][v]
	if !ok {
		return errors.New("unknown plugin release")
	}
	if s.desired[agentName] == nil {
		s.desired[agentName] = map[string]string{}
	}
	old := s.desired[agentName][id]
	s.desired[agentName][id] = v
	if err := s.saveCatalogLocked(); err != nil {
		if old == "" {
			delete(s.desired[agentName], id)
		} else {
			s.desired[agentName][id] = old
		}
		return err
	}
	if a := s.agents[agentName]; a != nil {
		a.pluginOffers = append(a.pluginOffers, wire.Message{Type: "plugin_manifest", PluginID: id, Version: v, Manifest: release.raw, CatalogVersion: s.catalogVersion})
		s.offerNextLocked(a)
	}
	s.audit("plugin_assigned", map[string]string{"agent": agentName, "plugin_id": id, "plugin_version": v, "publisher": release.manifest.PublisherKeyID})
	return nil
}

// Activate requests activation of a previously assigned release.
func (s *Server) Activate(agentName, id, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.desired[agentName][id] != v {
		return errors.New("release is not assigned")
	}
	if s.activeDesired[agentName] == nil {
		s.activeDesired[agentName] = map[string]string{}
	}
	old := s.activeDesired[agentName][id]
	s.activeDesired[agentName][id] = v
	if err := s.saveCatalogLocked(); err != nil {
		if old == "" {
			delete(s.activeDesired[agentName], id)
		} else {
			s.activeDesired[agentName][id] = old
		}
		return err
	}
	if a := s.agents[agentName]; a != nil {
		for _, installed := range a.installed[id] {
			if installed == v {
				s.queuePluginLocked(a, wire.Message{Type: "plugin_activate", PluginID: id, Version: v})
				break
			}
		}
	}
	s.audit("plugin_activation_requested", map[string]string{"agent": agentName, "plugin_id": id, "plugin_version": v})
	return nil
}

// Rollback asks a connected agent to restore its previous verified release.
func (s *Server) Rollback(agentName, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.agents[agentName]
	if a == nil {
		return errors.New("agent is not connected")
	}
	if s.activeDesired[agentName][id] == "" {
		return errors.New("plugin is not active")
	}
	s.queuePluginLocked(a, wire.Message{Type: "plugin_rollback", PluginID: id})
	s.audit("plugin_rollback_requested", map[string]string{"agent": agentName, "plugin_id": id})
	return nil
}
func (s *Server) saveCatalogLocked() error {
	if s.cfg.CatalogPath == "" {
		return nil
	}
	raw, err := os.ReadFile(s.cfg.CatalogPath)
	if err != nil {
		return err
	}
	var doc catalogFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	doc.Desired = s.desired
	doc.Active = s.activeDesired
	updated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	updated = append(updated, '\n')
	path := s.cfg.CatalogPath
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, updated, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	s.catalogVersion = plugin.Hash(updated)
	return nil
}

// PluginInfo describes an installed version reported by the connected agent.
type PluginInfo struct {
	PluginID string `json:"plugin_id"`
	Version  string `json:"version"`
	Active   bool   `json:"active"`
	Desired  bool   `json:"desired"`
}

func (s *Server) Plugins(name string) ([]PluginInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a := s.agents[name]
	if a == nil {
		return nil, fmt.Errorf("agent %q is not connected", name)
	}
	plugins := []PluginInfo{}
	for id, versions := range a.installed {
		for _, v := range versions {
			plugins = append(plugins, PluginInfo{PluginID: id, Version: v, Active: a.active[id] == v, Desired: s.desired[name][id] == v})
		}
	}
	sort.Slice(plugins, func(i, j int) bool {
		if plugins[i].PluginID == plugins[j].PluginID {
			return plugins[i].Version < plugins[j].Version
		}
		return plugins[i].PluginID < plugins[j].PluginID
	})
	return plugins, nil
}
