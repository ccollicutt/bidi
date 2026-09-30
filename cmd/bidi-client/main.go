package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ccollicutt/bidi/internal/client"
	"github.com/ccollicutt/bidi/internal/plugin"
)

func main() {
	addr := flag.String("addr", "localhost:8443", "server address")
	ca := flag.String("ca", "certs/ca.crt", "trusted server CA")
	cert := flag.String("cert", "certs/agent.crt", "agent certificate")
	key := flag.String("key", "certs/agent.key", "agent private key")
	name := flag.String("name", "agent-1", "agent name; must match certificate CN")
	pluginDir := flag.String("plugin-dir", "", "protected plugin storage directory; empty disables plugins")
	trustFile := flag.String("publisher-keys", "", "JSON map of publisher IDs to base64 Ed25519 public keys")
	pluginAllow := flag.String("plugin-allow", "", "comma-separated locally allowlisted plugin IDs")
	pluginReadPaths := flag.String("plugin-read-paths", "", "comma-separated filesystem paths allowed for read-only plugin capabilities")
	pluginServices := flag.String("plugin-services", "", "JSON map of approved service IDs to address and path")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var manager *plugin.Manager
	if *pluginDir != "" {
		if *trustFile == "" {
			log.Fatal("-publisher-keys is required with -plugin-dir")
		}
		raw, err := os.ReadFile(*trustFile)
		if err != nil {
			log.Fatal(err)
		}
		var encoded map[string]string
		if err := json.Unmarshal(raw, &encoded); err != nil {
			log.Fatal(err)
		}
		keys := map[string]ed25519.PublicKey{}
		for id, value := range encoded {
			key, err := base64.StdEncoding.DecodeString(value)
			if err != nil || len(key) != ed25519.PublicKeySize {
				log.Fatalf("invalid publisher key %s", id)
			}
			keys[id] = key
		}
		allow := map[string]bool{}
		for _, id := range strings.Split(*pluginAllow, ",") {
			if id != "" {
				allow[id] = true
			}
		}
		var paths []string
		for _, path := range strings.Split(*pluginReadPaths, ",") {
			if path != "" {
				paths = append(paths, path)
			}
		}
		services := map[string]plugin.ServiceTarget{}
		var network []string
		if *pluginServices != "" {
			raw, err := os.ReadFile(*pluginServices)
			if err != nil {
				log.Fatal(err)
			}
			if err := json.Unmarshal(raw, &services); err != nil {
				log.Fatal(err)
			}
			for _, target := range services {
				network = append(network, target.Address)
			}
		}
		manager, err = plugin.NewManager(plugin.Policy{Keys: keys, Plugins: allow, FilesystemRead: paths, Network: network, Services: services, Storage: *pluginDir})
		if err != nil {
			log.Fatal(err)
		}
	}
	input := make(chan string, 16)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			select {
			case input <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
		close(input)
	}()
	if err := client.Run(ctx, client.Config{Address: *addr, CAFile: *ca, CertFile: *cert, KeyFile: *key, Name: *name, Input: input, Plugins: manager}); err != nil {
		log.Fatal(err)
	}
}
