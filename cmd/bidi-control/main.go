package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/ccollicutt/bidi/internal/server"
)

func main() {
	socket := flag.String("socket", ".dev-plugins/control.sock", "local operator socket")
	operation := flag.String("operation", "run", "plugins, run, install, activate, rollback, or reload")
	agent := flag.String("agent", "agent-1", "target agent")
	action := flag.String("action", "", "action name")
	input := flag.String("input", "{}", "JSON input, or text for status/echo aliases")
	id := flag.String("plugin", "", "plugin ID")
	version := flag.String("version", "", "plugin version")
	flag.Parse()
	conn, err := net.DialTimeout("unix", *socket, 3*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(conn).Encode(server.ControlRequest{Operation: *operation, Agent: *agent, Action: *action, Input: *input, Plugin: *id, Version: *version}); err != nil {
		log.Fatal(err)
	}
	var result server.ControlResult
	if err := json.NewDecoder(conn).Decode(&result); err != nil {
		log.Fatal(err)
	}
	if result.Error != "" {
		log.Fatal(result.Error)
	}
	if *operation == "plugins" {
		fmt.Printf("plugins on %s (%d installed versions):\n", *agent, len(result.Plugins))
		for _, p := range result.Plugins {
			state := "installed"
			if p.Active {
				state = "active"
			}
			if p.Desired {
				state += " (desired)"
			}
			fmt.Printf("  %-20s %-12s %s\n", p.PluginID, p.Version, state)
		}
	} else if result.ID != "" {
		fmt.Println("queued command", result.ID, "(result appears in the server terminal)")
	} else {
		fmt.Println("operator command accepted")
	}
}
