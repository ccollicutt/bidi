package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ccollicutt/bidi/internal/server"
	"github.com/peterh/liner"
)

type console struct {
	mu      sync.Mutex
	waiting bool
}

func (c *console) promptStarted() {
	c.mu.Lock()
	c.waiting = true
	c.mu.Unlock()
}

func (c *console) commandStarted() {
	c.mu.Lock()
	c.waiting = false
	c.mu.Unlock()
}

func (c *console) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.waiting {
		fmt.Println()
	}
	n, err := os.Stdout.Write(p)
	if c.waiting {
		fmt.Print("> ")
	}
	return n, err
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "listen address")
	ca := flag.String("ca", "certs/ca.crt", "trusted client CA")
	cert := flag.String("cert", "certs/server.crt", "server certificate")
	key := flag.String("key", "certs/server.key", "server private key")
	permissionsFile := flag.String("permissions", "permissions.json", "JSON map of agent names to permitted actions")
	catalogFile := flag.String("catalog", "", "plugin catalog JSON path")
	auditFile := flag.String("audit", "audit.log", "append-only JSON audit log path")
	controlSocket := flag.String("control-socket", "", "optional owner-only local operator socket")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	permissionBytes, err := os.ReadFile(*permissionsFile)
	if err != nil {
		log.Fatal(err)
	}
	var permissions map[string][]string
	if err := json.Unmarshal(permissionBytes, &permissions); err != nil {
		log.Fatal(err)
	}
	audit, err := os.OpenFile(*auditFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer audit.Close()
	terminal := &console{}
	s := server.New(server.Config{Address: *addr, CAFile: *ca, CertFile: *cert, KeyFile: *key, Permissions: permissions, CatalogPath: *catalogFile, PermissionsPath: *permissionsFile, Audit: log.New(audit, "", 0), Logger: log.New(terminal, "", log.LstdFlags)})
	if *controlSocket != "" {
		listener, err := s.ListenControl(ctx, *controlSocket)
		if err != nil {
			log.Fatal(err)
		}
		defer listener.Close()
	}
	go func() {
		lineEditor := liner.NewLiner()
		defer lineEditor.Close()
		printHelp()
		for {
			terminal.promptStarted()
			entered, err := lineEditor.Prompt("> ")
			terminal.commandStarted()
			if err != nil {
				return
			}
			line := strings.TrimSpace(entered)
			if line != "" {
				lineEditor.AppendHistory(line)
			}
			parts := strings.SplitN(line, " ", 3)
			if len(parts) > 1 && parts[0] == "plugin" && parts[1] == "list" {
				parts[0] = "plugins"
			}
			switch parts[0] {
			case "help", "?":
				printHelp()
			case "list":
				agents := s.Agents()
				fmt.Printf("agents (%d connections): %v\n", len(agents), agents)
			case "plugins":
				agentName := ""
				if len(parts) == 3 && parts[1] == "list" {
					agentName = strings.TrimSpace(parts[2])
				} else if len(parts) == 2 && parts[1] != "list" {
					agentName = parts[1]
				}
				if agentName == "" || strings.ContainsAny(agentName, " \t") {
					fmt.Println("usage: plugins list AGENT")
					continue
				}
				plugins, err := s.Plugins(agentName)
				if err != nil {
					fmt.Println("error:", err)
					continue
				}
				fmt.Printf("plugins on %s (%d installed versions):\n", agentName, len(plugins))
				for _, p := range plugins {
					state := "installed"
					if p.Active {
						state = "active"
					}
					if p.Desired {
						state += " (desired)"
					}
					fmt.Printf("  %-20s %-12s %s\n", p.PluginID, p.Version, state)
				}
			case "connections", "conn":
				connections := s.Connections()
				fmt.Printf("open agent connections: %d\n", len(connections))
				for _, connection := range connections {
					fmt.Printf("  %s  remote=%s  local=%s  cert-serial=%s  since=%s  duration=%s\n",
						connection.Agent, connection.RemoteAddress, connection.LocalAddress,
						connection.CertificateSerial, connection.ConnectedAt.Local().Format("2006-01-02 15:04:05 MST"),
						time.Since(connection.ConnectedAt).Truncate(time.Second))
				}
			case "quit":
				stop()
				return
			case "status":
				if len(parts) < 2 {
					fmt.Println("usage: status AGENT")
					continue
				}
				id, err := s.Send(parts[1], "status", "")
				printResult(id, err)
			case "send":
				if len(parts) < 3 {
					fmt.Println("usage: send AGENT TEXT")
					continue
				}
				if err := s.SendMessage(parts[1], messageText(parts[2])); err != nil {
					fmt.Println("error:", err)
				} else {
					fmt.Printf("message queued for %s\n", parts[1])
				}
			case "echo":
				if len(parts) < 3 {
					fmt.Printf("usage: %s AGENT TEXT\n", parts[0])
					continue
				}
				id, err := s.Send(parts[1], "echo", messageText(parts[2]))
				printResult(id, err)
			case "run":
				if len(parts) < 3 {
					fmt.Println("usage: run AGENT PLUGIN_OR_ACTION [JSON]")
					continue
				}
				rest := strings.SplitN(parts[2], " ", 2)
				input := ""
				if len(rest) == 2 {
					input = strings.TrimSpace(rest[1])
				}
				id, err := s.Send(parts[1], rest[0], input)
				printResult(id, err)
			case "plugin":
				if len(parts) < 3 {
					fmt.Println("usage: plugin install|activate AGENT PLUGIN VERSION")
					continue
				}
				rest := strings.Fields(parts[2])
				if len(rest) != 3 && !(parts[1] == "rollback" && len(rest) == 2) {
					fmt.Println("usage: plugin install|activate AGENT PLUGIN VERSION; plugin rollback AGENT PLUGIN")
					continue
				}
				var err error
				switch parts[1] {
				case "install":
					err = s.SetDesired(rest[0], rest[1], rest[2])
				case "activate":
					err = s.Activate(rest[0], rest[1], rest[2])
				case "rollback":
					err = s.Rollback(rest[0], rest[1])
				default:
					err = fmt.Errorf("unknown plugin command")
				}
				if err != nil {
					fmt.Println("error:", err)
				}
			case "":
			default:
				fmt.Println("unknown command")
			}
		}
	}()
	if err := s.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

func printHelp() {
	fmt.Println("Commands:")
	fmt.Println("  list                 show connected agents")
	fmt.Println("  plugins list AGENT   show installed and active plugin versions")
	fmt.Println("  connections or conn  show sockets and session durations")
	fmt.Println("  send AGENT TEXT      display text on the agent")
	fmt.Println("  status AGENT         request agent status")
	fmt.Println("  echo AGENT TEXT      request an echoed result")
	fmt.Println("  run AGENT PLUGIN_OR_ACTION [JSON] run a plugin (input defaults to {})")
	fmt.Println("  plugin install AGENT PLUGIN VERSION assign a plugin release")
	fmt.Println("  plugin activate AGENT PLUGIN VERSION activate an assigned release")
	fmt.Println("  plugin rollback AGENT PLUGIN restore the previous verified release")
	fmt.Println("  help or ?            show this help")
	fmt.Println("  quit                 stop the server")
}

func messageText(text string) string {
	if len(text) >= 2 && ((text[0] == '"' && text[len(text)-1] == '"') || (text[0] == '\'' && text[len(text)-1] == '\'')) {
		return text[1 : len(text)-1]
	}
	return text
}

func printResult(id string, err error) {
	if err != nil {
		fmt.Println("error:", err)
	} else if id != "" {
		fmt.Println("request id:", id)
	}
}
