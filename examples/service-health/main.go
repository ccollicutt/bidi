package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"
)

type serviceTarget struct {
	Address string `json:"address"`
	Path    string `json:"path"`
}

func main() {
	var req struct {
		APIVersion int    `json:"api_version"`
		Action     string `json:"action"`
		CommandID  string `json:"command_id"`
		Input      struct {
			ServiceID string `json:"service_id"`
		} `json:"input"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		os.Exit(2)
	}
	result := map[string]any{"command_id": req.CommandID}
	var services map[string]serviceTarget
	configErr := json.Unmarshal([]byte(os.Getenv("BIDI_SERVICES_JSON")), &services)
	target, allowed := services[req.Input.ServiceID]
	if req.APIVersion != 1 || req.Action != "service-health.check" || req.CommandID == "" {
		result["error"] = "invalid request"
	} else if configErr != nil || !allowed {
		result["error"] = "service denied"
	} else {
		transport := &http.Transport{Proxy: nil}
		defer transport.CloseIdleConnections()
		client := http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect denied") }}
		started := time.Now()
		response, err := client.Get("http://" + target.Address + target.Path)
		if err != nil {
			result["error"] = "service request failed"
		} else {
			response.Body.Close()
			result["output"] = map[string]any{"service_id": req.Input.ServiceID, "status": response.StatusCode, "latency_ms": time.Since(started).Milliseconds()}
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
