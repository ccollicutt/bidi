package main

import (
	"encoding/json"
	"os"
	"runtime"
)

func main() {
	var request struct {
		APIVersion int    `json:"api_version"`
		Action     string `json:"action"`
		CommandID  string `json:"command_id"`
		Input      struct {
			Agent string `json:"agent"`
		} `json:"input"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		os.Exit(2)
	}
	result := map[string]any{"command_id": request.CommandID}
	if request.APIVersion != 1 || request.Action != "status.get" || request.CommandID == "" || request.Input.Agent == "" {
		result["error"] = "invalid request"
	} else {
		result["output"] = map[string]string{"text": "agent=" + request.Input.Agent + " os=" + runtime.GOOS + " arch=" + runtime.GOARCH}
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
