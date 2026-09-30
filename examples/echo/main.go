package main

import (
	"encoding/json"
	"os"
)

func main() {
	var request struct {
		APIVersion int    `json:"api_version"`
		Action     string `json:"action"`
		CommandID  string `json:"command_id"`
		Input      struct {
			Text string `json:"text"`
		} `json:"input"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		os.Exit(2)
	}
	result := map[string]any{"command_id": request.CommandID}
	if request.APIVersion != 1 || request.Action != "echo.repeat" || request.CommandID == "" {
		result["error"] = "invalid request"
	} else {
		result["output"] = map[string]string{"text": request.Input.Text}
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
