package main

import (
	"encoding/json"
	"os"
	"syscall"
)

func main() {
	var req struct {
		APIVersion int            `json:"api_version"`
		Action     string         `json:"action"`
		CommandID  string         `json:"command_id"`
		Input      map[string]any `json:"input"`
	}
	if json.NewDecoder(os.Stdin).Decode(&req) != nil {
		os.Exit(2)
	}
	result := map[string]any{"command_id": req.CommandID}
	var info syscall.Sysinfo_t
	if req.APIVersion != 1 || req.Action != "uptime.get" || req.CommandID == "" || len(req.Input) != 0 {
		result["error"] = "invalid request"
	} else if syscall.Sysinfo(&info) != nil {
		result["error"] = "uptime unavailable"
	} else {
		result["output"] = map[string]int64{"uptime_seconds": info.Uptime}
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
