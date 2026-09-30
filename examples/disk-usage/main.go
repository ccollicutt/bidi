package main

import (
	"encoding/json"
	"os"
	"syscall"
)

func main() {
	var req struct {
		APIVersion int    `json:"api_version"`
		Action     string `json:"action"`
		CommandID  string `json:"command_id"`
		Input      struct {
			Path string `json:"path"`
		} `json:"input"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		os.Exit(2)
	}
	result := map[string]any{"command_id": req.CommandID}
	if req.APIVersion != 1 || req.Action != "disk-usage.measure" || req.CommandID == "" || req.Input.Path != "/tmp" {
		result["error"] = "invalid request"
	} else {
		var stats syscall.Statfs_t
		if err := syscall.Statfs(req.Input.Path, &stats); err != nil {
			result["error"] = "measurement failed"
		} else {
			result["output"] = map[string]any{"path": req.Input.Path, "total_bytes": stats.Blocks * uint64(stats.Bsize), "free_bytes": stats.Bavail * uint64(stats.Bsize)}
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
