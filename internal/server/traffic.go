package server

import (
	"encoding/hex"
	"math"
	"strconv"
	"time"

	"github.com/ccollicutt/bidi/internal/traffic"
)

// TrafficReading contains agent-reported counts and the server's receipt time.
// Rates use elapsed time on the agent, avoiding changes to its wall clock.
type TrafficReading struct {
	traffic.Snapshot
	ReceivedAt             time.Time `json:"received_at"`
	IntervalSeconds        float64   `json:"interval_seconds"`
	SentBytesPerSecond     float64   `json:"sent_bytes_per_second"`
	ReceivedBytesPerSecond float64   `json:"received_bytes_per_second"`
}

func (s *Server) recordTraffic(a *agent, sample *traffic.Snapshot) {
	// Older agents can still send plain heartbeats.
	if sample == nil {
		return
	}
	id, err := hex.DecodeString(sample.SessionID)
	if err != nil || len(id) != 16 || sample.ElapsedSeconds < 0 || math.IsInf(sample.ElapsedSeconds, 0) || math.IsNaN(sample.ElapsedSeconds) {
		return
	}
	reading := &TrafficReading{Snapshot: *sample, ReceivedAt: time.Now().UTC()}
	s.mu.Lock()
	if previous := a.traffic; previous != nil {
		// The session ID is fixed by hello. A reconnect creates a fresh agent record.
		if previous.SessionID != sample.SessionID || sample.SentBytes < previous.SentBytes || sample.ReceivedBytes < previous.ReceivedBytes || sample.ElapsedSeconds <= previous.ElapsedSeconds {
			s.mu.Unlock()
			return
		}
		reading.IntervalSeconds = sample.ElapsedSeconds - previous.ElapsedSeconds
		reading.SentBytesPerSecond = float64(sample.SentBytes-previous.SentBytes) / reading.IntervalSeconds
		reading.ReceivedBytesPerSecond = float64(sample.ReceivedBytes-previous.ReceivedBytes) / reading.IntervalSeconds
	} else if sample.ElapsedSeconds > 0 {
		reading.IntervalSeconds = sample.ElapsedSeconds
		reading.SentBytesPerSecond = float64(sample.SentBytes) / sample.ElapsedSeconds
		reading.ReceivedBytesPerSecond = float64(sample.ReceivedBytes) / sample.ElapsedSeconds
	}
	a.traffic = reading
	s.mu.Unlock()
	f := func(value float64) string { return strconv.FormatFloat(value, 'f', 3, 64) }
	s.audit("traffic_sample", map[string]string{
		"agent": a.name, "session_id": sample.SessionID,
		"received_at":     reading.ReceivedAt.Format(time.RFC3339Nano),
		"sent_bytes":      strconv.FormatUint(sample.SentBytes, 10),
		"received_bytes":  strconv.FormatUint(sample.ReceivedBytes, 10),
		"elapsed_seconds": f(sample.ElapsedSeconds), "interval_seconds": f(reading.IntervalSeconds),
		"sent_bytes_per_second":     f(reading.SentBytesPerSecond),
		"received_bytes_per_second": f(reading.ReceivedBytesPerSecond),
	})
}
