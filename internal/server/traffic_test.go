package server

import (
	"io"
	"log"
	"math"
	"testing"

	"github.com/ccollicutt/bidi/internal/traffic"
)

func TestTrafficRatesAndInvalidSamples(t *testing.T) {
	s := New(Config{Logger: log.New(io.Discard, "", 0)})
	a := &agent{name: "agent-1"}
	sample := traffic.Snapshot{SessionID: "00112233445566778899aabbccddeeff", SentBytes: 1000, ReceivedBytes: 500, ElapsedSeconds: 10}
	s.recordTraffic(a, &sample)
	if a.traffic == nil || a.traffic.SentBytesPerSecond != 100 || a.traffic.ReceivedAt.IsZero() {
		t.Fatalf("initial sample: %+v", a.traffic)
	}
	sample.SentBytes = 1500
	sample.ReceivedBytes = 700
	sample.ElapsedSeconds = 20
	s.recordTraffic(a, &sample)
	if a.traffic.SentBytesPerSecond != 50 || a.traffic.ReceivedBytesPerSecond != 20 || a.traffic.IntervalSeconds != 10 {
		t.Fatalf("rates: %+v", a.traffic)
	}
	previous := a.traffic
	for _, tc := range []struct {
		name   string
		change func(*traffic.Snapshot)
	}{
		{"changed session", func(p *traffic.Snapshot) { p.SessionID = "11112233445566778899aabbccddeeff" }},
		{"sent reset", func(p *traffic.Snapshot) { p.SentBytes = 0 }},
		{"received reset", func(p *traffic.Snapshot) { p.ReceivedBytes = 0 }},
		{"elapsed reset", func(p *traffic.Snapshot) { p.ElapsedSeconds = 1 }},
		{"nonfinite time", func(p *traffic.Snapshot) { p.ElapsedSeconds = math.Inf(1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := sample
			invalid.ElapsedSeconds = 30
			tc.change(&invalid)
			s.recordTraffic(a, &invalid)
			if a.traffic != previous {
				t.Fatal("invalid reading accepted")
			}
		})
	}
	s.recordTraffic(a, nil)
	if a.traffic != previous {
		t.Fatal("legacy heartbeat changed sample")
	}
	reconnect := &agent{name: "agent-1"}
	sample.SessionID = "11112233445566778899aabbccddeeff"
	sample.SentBytes = 100
	sample.ReceivedBytes = 50
	sample.ElapsedSeconds = 1
	s.recordTraffic(reconnect, &sample)
	if reconnect.traffic == nil || reconnect.traffic.SentBytesPerSecond != 100 {
		t.Fatal("reconnect did not start fresh session")
	}
}
