package traffic

import (
	"io"
	"net"
	"testing"
)

type partialConn struct{ net.Conn }

func (partialConn) Read(p []byte) (int, error)  { copy(p, "abc"); return 3, io.EOF }
func (partialConn) Write(p []byte) (int, error) { return 2, io.ErrShortWrite }

func TestCountsActualBytesIncludingPartialErrors(t *testing.T) {
	c, err := NewConn(partialConn{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 10)); err != io.EOF {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("hello")); err != io.ErrShortWrite {
		t.Fatal(err)
	}
	sample := c.Snapshot()
	if sample.ReceivedBytes != 3 || sample.SentBytes != 2 || len(sample.SessionID) != 32 || sample.ElapsedSeconds <= 0 {
		t.Fatalf("sample: %+v", sample)
	}
	next, err := NewConn(partialConn{})
	if err != nil {
		t.Fatal(err)
	}
	if next.Snapshot().SessionID == sample.SessionID || next.Snapshot().SentBytes != 0 {
		t.Fatal("new connection did not reset")
	}
}
