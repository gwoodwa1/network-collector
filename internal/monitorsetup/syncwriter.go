package monitorsetup

import (
	"io"
	"sync"
)

// SyncWriter serializes concurrent Write calls to w with a mutex. Every
// device in a run polls on its own goroutine; fmt.Fprintf and io.MultiWriter
// give no atomicity guarantee of their own, so without this, two devices'
// status lines (or, for cmd/routing-monitor, two devices on different
// platforms) can splice together mid-line on the terminal or in
// session.log.
type SyncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func NewSyncWriter(w io.Writer) *SyncWriter {
	return &SyncWriter{w: w}
}

func (s *SyncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}
