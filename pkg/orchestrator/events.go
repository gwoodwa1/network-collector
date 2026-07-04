package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Event struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	RunID     string                 `json:"run_id,omitempty"`
	Hostname  string                 `json:"hostname,omitempty"`
	IP        string                 `json:"ip,omitempty"`
	Step      string                 `json:"step,omitempty"`
	Failed    *bool                  `json:"failed,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

type EventSink interface {
	Handle(context.Context, Event) error
	Close() error
}

type JSONLSink struct {
	mu     sync.Mutex
	writer io.WriteCloser
}

func NewJSONLSink(path string) (*JSONLSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create event output directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("open event output: %w", err)
	}
	return &JSONLSink{writer: file}, nil
}

func (s *JSONLSink) Handle(_ context.Context, event Event) error {
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.writer.Write(append(encoded, '\n'))
	return err
}

func (s *JSONLSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writer.Close()
}

type DeviceOutcome struct {
	Hostname string        `json:"hostname"`
	IP       string        `json:"ip,omitempty"`
	Failed   bool          `json:"failed"`
	Duration time.Duration `json:"duration_ns,omitempty"`
}
