package main

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestJSONLEventSink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	sink, err := newJSONLEventSink(path)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &eventDispatcher{runID: "run-test", sinks: []eventSink{sink}}
	dispatcher.emit(lifecycleEvent{Type: "run.started"})
	dispatcher.emit(lifecycleEvent{Type: "device.started", Hostname: "router-1"})
	dispatcher.close()

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		var event lifecycleEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if event.RunID != "run-test" {
			t.Fatalf("unexpected run ID: %q", event.RunID)
		}
		count++
	}
	if count != 2 {
		t.Fatalf("got %d events, want 2", count)
	}
}

type failingEventSink struct{}

func (failingEventSink) Handle(context.Context, lifecycleEvent) error { return os.ErrPermission }
func (failingEventSink) Close() error                                 { return nil }

func TestEventDispatcherSinkFailureIsNonFatal(t *testing.T) {
	dispatcher := &eventDispatcher{sinks: []eventSink{failingEventSink{}}}
	dispatcher.emit(lifecycleEvent{Type: "test"})
}
