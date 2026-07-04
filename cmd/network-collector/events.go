package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/orchestrator"
)

type lifecycleEvent = orchestrator.Event
type eventSink = orchestrator.EventSink

type eventDispatcher struct {
	runID string
	sinks []eventSink
}

func (d *eventDispatcher) emit(event lifecycleEvent) {
	if d == nil {
		return
	}
	event.RunID = d.runID
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	for _, sink := range d.sinks {
		if err := sink.Handle(context.Background(), event); err != nil {
			slog.Warn("lifecycle event sink failed", "event", event.Type, "error", err)
		}
	}
}

func (d *eventDispatcher) close() {
	if d == nil {
		return
	}
	for _, sink := range d.sinks {
		if err := sink.Close(); err != nil {
			slog.Warn("error closing lifecycle event sink", "error", err)
		}
	}
}

func newJSONLEventSink(path string) (eventSink, error) {
	return orchestrator.NewJSONLSink(path)
}
