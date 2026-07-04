package orchestrator

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompileSelector(t *testing.T) {
	selector, err := CompileSelector(`site=london and (role=core or hostname=edge-1) and not maintenance=true`)
	if err != nil {
		t.Fatal(err)
	}
	if !selector(Target{Hostname: "core-1", Labels: map[string]string{"site": "London", "role": "core"}}) {
		t.Fatal("expected target to match")
	}
	if selector(Target{Hostname: "core-1", Labels: map[string]string{"site": "london", "role": "core", "maintenance": "true"}}) {
		t.Fatal("excluded target matched")
	}
}

func TestRunBoundsConcurrency(t *testing.T) {
	var active, peak atomic.Int32
	outcomes, stopped := Run(context.Background(), []int{1, 2, 3, 4, 5}, Policy{MaxParallel: 2}, func(_ context.Context, index, item int) Outcome[int] {
		current := active.Add(1)
		for {
			previous := peak.Load()
			if current <= previous || peak.CompareAndSwap(previous, current) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		active.Add(-1)
		return Outcome[int]{Index: index, Value: item}
	})
	if stopped || len(outcomes) != 5 || peak.Load() > 2 {
		t.Fatalf("unexpected execution: stopped=%v outcomes=%d peak=%d", stopped, len(outcomes), peak.Load())
	}
}

func TestRunStopsAfterFailedCanary(t *testing.T) {
	var calls atomic.Int32
	outcomes, stopped := Run(context.Background(), []int{1, 2, 3}, Policy{MaxParallel: 1, CanaryCount: 1}, func(_ context.Context, index, item int) Outcome[int] {
		calls.Add(1)
		return Outcome[int]{Index: index, Value: item, Failed: true}
	})
	if !stopped || calls.Load() != 1 || len(outcomes) != 1 {
		t.Fatalf("canary did not stop execution: stopped=%v calls=%d outcomes=%d", stopped, calls.Load(), len(outcomes))
	}
}

func TestRunHonoursFailureThreshold(t *testing.T) {
	var calls atomic.Int32
	_, stopped := Run(context.Background(), []int{1, 2, 3, 4}, Policy{MaxParallel: 1, FailureThreshold: 2}, func(_ context.Context, index, item int) Outcome[int] {
		calls.Add(1)
		return Outcome[int]{Index: index, Value: item, Failed: true}
	})
	if !stopped || calls.Load() != 2 {
		t.Fatalf("failure threshold not enforced: stopped=%v calls=%d", stopped, calls.Load())
	}
}

func TestJSONLSink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	sink, err := NewJSONLSink(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Handle(context.Background(), Event{Type: "run.started", RunID: "run-test"}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		t.Fatal("event file is empty")
	}
	var event Event
	if err := json.Unmarshal(scanner.Bytes(), &event); err != nil || event.RunID != "run-test" {
		t.Fatalf("unexpected event: %+v error=%v", event, err)
	}
}
