// Package orchestrator provides reusable inventory targeting, lifecycle events,
// result types, and bounded execution policies for network automation programs.
package orchestrator

import (
	"context"
	"sync"
	"time"
)

type Policy struct {
	MaxParallel      int
	StartInterval    time.Duration
	CanaryCount      int
	FailureThreshold int
}

type Outcome[T any] struct {
	Index  int
	Value  T
	Failed bool
}

type Executor[T, R any] func(context.Context, int, T) Outcome[R]

// Run executes items with bounded concurrency. Canaries form a separate first
// stage and all must succeed. Once FailureThreshold is reached, no new work is
// launched; already-running work is allowed to complete.
func Run[T, R any](ctx context.Context, items []T, policy Policy, execute Executor[T, R]) ([]Outcome[R], bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	canaryCount := policy.CanaryCount
	if canaryCount > len(items) {
		canaryCount = len(items)
	}
	if canaryCount < 0 {
		canaryCount = 0
	}
	results := make([]Outcome[R], 0, len(items))
	lastStart := time.Time{}
	failures := 0
	if canaryCount > 0 {
		canaryPolicy := policy
		canaryPolicy.FailureThreshold = 0
		stage, stageFailures, stopped := runBatch(ctx, items[:canaryCount], 0, canaryPolicy, &lastStart, execute)
		results = append(results, stage...)
		failures += stageFailures
		if stopped || stageFailures > 0 {
			return results, true
		}
	}
	remaining := policy
	if remaining.FailureThreshold > 0 {
		remaining.FailureThreshold -= failures
	}
	stage, _, stopped := runBatch(ctx, items[canaryCount:], canaryCount, remaining, &lastStart, execute)
	results = append(results, stage...)
	return results, stopped
}

func runBatch[T, R any](ctx context.Context, items []T, offset int, policy Policy, lastStart *time.Time, execute Executor[T, R]) ([]Outcome[R], int, bool) {
	maxParallel := policy.MaxParallel
	if maxParallel <= 0 {
		maxParallel = 1
	}
	completed := make(chan Outcome[R], len(items))
	results := make([]Outcome[R], 0, len(items))
	active, failures, next := 0, 0, 0
	stopped := false
	var wg sync.WaitGroup

	receive := func() {
		result := <-completed
		active--
		if result.Failed {
			failures++
		}
		results = append(results, result)
	}

	for next < len(items) {
		if ctx.Err() != nil || policy.FailureThreshold > 0 && failures >= policy.FailureThreshold {
			stopped = true
			break
		}
		if active >= maxParallel {
			receive()
			continue
		}
		if !lastStart.IsZero() && policy.StartInterval > 0 {
			wait := time.Until(lastStart.Add(policy.StartInterval))
			if wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case result := <-completed:
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					active--
					if result.Failed {
						failures++
					}
					results = append(results, result)
					continue
				case <-timer.C:
				case <-ctx.Done():
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					stopped = true
				}
				if stopped {
					break
				}
			}
		}
		if stopped {
			break
		}
		index, item := offset+next, items[next]
		next++
		active++
		*lastStart = time.Now()
		wg.Add(1)
		go func() {
			defer wg.Done()
			completed <- execute(ctx, index, item)
		}()
	}
	for active > 0 {
		receive()
	}
	wg.Wait()
	return results, failures, stopped
}
