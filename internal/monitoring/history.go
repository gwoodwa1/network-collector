package monitoring

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gwoodwa1/network-collector/internal/safeoutput"
	"github.com/gwoodwa1/network-collector/internal/secureartifact"
	"github.com/gwoodwa1/network-collector/pkg/orchestrator"
)

const MaxRecordBytes = 9 << 20 // below the report scanner's 10 MiB limit

type Tick struct {
	Timestamp            string                     `json:"timestamp"`
	Hostname             string                     `json:"hostname"`
	RunID                string                     `json:"run_id,omitempty"`
	State                string                     `json:"state,omitempty"`
	IntervalSeconds      float64                    `json:"interval_seconds,omitempty"`
	BGP                  json.RawMessage            `json:"bgp,omitempty"`
	Routes               map[string]json.RawMessage `json:"routes,omitempty"`
	Tables               map[string]json.RawMessage `json:"tables,omitempty"`
	DefaultRouteNextHops map[string]json.RawMessage `json:"default_route_next_hops,omitempty"`
	Interfaces           map[string]json.RawMessage `json:"interfaces,omitempty"`
	Errors               []string                   `json:"errors,omitempty"`
}

type Health struct {
	RunID         string    `json:"run_id"`
	Hostname      string    `json:"hostname"`
	StartedAt     time.Time `json:"started_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	LastSample    string    `json:"last_sample,omitempty"`
	State         string    `json:"state"`
	FailedSamples int       `json:"failed_samples"`
	Issues        []string  `json:"issues,omitempty"`
	Complete      bool      `json:"complete"`
}

type Runtime struct {
	RunID  string
	config Config
	sinks  []orchestrator.EventSink
	mu     sync.Mutex
	errors []error
}

func newRunID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(b[:]), nil
}

func NewRuntime(outputDir, configPath string) (*Runtime, error) {
	c, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	id, err := newRunID()
	if err != nil {
		return nil, err
	}
	sinks, err := c.sinks()
	if err != nil {
		return nil, err
	}
	if err := PruneHistory(outputDir, c.RetentionDays, time.Now()); err != nil {
		for _, s := range sinks {
			_ = s.Close()
		}
		return nil, err
	}
	return &Runtime{RunID: id, config: c, sinks: sinks}, nil
}

func (r *Runtime) RecordError(err error) {
	if err == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// One summary per device is enough; never grow memory with run duration.
	if len(r.errors) < 100 {
		r.errors = append(r.errors, err)
	}
}

func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sinks {
		if err := s.Close(); err != nil {
			r.errors = append(r.errors, err)
		}
	}
	r.sinks = nil
	return errors.Join(r.errors...)
}

type Recorder struct {
	runtime                           *Runtime
	dir, base, healthPath, legacyPath string
	interval                          time.Duration
	file                              *os.File
	segment                           int
	size                              int64
	health                            Health
	engine                            *Engine
}

func OpenRecorder(ctx context.Context, dir, hostname, legacyName string, interval time.Duration) (*Recorder, error) {
	if interval <= 0 {
		return nil, errors.New("poll interval must be positive")
	}
	runtime, _ := ctx.Value(contextKey{}).(*Runtime)
	legacy := runtime == nil
	if legacy {
		c, _ := LoadConfig("")
		id, err := newRunID()
		if err != nil {
			return nil, err
		}
		runtime = &Runtime{RunID: id, config: c}
	}
	hostHash := sha256.Sum256([]byte(hostname))
	base := fmt.Sprintf("ticks-%s-%x", runtime.RunID, hostHash[:8])
	r := &Recorder{runtime: runtime, dir: dir, base: base, interval: interval,
		healthPath: filepath.Join(dir, base+".health.json"), engine: NewEngine(runtime.config.Alerts),
		health: Health{RunID: runtime.RunID, Hostname: hostname, StartedAt: time.Now().UTC(), State: "starting"},
	}
	if legacy {
		r.legacyPath = filepath.Join(dir, filepath.Base(legacyName)+".jsonl")
	}
	if err := r.openSegment(); err != nil {
		return nil, err
	}
	if err := r.Status("starting"); err != nil {
		_ = r.file.Close()
		return nil, err
	}
	return r, nil
}

func (r *Recorder) openSegment() error {
	r.segment++
	name := filepath.Join(r.dir, fmt.Sprintf("%s-%06d.jsonl", r.base, r.segment))
	flags := os.O_CREATE | os.O_EXCL | os.O_WRONLY
	if r.legacyPath != "" {
		name = r.legacyPath
		flags = os.O_CREATE | os.O_APPEND | os.O_WRONLY
	}
	f, err := secureartifact.OpenFile(name, flags)
	if err != nil {
		return fmt.Errorf("open monitor history: %w", err)
	}
	r.file, r.size = f, 0
	return nil
}

func (r *Recorder) sealSegment() error {
	if r.file == nil {
		return nil
	}
	f := r.file
	r.file = nil
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return fmt.Errorf("close monitor history: %w", err)
	}
	if r.legacyPath != "" {
		return nil
	}
	// Only successfully closed segments receive a retention marker. Active,
	// interrupted and legacy files are never automatically deleted.
	marker, err := json.Marshal(struct {
		ClosedAt time.Time `json:"closed_at"`
	}{time.Now().UTC()})
	if err != nil {
		return err
	}
	return secureartifact.WriteFile(f.Name()+".closed.json", marker)
}

func (r *Recorder) appendRecord(value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	data = []byte(safeoutput.Sanitize(string(data)))
	if len(data)+1 > MaxRecordBytes {
		return errors.New("monitor record exceeds 9 MiB")
	}
	if r.file == nil {
		return errors.New("monitor history is closed")
	}
	if r.legacyPath == "" && r.size > 0 && r.size+int64(len(data)+1) > r.runtime.config.RotateBytes {
		if err := r.sealSegment(); err != nil {
			return err
		}
		if err := r.openSegment(); err != nil {
			return err
		}
	}
	data = append(data, '\n')
	n, err := r.file.Write(data)
	r.size += int64(n)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("persist monitor record: %w", err)
	}
	// Flush to the filesystem before advertising a successful collection.
	return r.file.Sync()
}

func (r *Recorder) Status(state string, issues ...string) error {
	r.health.State, r.health.UpdatedAt = state, time.Now().UTC()
	for _, issue := range issues {
		if len(r.health.Issues) >= 20 {
			break
		}
		issue = safeoutput.Sanitize(issue)
		if len(issue) > 2048 {
			issue = issue[:2048]
		}
		r.health.Issues = append(r.health.Issues, issue)
	}
	data, err := json.Marshal(r.health)
	if err != nil {
		return err
	}
	return secureartifact.WriteFile(r.healthPath, []byte(safeoutput.Sanitize(string(data))))
}

func (r *Recorder) WriteTick(ctx context.Context, tick Tick, alive, reauth bool) error {
	tick.RunID, tick.IntervalSeconds = r.runtime.RunID, r.interval.Seconds()
	tick.State = "healthy"
	if len(tick.Errors) > 0 {
		tick.State = "degraded"
		r.health.FailedSamples++
	}
	if reauth {
		tick.State = "authentication-wait"
	} else if !alive {
		tick.State = "disconnected"
	}
	if err := r.appendRecord(tick); err != nil {
		return err
	}
	r.health.LastSample = tick.Timestamp
	if err := r.Status(tick.State, tick.Errors...); err != nil {
		return err
	}
	for _, event := range r.engine.Observe(tick) {
		event.RunID = r.runtime.RunID
		encoded, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(safeoutput.Sanitize(string(encoded))), &event); err != nil {
			return err
		}
		if err := r.appendRecord(event); err != nil {
			return err
		}
		slog.Warn("monitor alert", "hostname", event.Hostname, "rule", event.Step, "state", event.Data["state"])
		for _, sink := range r.runtime.sinks {
			if err := sink.Handle(ctx, event); err != nil {
				return fmt.Errorf("deliver monitor alert: %w", err)
			}
		}
	}
	return nil
}

func (r *Recorder) Close(complete bool, issues ...string) error {
	r.health.Complete = complete
	state := "incomplete"
	if complete {
		state = "completed"
	}
	return errors.Join(r.Status(state, issues...), r.sealSegment())
}

var segmentName = regexp.MustCompile(`^ticks-\d{8}T\d{6}\.\d{9}Z-[0-9a-f]{16}-[0-9a-f]{16}-\d{6,}\.jsonl$`)

// PruneHistory only removes this version's sealed tick segments. No recursive
// deletion, symlink following, user filenames or paths from JSON are involved.
func PruneHistory(dir string, days int, now time.Time) error {
	if days == 0 {
		return nil
	}
	if days < 0 || days > 36500 {
		return errors.New("invalid retention days")
	}
	paths, err := filepath.Glob(filepath.Join(dir, "ticks-*.jsonl.closed.json"))
	if err != nil {
		return err
	}
	cutoff := now.AddDate(0, 0, -days)
	for _, marker := range paths {
		path := strings.TrimSuffix(marker, ".closed.json")
		if !segmentName.MatchString(filepath.Base(path)) {
			continue
		}
		info, err := os.Lstat(marker)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 1024 {
			continue
		}
		data, err := os.ReadFile(marker)
		if err != nil {
			return err
		}
		var closed struct {
			ClosedAt time.Time `json:"closed_at"`
		}
		if json.Unmarshal(data, &closed) != nil || closed.ClosedAt.IsZero() || !closed.ClosedAt.Before(cutoff) {
			continue
		}
		info, err = os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		if err := os.Remove(marker); err != nil {
			return err
		}
		slog.Info("removed expired sealed monitor segment", "file", filepath.Base(path))
	}
	return nil
}
