package monitoring

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/orchestrator"
)

type alertState struct {
	bad, good int
	active    bool
	lastSent  time.Time
}

// Engine is device-local: callers must not share it between poll goroutines.
// Baselines are the first valid observations of this run, not a rolling average
// that could gradually hide a persistent degradation.
type Engine struct {
	config    AlertConfig
	baseline  map[string]float64
	nextHops  map[string]string
	counters  map[string]float64
	states    map[string]*alertState
	neighbors map[string]bool
}

func NewEngine(c AlertConfig) *Engine {
	return &Engine{config: c, baseline: map[string]float64{}, nextHops: map[string]string{},
		counters: map[string]float64{}, states: map[string]*alertState{}, neighbors: map[string]bool{}}
}

func finite(n float64) bool { return !math.IsNaN(n) && !math.IsInf(n, 0) }

func number(s string) (float64, bool) {
	n, err := strconv.ParseFloat(strings.ReplaceAll(strings.TrimSpace(s), ",", ""), 64)
	return n, err == nil && finite(n) && n >= 0
}

func rows(raw json.RawMessage, root string) ([]map[string]string, bool) {
	var data map[string]json.RawMessage
	if json.Unmarshal(raw, &data) != nil {
		return nil, false
	}
	var result []map[string]string
	rawRows, ok := data[root]
	if !ok || string(rawRows) == "null" || json.Unmarshal(rawRows, &result) != nil {
		return nil, false
	}
	return result, true
}

func (e *Engine) Observe(t Tick) []orchestrator.Event {
	if !e.config.Enabled {
		return nil
	}
	if len(t.Errors) > 0 || (t.State != "" && t.State != "healthy") {
		// Unknown samples neither establish baselines nor satisfy persistence.
		for _, s := range e.states {
			s.bad, s.good = 0, 0
		}
		return nil
	}
	now, err := time.Parse(time.RFC3339Nano, t.Timestamp)
	if err != nil {
		return nil
	}
	conditions := map[string]bool{}
	if records, ok := rows(t.BGP, "neighbors"); ok {
		current := map[string]bool{}
		valid := true
		for _, r := range records {
			peer := r["NEIGHBOR"]
			state := r["STATE_OR_PFXRCD"]
			if state == "" {
				state = r["STATE"]
			}
			if peer == "" || state == "" {
				valid = false
				break
			}
			_, numeric := number(state)
			current[peer] = numeric || strings.HasPrefix(strings.ToLower(state), "establ")
		}
		if valid {
			for peer, up := range current {
				if up {
					e.neighbors[peer] = true
				}
			}
			for peer := range e.neighbors {
				conditions["bgp-neighbor-lost/"+peer] = !current[peer]
			}
		}
	}
	for _, tables := range []map[string]json.RawMessage{t.Routes, t.Tables} {
		for table, raw := range tables {
			records, ok := rows(raw, "routes")
			if !ok || len(records) == 0 {
				continue
			}
			total, valid := 0.0, true
			for _, r := range records {
				field := r["TOTAL_ROUTES"]
				if field == "" {
					field = r["ROUTES"]
				}
				n, ok := number(field)
				if !ok {
					valid = false
					break
				}
				if strings.EqualFold(strings.TrimSpace(r["SOURCE"]), "total") {
					total = n
					break
				}
				total += n
			}
			if valid && finite(total) {
				e.relative(conditions, "route-count-drop/"+table, total, e.config.RouteDropPercent, true)
			}
		}
	}
	for table, raw := range t.DefaultRouteNextHops {
		records, ok := rows(raw, "next_hops")
		if !ok {
			continue
		}
		set := map[string]bool{}
		for _, r := range records {
			if r["NEXTHOP"] == "" {
				ok = false
				break
			}
			set[r["NEXTHOP"]] = true
		}
		if !ok {
			continue
		}
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		sig := strings.Join(names, ",")
		base, seen := e.nextHops[table]
		if !seen {
			e.nextHops[table] = sig
			continue
		}
		conditions["next-hop-change/"+table] = base != sig
	}
	for iface, raw := range t.Interfaces {
		records, ok := rows(raw, "stats")
		if !ok || len(records) == 0 {
			continue
		}
		for _, dir := range []string{"INPUT", "OUTPUT"} {
			if rate, ok := number(records[0][dir+"_RATE_BPS"]); ok {
				e.relative(conditions, "traffic-shift/"+iface+"/"+strings.ToLower(dir), rate, e.config.TrafficShiftPercent, false)
			}
			if count, ok := number(records[0][dir+"_ERRORS"]); ok {
				key := "interface-errors/" + iface + "/" + strings.ToLower(dir)
				prev, seen := e.counters[key]
				e.counters[key] = count
				if seen {
					conditions[key] = count >= prev && count-prev >= e.config.InterfaceErrorDelta
				}
			}
		}
	}
	for key, s := range e.states {
		if _, ok := conditions[key]; !ok {
			s.bad, s.good = 0, 0
		}
	}
	keys := make([]string, 0, len(conditions))
	for key := range conditions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var events []orchestrator.Event
	for _, key := range keys {
		s := e.states[key]
		if s == nil {
			s = &alertState{}
			e.states[key] = s
		}
		bad := conditions[key]
		if bad {
			s.bad++
			s.good = 0
		} else {
			s.good++
			s.bad = 0
		}
		state := ""
		if bad && s.bad >= e.config.ConsecutiveSamples && now.Sub(s.lastSent) >= time.Duration(e.config.CooldownSeconds)*time.Second {
			state, s.active, s.lastSent = "firing", true, now
		} else if !bad && s.active && s.good >= e.config.ConsecutiveSamples {
			state, s.active = "resolved", false
		}
		if state != "" {
			events = append(events, orchestrator.Event{Type: "monitor.alert", Timestamp: now, Hostname: t.Hostname,
				Step: key, Data: map[string]interface{}{"state": state, "baseline": "first valid observation in this run"}})
		}
	}
	return events
}

func (e *Engine) relative(conditions map[string]bool, key string, current, threshold float64, dropOnly bool) {
	base, seen := e.baseline[key]
	if !seen {
		e.baseline[key] = current
		return
	}
	denominator := base
	if !dropOnly {
		denominator = math.Max(base, e.config.TrafficMinimumBPS)
	}
	change := current - base
	if dropOnly {
		change = base - current
	} else {
		change = math.Abs(change)
	}
	conditions[key] = denominator > 0 && change/denominator*100 >= threshold
}
