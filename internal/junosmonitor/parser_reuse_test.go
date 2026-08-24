package junosmonitor

import (
	"sync"
	"testing"
)

// Every device goroutine shares the same compiled TextFSM template
// (parsers are loaded once in main and passed to every PollDevice), so a
// template retaining state between Run() calls would corrupt the second
// and later devices' parses. These tests pin that invariant for the two
// stateful-looking templates: the nexthop parser (Required value) and the
// route-table parser (Filldown values).

func TestParserReuseSequentialRunsProduceIdenticalOutput(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		parser string
		input  string
	}{
		{"junos_default_route_nexthop", sampleDefaultRouteNextHopOutput},
		{"junos_route_table", sampleRouteTableOutput},
	} {
		var outputs []string
		for i := 0; i < 3; i++ {
			parsed, err := parseOutputWithModule(tc.input, tc.parser, parsers)
			if err != nil {
				t.Fatalf("%s run %d: %v", tc.parser, i+1, err)
			}
			outputs = append(outputs, parsed)
		}
		for i := 1; i < len(outputs); i++ {
			if outputs[i] != outputs[0] {
				t.Errorf("%s: run %d differs from run 1 — compiled template retains state between runs:\nrun 1: %s\nrun %d: %s", tc.parser, i+1, outputs[0], i+1, outputs[i])
			}
		}
	}
}

func TestParserReuseConcurrentRunsProduceIdenticalOutput(t *testing.T) {
	parsers, err := LoadDefaultParsers()
	if err != nil {
		t.Fatal(err)
	}
	const workers = 8
	results := make([]string, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			results[w], errs[w] = parseOutputWithModule(sampleDefaultRouteNextHopOutput, "junos_default_route_nexthop", parsers)
		}(w)
	}
	wg.Wait()
	for w := 0; w < workers; w++ {
		if errs[w] != nil {
			t.Fatalf("worker %d: %v", w, errs[w])
		}
		if results[w] != results[0] {
			t.Errorf("worker %d output differs from worker 0:\nworker 0: %s\nworker %d: %s", w, results[0], w, results[w])
		}
	}
}
