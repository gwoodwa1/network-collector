package textfsm

import (
	"sync"
	"testing"
)

const sampleTemplate = `Value NAME (\S+)
Value AGE (\d+)

Start
  ^${NAME}\s+${AGE}\s*$$ -> Record
`

func TestCompileAndRun(t *testing.T) {
	compiled, err := Compile([]byte(sampleTemplate))
	if err != nil {
		t.Fatalf("unexpected compile error: %v", err)
	}
	got, err := compiled.Run("alice 30\nbob 42\n", "people")
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}
	want := `{"people":[{"AGE":"30","NAME":"alice"},{"AGE":"42","NAME":"bob"}]}`
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestRunDefaultsRootToRecords(t *testing.T) {
	compiled, err := Compile([]byte(sampleTemplate))
	if err != nil {
		t.Fatalf("unexpected compile error: %v", err)
	}
	got, err := compiled.Run("alice 30\n", "")
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}
	want := `{"records":[{"AGE":"30","NAME":"alice"}]}`
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestCompileRejectsInvalidTemplate(t *testing.T) {
	if _, err := Compile([]byte("not a valid template {{{")); err == nil {
		t.Fatal("expected error for invalid template")
	}
}

func TestParseCompilesAndRunsInOneStep(t *testing.T) {
	got, err := Parse("alice 30\n", []byte(sampleTemplate), "people")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `{"people":[{"AGE":"30","NAME":"alice"}]}`
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestRunOnNilCompiledReturnsError(t *testing.T) {
	var compiled *Compiled
	if _, err := compiled.Run("anything", "root"); err == nil {
		t.Fatal("expected error for nil compiled template")
	}
}

// TestRunIsSafeForConcurrentUse guards against a real production crash:
// gotextfsm.TextFSM.Values is a map that ParseTextString mutates in place
// even though its fsm parameter is passed "by value" (a map header still
// points at shared storage), so sharing one Compiled across goroutines
// without Run's mutex crashed with "fatal error: concurrent map iteration
// and map write" once xr-routing-monitor polled multiple devices at once —
// run with -race to catch a regression here, since the plain (non-race)
// build can pass even when the underlying map access is unsafe.
func TestRunIsSafeForConcurrentUse(t *testing.T) {
	compiled, err := Compile([]byte(sampleTemplate))
	if err != nil {
		t.Fatalf("unexpected compile error: %v", err)
	}

	const goroutines = 20
	const iterations = 50
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				got, err := compiled.Run("alice 30\nbob 42\n", "people")
				if err != nil {
					t.Errorf("unexpected run error: %v", err)
					return
				}
				want := `{"people":[{"AGE":"30","NAME":"alice"},{"AGE":"42","NAME":"bob"}]}`
				if got != want {
					t.Errorf("got %s, want %s", got, want)
					return
				}
			}
		}()
	}
	wg.Wait()
}
