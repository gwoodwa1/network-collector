package monitorsetup

import (
	"bytes"
	"strings"
	"testing"
)

func TestDeviceChecklistPrintsAllPendingInitially(t *testing.T) {
	c := NewDeviceChecklist([]string{"router1", "router2"})
	var out bytes.Buffer
	c.Print(&out)

	got := out.String()
	if !strings.Contains(got, "2 total, 0 connected, 0 failed, 0 skipped, 2 pending") {
		t.Fatalf("expected an all-pending summary line, got:\n%s", got)
	}
	if !strings.Contains(got, "[ ] router1") || !strings.Contains(got, "[ ] router2") {
		t.Fatalf("expected both devices listed pending, got:\n%s", got)
	}
}

func TestDeviceChecklistReflectsSetOutcomes(t *testing.T) {
	c := NewDeviceChecklist([]string{"router1", "router2", "router3", "router4"})
	c.SetAt(0, ChecklistConnected, "")
	c.SetAt(1, ChecklistFailed, "errAuthError: bad passcode")
	c.SetAt(2, ChecklistSkipped, "duplicate of router1")
	// router4 (index 3) stays pending.

	var out bytes.Buffer
	c.Print(&out)
	got := out.String()

	if !strings.Contains(got, "4 total, 1 connected, 1 failed, 1 skipped, 1 pending") {
		t.Fatalf("expected the summary counts to reflect all four outcomes, got:\n%s", got)
	}
	for _, want := range []string{
		"[x] router1",
		"[!] router2",
		"failed: errAuthError: bad passcode",
		"[-] router3",
		"skipped (duplicate): duplicate of router1",
		"[ ] router4",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, got)
		}
	}
}

// TestDeviceChecklistTracksDuplicateHostnamesIndependently is the
// regression test for keying by hostname instead of position: a
// --devices file listing "router1" twice must let the first occurrence's
// "connected" outcome and the second occurrence's "skipped" outcome
// (registry-level duplicate detection) coexist as two separate rows,
// rather than the second Set silently overwriting the first because both
// shared one map entry.
func TestDeviceChecklistTracksDuplicateHostnamesIndependently(t *testing.T) {
	c := NewDeviceChecklist([]string{"router1", "router1"})
	c.SetAt(0, ChecklistConnected, "")
	c.SetAt(1, ChecklistSkipped, "duplicate of router1")

	var out bytes.Buffer
	c.Print(&out)
	got := out.String()

	if !strings.Contains(got, "2 total, 1 connected, 0 failed, 1 skipped, 0 pending") {
		t.Fatalf("expected one connected and one skipped, got:\n%s", got)
	}
	if strings.Count(got, "[x] router1") != 1 {
		t.Fatalf("expected exactly one connected row for router1, got:\n%s", got)
	}
	if strings.Count(got, "[-] router1") != 1 {
		t.Fatalf("expected exactly one skipped row for router1, got:\n%s", got)
	}
}

func TestDeviceChecklistIgnoresOutOfRangeIndex(t *testing.T) {
	c := NewDeviceChecklist([]string{"router1"})
	c.SetAt(5, ChecklistConnected, "")  // must not panic
	c.SetAt(-1, ChecklistConnected, "") // must not panic

	var out bytes.Buffer
	c.Print(&out)
	got := out.String()

	if !strings.Contains(got, "1 total, 0 connected") {
		t.Fatalf("expected router1 to remain pending, got:\n%s", got)
	}
}

func TestDeviceChecklistPrintOnEmptyOrNilIsNoop(t *testing.T) {
	var out bytes.Buffer

	NewDeviceChecklist(nil).Print(&out)
	if out.Len() != 0 {
		t.Fatalf("expected no output for an empty checklist, got:\n%s", out.String())
	}

	var nilChecklist *DeviceChecklist
	nilChecklist.Print(&out) // must not panic
	if out.Len() != 0 {
		t.Fatalf("expected no output from a nil checklist, got:\n%s", out.String())
	}
}

func TestDeviceChecklistSetAtOnNilIsNoop(t *testing.T) {
	var c *DeviceChecklist
	c.SetAt(0, ChecklistConnected, "") // must not panic
}

func TestDeviceChecklistPreservesOriginalOrder(t *testing.T) {
	c := NewDeviceChecklist([]string{"zebra", "alpha", "middle"})
	c.SetAt(1, ChecklistConnected, "")

	var out bytes.Buffer
	c.Print(&out)
	got := out.String()

	zebraIdx := strings.Index(got, "zebra")
	alphaIdx := strings.Index(got, "alpha")
	middleIdx := strings.Index(got, "middle")
	if !(zebraIdx < alphaIdx && alphaIdx < middleIdx) {
		t.Fatalf("expected devices printed in their original (not sorted) order, got:\n%s", got)
	}
}
