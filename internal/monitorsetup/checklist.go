package monitorsetup

import (
	"fmt"
	"io"
)

// ChecklistStatus is a device's current outcome in a DeviceChecklist.
type ChecklistStatus string

const (
	ChecklistPending   ChecklistStatus = "pending"
	ChecklistConnected ChecklistStatus = "connected"
	ChecklistFailed    ChecklistStatus = "failed"
	ChecklistSkipped   ChecklistStatus = "skipped (duplicate)"
)

// DeviceChecklist tracks every device named in a --devices file through
// onboarding. Print reprints the full list (with each device's current
// status) as a fresh block — never redrawn or overwritten in place, the
// same append-only choice status.go's TickStatusPrinter documents, so
// scrollback and a session.log redirect both stay a faithful, replayable
// record of what happened and in what order. Callers are expected to print
// the checklist once up front (every device pending) and again after each
// device's outcome is known, so an operator watching a long onboarding run
// always sees progress against the whole fleet, not just whichever device
// is connecting right now.
//
// Outcomes are tracked by position, not by hostname: a --devices file can
// legitimately list the same hostname twice (a typo'd duplicate, or a
// deliberate re-listing), and keying by hostname would make every row
// sharing that name collapse onto one status — recording, say, "skipped"
// for a duplicate would overwrite the fact that the first occurrence
// actually connected. SetAt(i, ...) always addresses exactly the device at
// position i in the original hostnames slice.
type DeviceChecklist struct {
	hostnames []string
	status    []ChecklistStatus
	detail    []string
}

// NewDeviceChecklist returns a checklist with every hostname marked
// pending, in the given order. A nil/empty hostnames is valid — Print on it
// is a no-op, so callers with no --devices file don't need to special-case
// skipping it.
func NewDeviceChecklist(hostnames []string) *DeviceChecklist {
	c := &DeviceChecklist{
		hostnames: append([]string(nil), hostnames...),
		status:    make([]ChecklistStatus, len(hostnames)),
		detail:    make([]string, len(hostnames)),
	}
	for i := range c.status {
		c.status[i] = ChecklistPending
	}
	return c
}

// SetAt records the outcome for the device at position i (0-indexed,
// matching the order hostnames was given in NewDeviceChecklist — callers
// typically get i from `for i, spec := range specs`). detail is shown
// alongside a Failed or Skipped status (e.g. the connection error, or the
// hostname it duplicates) and ignored otherwise. An out-of-range i is
// silently ignored.
func (c *DeviceChecklist) SetAt(i int, status ChecklistStatus, detail string) {
	if c == nil || i < 0 || i >= len(c.status) {
		return
	}
	c.status[i] = status
	c.detail[i] = detail
}

// Print writes the full checklist to out: a summary counts line, then one
// line per device in its original order (each occurrence of a duplicate
// hostname gets its own row) with a checkbox-style marker ([ ] pending,
// [x] connected, [!] failed, [-] skipped) and status text. A nil checklist
// or one with no devices prints nothing.
func (c *DeviceChecklist) Print(out io.Writer) {
	if c == nil || len(c.hostnames) == 0 {
		return
	}

	width := 0
	for _, h := range c.hostnames {
		if len(h) > width {
			width = len(h)
		}
	}

	var connected, failed, skipped, pending int
	for _, status := range c.status {
		switch status {
		case ChecklistConnected:
			connected++
		case ChecklistFailed:
			failed++
		case ChecklistSkipped:
			skipped++
		default:
			pending++
		}
	}
	fmt.Fprintf(out, "--- Device checklist (%d total, %d connected, %d failed, %d skipped, %d pending) ---\n",
		len(c.hostnames), connected, failed, skipped, pending)

	for i, h := range c.hostnames {
		status := c.status[i]
		mark := " "
		switch status {
		case ChecklistConnected:
			mark = "x"
		case ChecklistFailed:
			mark = "!"
		case ChecklistSkipped:
			mark = "-"
		}
		line := fmt.Sprintf("  [%s] %-*s %s", mark, width, h, status)
		if detail := c.detail[i]; detail != "" && (status == ChecklistFailed || status == ChecklistSkipped) {
			line += ": " + detail
		}
		fmt.Fprintln(out, line)
	}
	fmt.Fprintln(out)
}
