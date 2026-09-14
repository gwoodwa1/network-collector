package monitoring

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTACACSTimeoutRemindersAreValidatedAndCopied(t *testing.T) {
	ctx, err := WithTACACSTimeoutReminders(context.Background(), []int{1500, 5000, 8000})
	if err != nil {
		t.Fatal(err)
	}
	got := TACACSTimeoutReminders(ctx)
	if len(got) != 3 || got[0] != 1500*time.Second || got[2] != 8000*time.Second {
		t.Fatalf("reminders = %#v", got)
	}
	got[0] = 0
	if TACACSTimeoutReminders(ctx)[0] == 0 {
		t.Fatal("context schedule was mutable")
	}
	for _, schedule := range [][]int{{0}, {5, 5}, {9, 8}, {86401}} {
		if _, err := WithTACACSTimeoutReminders(context.Background(), schedule); err == nil || !strings.Contains(err.Error(), "strictly increasing") {
			t.Fatalf("schedule %v error = %v", schedule, err)
		}
	}
}
