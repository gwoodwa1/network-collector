package hostkey

import (
	"testing"

	"github.com/scrapli/scrapligo/util"
)

func TestPolicyDefaultsAndValidation(t *testing.T) {
	defaultPolicy, err := New("", "")
	if err != nil || defaultPolicy.Name() != "known_hosts" {
		t.Fatalf("unexpected default policy=%v error=%v", defaultPolicy, err)
	}
	if _, err := New("pinned", ""); err == nil {
		t.Fatal("pinned policy accepted without a pinned known_hosts file")
	}
	for _, name := range []string{"known_hosts", "pinned", "insecure"} {
		file := ""
		if name == "pinned" {
			file = "device.known_hosts"
		}
		selected, err := New(name, file)
		if err != nil {
			t.Fatalf("valid policy %q rejected: %v", name, err)
		}
		if _, err := selected.Apply([]util.Option{}); err != nil {
			t.Fatalf("policy %q could not be applied: %v", name, err)
		}
	}
	if _, err := New("accept-new", ""); err == nil {
		t.Fatal("unknown policy accepted")
	}
}
