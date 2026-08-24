package xrmonitor

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestBGPSummaryTemplateRowShapeMatchesCanonical guards against the two
// nearly-identical BGP-neighbor-table TextFSM templates in this repo
// silently drifting apart. templates/cisco_xr/show_bgp_vpnv4_summary.textfsm
// is a deliberate, standalone copy kept local to this binary (see parser.go)
// rather than reusing ../../parser_templates/cisco_xr/show_bgp_summary.textfsm
// — both parse the same underlying IOS-XR neighbor-table row, so a future
// IOS-XR column-format change fixed in one and forgotten in the other would
// silently break parsing wherever it wasn't updated. This test doesn't
// compare field names (the two deliberately differ: an added UPDOWN column,
// and a more precise STATE_OR_PFXRCD name), only row *structure* — the
// literal separators and field ordering of the "Start" rule's match line —
// so it fails the moment one template's row shape changes without the
// other's following.
func TestBGPSummaryTemplateRowShapeMatchesCanonical(t *testing.T) {
	canonical := normalizedRowShape(t, "../../parser_templates/cisco_xr/show_bgp_summary.textfsm")
	vpnv4 := normalizedRowShape(t, "templates/cisco_xr/show_bgp_vpnv4_summary.textfsm")

	if canonical != vpnv4 {
		t.Fatalf("BGP summary row shape drifted between templates:\ncanonical (show_bgp_summary.textfsm): %s\nvpnv4     (show_bgp_vpnv4_summary.textfsm): %s\n"+
			"if this is an intentional IOS-XR format change, update both templates so their row shape matches again", canonical, vpnv4)
	}
}

var (
	startRuleLineRe = regexp.MustCompile(`(?m)^\s*\^(.*)\$\$\s*->\s*Record\s*$`)
	rowTokenRe      = regexp.MustCompile(`\$\{[A-Za-z_]+\}|\\S\+|\\s\+|\\s\*|\\d\+`)
)

// normalizedRowShape extracts a TextFSM template's "Start" rule match line
// and reduces it to a sequence of structural tokens: every captured field
// (${NAME}) and every uncaptured single-token wildcard (\S+) collapse to the
// same generic placeholder, since both mean "one token here" — only whether
// it's captured differs, which is a naming/output concern, not a row-shape
// one. Literal separators (\s+, \s*, \d+) are kept as-is, since a real
// structural change (a missing/added column, a different separator) must
// still make two templates compare unequal.
func normalizedRowShape(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	m := startRuleLineRe.FindStringSubmatch(string(b))
	if m == nil {
		t.Fatalf("%s: could not find a Start rule match line (^...$$ -> Record)", path)
	}
	tokens := rowTokenRe.FindAllString(m[1], -1)
	for i, tok := range tokens {
		if strings.HasPrefix(tok, "${") || tok == `\S+` {
			tokens[i] = "$F"
		}
	}
	return strings.Join(tokens, " ")
}
