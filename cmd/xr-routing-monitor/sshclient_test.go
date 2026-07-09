package main

import "testing"

func TestPasscodePromptPatternMatchesRealDevicePrompt(t *testing.T) {
	shouldMatch := []string{
		"Enter PASSCODE:",
		"Enter PASSCODE: ",
		"enter passcode:",
		"Password:",
		"Password: ",
		"user@host's password:",
	}
	for _, prompt := range shouldMatch {
		if !passcodePromptPattern.MatchString(prompt) {
			t.Errorf("expected pattern to match %q", prompt)
		}
	}
}

func TestPasscodePromptPatternDoesNotMatchUnrelatedOutput(t *testing.T) {
	shouldNotMatch := []string{
		"RP/0/RSP0/CPU0:pe-router-1#",
		"Wed Jul  8 22:07:26.779 BST",
		"Username:",
	}
	for _, line := range shouldNotMatch {
		if passcodePromptPattern.MatchString(line) {
			t.Errorf("expected pattern not to match %q", line)
		}
	}
}
