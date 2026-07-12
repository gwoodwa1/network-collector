package main

import "testing"

func TestRSAPasscodePromptPattern(t *testing.T) {
	for _, prompt := range []string{"Enter PASSCODE:", "Password:", "user@router's password:"} {
		if !rsaPasscodePromptPattern.MatchString(prompt) {
			t.Fatalf("RSA prompt pattern did not match %q", prompt)
		}
	}
}
