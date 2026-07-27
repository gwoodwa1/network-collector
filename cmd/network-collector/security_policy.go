package main

import (
	"fmt"
	"strings"
)

const (
	securityModeProduction  = "production"
	securityModePermissive  = "permissive"
	maxRSATokenReuseDevices = 25
)

func normalizeSecurityMode(mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return securityModeProduction, nil
	}
	switch mode {
	case securityModeProduction, securityModePermissive:
		return mode, nil
	default:
		return "", fmt.Errorf("security_mode must be production or permissive")
	}
}

func validateSecurityPolicy(config Config, devices []DeviceConfig) (string, error) {
	mode, err := normalizeSecurityMode(config.SecurityMode)
	if err != nil {
		return "", err
	}

	for index, device := range devices {
		security := effectiveSSHSecurity(config.SSHSecurity, device.SSHSecurity)
		if err := validateSSHSecurity(security); err != nil {
			return "", fmt.Errorf("device %q SSH security: %w", deviceSecurityName(device, index), err)
		}
		if mode == securityModeProduction {
			profile := strings.ToLower(strings.TrimSpace(security.Profile))
			if profile == "" {
				profile = "modern"
			}
			if profile != "modern" {
				return "", fmt.Errorf("device %q uses SSH profile %q; production security requires modern (set security_mode: permissive only for an explicitly approved legacy environment)", deviceSecurityName(device, index), profile)
			}
			policy := strings.ToLower(strings.TrimSpace(security.HostKeyPolicy))
			if policy == "" {
				policy = "known_hosts"
			}
			if policy == "insecure" {
				return "", fmt.Errorf("device %q disables SSH host-key verification; production security requires known_hosts or pinned", deviceSecurityName(device, index))
			}
			if device.GNMI != nil {
				if device.GNMI.Insecure != nil && *device.GNMI.Insecure {
					return "", fmt.Errorf("device %q enables plaintext gNMI; production security requires TLS", deviceSecurityName(device, index))
				}
				if device.GNMI.SkipVerify != nil && *device.GNMI.SkipVerify {
					return "", fmt.Errorf("device %q disables gNMI certificate verification; production security requires certificate verification", deviceSecurityName(device, index))
				}
			}
		}
		if err := validateStepSecurity(device.Steps, fmt.Sprintf("device %q steps", deviceSecurityName(device, index)), mode); err != nil {
			return "", err
		}
	}
	for name, workflow := range config.Workflows {
		if err := validateStepSecurity(workflow.Steps, "workflow "+name, mode); err != nil {
			return "", err
		}
	}
	return mode, nil
}

func validateStepSecurity(steps []StepConfig, path, mode string) error {
	for index, step := range steps {
		stepPath := fmt.Sprintf("%s[%d]", path, index)
		if name := strings.TrimSpace(step.Name); name != "" {
			stepPath += "(" + name + ")"
		}
		if mode == securityModeProduction && step.GNMISubscribe != nil && step.GNMISubscribe.SkipTLS {
			return fmt.Errorf("%s uses legacy gNMI skip_tls; production security requires TLS", stepPath)
		}

		nested := []struct {
			name  string
			steps []StepConfig
		}{
			{"repeat.steps", stepsFromRepeat(step.Repeat)},
			{"foreach.steps", stepsFromForeach(step.Foreach)},
			{"parallel.steps", stepsFromParallel(step.Parallel)},
			{"block.steps", stepsFromBlock(step.Block, "steps")},
			{"block.rescue", stepsFromBlock(step.Block, "rescue")},
			{"block.rollback", stepsFromBlock(step.Block, "rollback")},
			{"block.always", stepsFromBlock(step.Block, "always")},
			{"on_pass.steps", stepsFromAction(step.OnPass)},
			{"on_fail.steps", stepsFromAction(step.OnFail)},
		}
		if step.GNMISubscribe != nil {
			for triggerIndex, trigger := range step.GNMISubscribe.Triggers {
				nested = append(nested, struct {
					name  string
					steps []StepConfig
				}{
					fmt.Sprintf("gnmi_subscribe.triggers[%d].steps", triggerIndex),
					trigger.Steps,
				})
			}
		}
		for _, child := range nested {
			if err := validateStepSecurity(child.steps, stepPath+"."+child.name, mode); err != nil {
				return err
			}
		}
	}
	return nil
}

func deviceSecurityName(device DeviceConfig, index int) string {
	for _, value := range []string{device.Hostname, device.Host, device.IP} {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return fmt.Sprintf("index-%d", index)
}

func validateRSATokenReuse(config CredentialProviderConfig, rsaToken bool, deviceCount int) (int, error) {
	configured := config.RSATokenReuseMaxDevices
	if !rsaToken {
		if configured != 0 {
			return 0, fmt.Errorf("credentials.rsa_token_reuse_max_devices requires credentials.rsa_token or --rsa-token")
		}
		return 0, nil
	}
	if configured < 0 {
		return 0, fmt.Errorf("credentials.rsa_token_reuse_max_devices must be greater than 0")
	}
	maxDevices := configured
	if maxDevices == 0 {
		maxDevices = 1
	}
	if maxDevices > maxRSATokenReuseDevices {
		return 0, fmt.Errorf("credentials.rsa_token_reuse_max_devices must not exceed %d", maxRSATokenReuseDevices)
	}
	if deviceCount > maxDevices {
		return 0, fmt.Errorf("RSA passcode reuse is limited to %d initial device connection(s), but %d were selected; increase credentials.rsa_token_reuse_max_devices explicitly (maximum %d) or select fewer devices", maxDevices, deviceCount, maxRSATokenReuseDevices)
	}
	return maxDevices, nil
}
