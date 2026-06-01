package drivers

// TLSConfig holds common TLS-related options for network driver clients.
type TLSConfig struct {
	SkipVerify bool
	Insecure   bool
}

// Option is a shared generic option type for driver configuration.
// Specific driver packages provide their own helper constructors.
type Option func(interface{})
