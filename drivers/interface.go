package drivers

type DeviceInterface interface {
	Connect(ip string, username string, password string, opts ...Option) error
	Execute(cmd string) (string, error)
	Close() error
}
