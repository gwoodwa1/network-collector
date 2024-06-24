package drivers

import (
	"fmt"
	"github.com/scrapli/scrapligo/driver/options"
	"github.com/scrapli/scrapligo/platform"
)

type ScrapligoSSH struct {
	driverName string
	host       string
	platform   *platform.Platform // Store the platform instead
}

func (s *ScrapligoSSH) Connect(host, username, password, driverName string) error {
	s.driverName = driverName
	s.host = host

	p, err := platform.NewPlatform(
		driverName,
		host,
		options.WithAuthNoStrictKey(),
		options.WithAuthUsername(username),
		options.WithAuthPassword(password),
	)
	if err != nil {
		return fmt.Errorf("failed to create platform; error: %+v", err)
	}

	// We don't open the driver here, we'll do it in Execute
	s.platform = p
	return nil
}

func (s *ScrapligoSSH) Execute(cmd string) (string, error) {
	d, err := s.platform.GetNetworkDriver()
	if err != nil {
		return "", fmt.Errorf("failed to fetch network driver from the platform; error: %+v", err)
	}

	err = d.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open driver; error: %+v", err)
	}

	output, err := d.Channel.SendInput(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to send input to device; error: %+v", err)
	}
	return string(output), nil
}

func (s *ScrapligoSSH) Close() error {

	if s != nil && s.platform != nil {

		driver, err := s.platform.GetNetworkDriver()
		if err != nil {
			return fmt.Errorf("error getting driver: %w", err)
		}

		if err := driver.Close(); err != nil {
			return fmt.Errorf("error closing driver: %w", err)
		}

	}
	return nil

}
