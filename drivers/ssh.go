package drivers

import (
    "fmt"
    "log"
    "os"
    "time"

    "github.com/scrapli/scrapligo/driver/options"
    "github.com/scrapli/scrapligo/platform"
)

type ScrapligoSSH struct {
    driverName string
    host       string
    platform   *platform.Platform
}

func (s *ScrapligoSSH) Connect(host, username, password, driverName string) error {
    s.driverName = driverName
    s.host = host

    log.Printf("hello %s and %s", username, password)
    log.Printf("DEBUG: Creating platform for %s (driver: %s)", host, driverName)

    p, err := platform.NewPlatform(
        driverName,
        host,
        options.WithAuthNoStrictKey(),
        options.WithAuthUsername(username),
        options.WithAuthPassword(password),

        // === Legacy IOS-XR fixes (only the options that exist) ===
        options.WithStandardTransportExtraKexs([]string{
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1",
            "diffie-hellman-group1-sha1",
        }),
        options.WithStandardTransportExtraCiphers([]string{
            "aes128-ctr", "aes192-ctr", "aes256-ctr",
            "aes128-cbc", "aes192-cbc", "aes256-cbc",
            "3des-cbc",
        }),

        // === Increased timeouts (this often fixes the "connected but timeout" issue) ===
        options.WithTimeoutSocket(45 * time.Second),
        options.WithTimeoutOps(90 * time.Second),

        // === Heavy logging so we can see exactly where it hangs ===
        options.WithDefaultLogger(),       // General debug logs from scrapligo
        options.WithChannelLog(os.Stdout), // Raw SSH channel traffic (very useful)
    )
    if err != nil {
        return fmt.Errorf("failed to create platform; error: %+v", err)
    }

    s.platform = p
    log.Printf("DEBUG: Platform created successfully for %s", host)
    return nil
}

func (s *ScrapligoSSH) Execute(cmd string) (string, error) {
    log.Printf("DEBUG: Getting network driver for command: %s", cmd)

    d, err := s.platform.GetNetworkDriver()
    if err != nil {
        return "", fmt.Errorf("failed to fetch network driver; error: %+v", err)
    }

    log.Printf("DEBUG: Opening driver connection (this is where most timeouts happen)...")
    start := time.Now()

    err = d.Open()
    if err != nil {
        return "", fmt.Errorf("failed to open driver after %.1fs; error: %+v", time.Since(start).Seconds(), err)
    }
    log.Printf("DEBUG: Driver opened successfully in %.1fs", time.Since(start).Seconds())

    log.Printf("DEBUG: Sending command: %s", cmd)
    output, err := d.Channel.SendInput(cmd)
    if err != nil {
        return "", fmt.Errorf("failed to send input; error: %+v", err)
    }

    log.Printf("DEBUG: Command executed successfully, output length: %d bytes", len(output))
    return string(output), nil
}

func (s *ScrapligoSSH) Close() error {
    if s == nil || s.platform == nil {
        return nil
    }

    log.Printf("DEBUG: Closing connection for %s", s.host)

    d, err := s.platform.GetNetworkDriver()
    if err != nil {
        log.Printf("WARN: Could not get driver for close: %v", err)
        return nil
    }

    if err := d.Close(); err != nil {
        log.Printf("WARN: Error closing driver: %v", err)
    }

    log.Printf("DEBUG: Connection closed for %s", s.host)
    return nil
}
