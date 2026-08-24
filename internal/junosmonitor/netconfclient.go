package junosmonitor

import (
	"github.com/gwoodwa1/network-collector/pkg/drivers/netconf"
)

// ConnectJunosNetconfDevice opens exactly one NETCONF session via the shared
// pkg/drivers/netconf.ScrapligoNETCONF, using the exact same username and
// password that just authenticated the device's SSH session (see
// ConnectDevice) — no additional prompt. Static credentials only: unlike
// ConnectJunosDevice's SSH path, ScrapligoNETCONF.Connect has no
// keyboard-interactive/passcode-prompt pattern to attach to, so an RSA
// SecurID passcode typed here behaves exactly like the one-time value it is
// — it authenticates this single connection attempt and nothing more. That's
// fine for this tool's usage: the NETCONF connection is dialed once, right
// alongside SSH, immediately after that same passcode was accepted, then
// kept open for the whole run (see DeviceSession.netconfClient) rather than
// re-authenticated later.
func ConnectJunosNetconfDevice(host, username, password string) (sessionExecutor, error) {
	client := &netconf.ScrapligoNETCONF{}
	if err := client.Connect(host, username, password); err != nil {
		return nil, err
	}
	return client, nil
}

// sessionExecutor (main.go) is satisfied directly by
// *netconf.ScrapligoNETCONF's Execute/Close methods, so a fake can still
// stand in for it in tests without a real NETCONF connection.
var _ sessionExecutor = (*netconf.ScrapligoNETCONF)(nil)
