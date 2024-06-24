package drivers

import (
	"fmt"
	"github.com/scrapli/scrapligo/driver/netconf"
	"github.com/scrapli/scrapligo/driver/opoptions"
	"github.com/scrapli/scrapligo/driver/options"
	"log"
)

type ScrapligoNETCONF struct {
	host    string
	network *netconf.Driver // Hold the NETCONF driver for reuse in Execute
}

func (n *ScrapligoNETCONF) Connect(host, username, password string) error {
	n.host = host

	d, err := netconf.NewDriver(
		host,
		options.WithAuthNoStrictKey(),
		options.WithAuthUsername(username), // Set your NETCONF username
		options.WithAuthPassword(password), // Set your NETCONF password
		options.WithPort(830),
	)
	if err != nil {
		return fmt.Errorf("failed to create driver; error: %+v", err)
	}

	err = d.Open()
	if err != nil {
		return fmt.Errorf("failed to open driver; error: %+v", err)
	}

	n.network = d // Store the NETCONF driver for reuse in Execute
	return nil
}

func (n *ScrapligoNETCONF) Execute(cmd string) (string, error) {
	r, err := n.network.RPC(opoptions.WithFilter(cmd))
	if err != nil {
		return "", fmt.Errorf("failed executing RPC; error: %+v", err)
	}

	if r.Failed != nil {
		return "", fmt.Errorf("response object indicates failure: %+v", r.Failed)
	}

	return r.Result, nil
}

func (n *ScrapligoNETCONF) Close() error {
	if n != nil && n.network != nil {
		err := n.network.Close()
		if err != nil {
			log.Printf("Error while closing network connection: %v", err)
			return err
		}
		log.Println("Network connection closed successfully.")
		return nil
	}

	log.Println("Either ScrapligoNETCONF object or network driver object is nil. Skipping close operation.")
	return nil
}
