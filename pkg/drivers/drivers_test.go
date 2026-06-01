package drivers_test

import (
	"testing"
	"time"

	"github.com/kcajme/network-collector/pkg/drivers"
	"github.com/kcajme/network-collector/pkg/drivers/aristahttp"
	"github.com/kcajme/network-collector/pkg/drivers/gnmi"
	"github.com/kcajme/network-collector/pkg/drivers/netconf"
	"github.com/kcajme/network-collector/pkg/drivers/restconf"
)

func TestDriverInterfaces(t *testing.T) {
	var _ drivers.DeviceInterface = (*aristahttp.AristaHTTP)(nil)
	var _ drivers.DeviceInterface = (*gnmi.GNMIClient)(nil)
}

func TestOptionHelpers(t *testing.T) {
	client := &aristahttp.AristaHTTP{}
	aristahttp.WithSkipTLS()(client)
	aristahttp.WithRequestTimeout(5 * time.Second)(client)

	restClient := &restconf.RESTCONFClient{}
	restconf.WithSkipTLS()(restClient)
	restconf.WithRequestTimeout(5 * time.Second)(restClient)

	gnmiClient := &gnmi.GNMIClient{}
	gnmi.WithSkipTLS()(gnmiClient)
	gnmi.WithRequestTimeout(5 * time.Second)(gnmiClient)

	netconfClient := &netconf.ScrapligoNETCONF{}
	netconf.WithNetconfTimeouts(3*time.Second, 5*time.Second)(netconfClient)
}
