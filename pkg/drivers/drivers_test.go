package drivers_test

import (
	"testing"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drivers"
	"github.com/gwoodwa1/network-collector/pkg/drivers/aristahttp"
	"github.com/gwoodwa1/network-collector/pkg/drivers/gnmi"
	"github.com/gwoodwa1/network-collector/pkg/drivers/netconf"
	"github.com/gwoodwa1/network-collector/pkg/drivers/restconf"
)

func TestDriverInterfaces(t *testing.T) {
	type aristaDriver interface {
		Connect(string, string, string, ...aristahttp.Option) error
		Execute(string) (string, error)
		Close() error
	}
	type gnmiDriver interface {
		Connect(string, string, string, ...gnmi.Option) error
		Execute(string) (string, error)
		Close() error
	}
	type restconfDriver interface {
		Connect(string, string, string, ...restconf.Option) error
		Execute(string, string) (string, error)
		Close() error
	}

	var _ aristaDriver = (*aristahttp.AristaHTTP)(nil)
	var _ gnmiDriver = (*gnmi.GNMIClient)(nil)
	var _ restconfDriver = (*restconf.RESTCONFClient)(nil)
	var _ drivers.DeviceInterface = (*netconf.ScrapligoNETCONF)(nil)
}

func TestOptionHelpers(t *testing.T) {
	client := &aristahttp.AristaHTTP{}
	aristahttp.WithSkipTLSVerification()(client)
	aristahttp.WithRequestTimeout(5 * time.Second)(client)

	restClient := &restconf.RESTCONFClient{}
	restconf.WithSkipTLSVerification()(restClient)
	restconf.WithRequestTimeout(5 * time.Second)(restClient)

	gnmiClient := &gnmi.GNMIClient{}
	gnmi.WithSkipTLS()(gnmiClient)
	gnmi.WithRequestTimeout(5 * time.Second)(gnmiClient)

	netconfClient := &netconf.ScrapligoNETCONF{}
	netconf.WithNetconfTimeouts(3*time.Second, 5*time.Second)(netconfClient)
}
