package drivers

type TLSConfig struct {
	SkipVerify bool
	Insecure   bool
}

type Option func(interface{})

func WithSkipTLS() Option {
	return func(d interface{}) {
		switch device := d.(type) {
		case *AristaHTTP:
			device.TLSConfig.SkipVerify = true
		case *GNMIClient:
			device.TLSConfig.SkipVerify = true
			device.TLSConfig.Insecure = true
		case *RESTCONFClient:
			device.TLSConfig.SkipVerify = true
			device.TLSConfig.Insecure = true
		}
	}
}
