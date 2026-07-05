package facts

import "strings"

var openConfigRoot = map[string]string{
	"system": "openconfig-system:system", "platform": "openconfig-platform:components",
	"interfaces": "openconfig-interfaces:interfaces", "lldp": "openconfig-lldp:lldp",
	"bgp": "openconfig-network-instance:network-instances", "isis": "openconfig-network-instance:network-instances",
	"ldp": "openconfig-network-instance:network-instances",
}

var genericDefinitions = map[string]Definition{
	"system":     {NETCONFFilter: `<system xmlns="http://openconfig.net/yang/system"/>`},
	"platform":   {NETCONFFilter: `<components xmlns="http://openconfig.net/yang/platform"/>`},
	"interfaces": {NETCONFFilter: `<interfaces xmlns="http://openconfig.net/yang/interfaces"/>`},
	"lldp":       {NETCONFFilter: `<lldp xmlns="http://openconfig.net/yang/lldp"/>`},
	"bgp":        {NETCONFFilter: `<network-instances xmlns="http://openconfig.net/yang/network-instance"><network-instance><protocols><protocol><bgp xmlns="http://openconfig.net/yang/bgp"/></protocol></protocols></network-instance></network-instances>`},
	"isis":       {NETCONFFilter: `<network-instances xmlns="http://openconfig.net/yang/network-instance"><network-instance><protocols><protocol><isis xmlns="http://openconfig.net/yang/isis"/></protocol></protocols></network-instance></network-instances>`},
	"ldp":        {NETCONFFilter: `<network-instances xmlns="http://openconfig.net/yang/network-instance"><network-instance><mpls><signaling-protocols><ldp xmlns="http://openconfig.net/yang/mpls-ldp"/></signaling-protocols></mpls></network-instance></network-instances>`},
}

var xrDefinitions = map[string]Definition{
	"system":     {Command: "show version", Parser: "xr_facts_system", NETCONFFilter: `<system xmlns="http://openconfig.net/yang/system"/>`},
	"platform":   {Command: "show platform", Parser: "xr_show_platform", NETCONFFilter: `<components xmlns="http://openconfig.net/yang/platform"/>`},
	"interfaces": {Command: "show interfaces brief", Parser: "xr_show_interfaces_brief_textfsm", NETCONFFilter: `<interfaces xmlns="http://openconfig.net/yang/interfaces"/>`},
	"lldp":       {Command: "show lldp neighbors detail", Parser: "xr_facts_lldp", NETCONFFilter: `<lldp xmlns="http://openconfig.net/yang/lldp"/>`},
	"bgp":        {Command: "show bgp summary", Parser: "xr_facts_bgp", NETCONFFilter: `<network-instances xmlns="http://openconfig.net/yang/network-instance"><network-instance><protocols><protocol><bgp xmlns="http://openconfig.net/yang/bgp"/></protocol></protocols></network-instance></network-instances>`},
	"isis":       {Command: "show isis neighbors", Parser: "xr_facts_isis", NETCONFFilter: `<network-instances xmlns="http://openconfig.net/yang/network-instance"><network-instance><protocols><protocol><isis xmlns="http://openconfig.net/yang/isis"/></protocol></protocols></network-instance></network-instances>`},
	"ldp":        {Command: "show mpls ldp neighbor brief", Parser: "xr_facts_ldp", NETCONFFilter: `<network-instances xmlns="http://openconfig.net/yang/network-instance"><network-instance><mpls><signaling-protocols><ldp xmlns="http://openconfig.net/yang/mpls-ldp"/></signaling-protocols></mpls></network-instance></network-instances>`},
}

var eosDefinitions = map[string]Definition{
	"system":     {Command: "show version", Parser: "eos_facts_system"},
	"platform":   {Command: "show module", Parser: "eos_facts_platform"},
	"interfaces": {Command: "show interfaces status", Parser: "eos_facts_interfaces"},
	"lldp":       {Command: "show lldp neighbors detail", Parser: "eos_facts_lldp"},
	"bgp":        {Command: "show ip bgp summary", Parser: "eos_facts_bgp"},
}

var junosDefinitions = map[string]Definition{
	"system":     {Command: "show version", Parser: "junos_facts_system"},
	"platform":   {Command: "show chassis hardware", Parser: "junos_facts_platform"},
	"interfaces": {Command: "show interfaces terse", Parser: "junos_facts_interfaces"},
	"lldp":       {Command: "show lldp neighbors detail", Parser: "junos_facts_lldp"},
	"bgp":        {Command: "show bgp summary", Parser: "junos_facts_bgp"},
}

func canonicalPlatform(platform string) string {
	value := strings.ToLower(strings.TrimSpace(platform))
	switch value {
	case "cisco_iosxr", "iosxr", "ios-xr":
		return "cisco_iosxr"
	case "arista_eos", "eos", "arista-eos":
		return "arista_eos"
	case "juniper_junos", "junos", "juniper-junos":
		return "juniper_junos"
	default:
		return value
	}
}

func lookup(platform, subset string) (Definition, bool) {
	definition, ok := genericDefinitions[subset]
	if !ok {
		return Definition{}, false
	}
	switch canonicalPlatform(platform) {
	case "cisco_iosxr":
		sshDefinition := xrDefinitions[subset]
		definition.Command = sshDefinition.Command
		definition.Parser = sshDefinition.Parser
	case "arista_eos":
		sshDefinition := eosDefinitions[subset]
		definition.Command = sshDefinition.Command
		definition.Parser = sshDefinition.Parser
	case "juniper_junos":
		sshDefinition := junosDefinitions[subset]
		definition.Command = sshDefinition.Command
		definition.Parser = sshDefinition.Parser
	}
	return definition, true
}
