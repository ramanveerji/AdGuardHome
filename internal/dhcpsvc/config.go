package dhcpsvc

import (
	"net/netip"

	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/google/gopacket/layers"
)

// Config is the configuration for the DHCP service.
type Config struct {
	// Interfaces stores configurations of DHCP server specific for network
	// interface.
	Interfaces map[string]*InterfaceConfig `yaml:"interfaces"`

	// LocalDomainName is the top-level domain name to use for resolving DHCP
	// clients' hostnames.
	LocalDomainName string `yaml:"local_domain_name"`

	// ICMPTimeout is the timeout for checking another DHCP server's presence.
	ICMPTimeout timeutil.Duration `yaml:"icmp_timeout"`

	// Enabled is the state of the DHCP service, whether it is enabled or not.
	Enabled bool `yaml:"enabled"`
}

// InterfaceConfig is the configuration of a single DHCP interface.
type InterfaceConfig struct {
	// DHCPv4 is the configuration for handling IPv4.
	DHCPv4 *DHCPv4Config `yaml:"dhcpv4"`

	// DHCPv6 is the configuration for handling IPv6.
	DHCPv6 *DHCPv6Config `yaml:"dhcpv6"`

	// LeaseDuration is the TTL of a DHCP lease.
	LeaseDuration timeutil.Duration `yaml:"lease_duration"`
}

// DHCPv4Config is the interface-specific configuration for DHCPv4.
type DHCPv4Config struct {
	// GatewayIP is the IPv4 address of the network's gateway.  It is used as
	// the default gateway for DHCP clients and also used in calculating the
	// network-specific broadcast address.
	GatewayIP netip.Addr `yaml:"gateway_ip"`

	// SubnetMask is the IPv4 subnet mask of the network.  It should be a valid
	// IPv4 subnet mask (i.e. all 1s followed by all 0s).
	SubnetMask netip.Addr `yaml:"subnet_mask"`

	// RangeStart is the first address in the range to assign to DHCP clients.
	RangeStart netip.Addr `yaml:"range_start"`

	// RangeEnd is the last address in the range to assign to DHCP clients.
	RangeEnd netip.Addr `yaml:"range_end"`

	// Options is the list of DHCP options to send to DHCP clients.
	//
	// TODO(e.burkov):  Use custom marshaler.
	Options layers.DHCPOptions `yaml:"options"`

	// Enabled is the state of the DHCPv4 service, whether it is enabled or not
	// on the specific interface.
	Enabled bool `yaml:"enabled"`
}

// DHCPv6Config is the interface-specific configuration for DHCPv6.
type DHCPv6Config struct {
	// RangeStart is the first address in the range to assign to DHCP clients.
	RangeStart netip.Addr `yaml:"range_start"`

	// Options is the list of DHCP options to send to DHCP clients.
	//
	// TODO(e.burkov):  Use custom marshaler.
	Options layers.DHCPOptions `yaml:"options"`

	// RASlaacOnly defines whether the DHCP clients should only use SLAAC for
	// address assignment.
	RASLAACOnly bool `yaml:"ra_slaac_only"`

	// RAAllowSlaac defines whether the DHCP clients may use SLAAC for address
	// assignment.
	RAAllowSLAAC bool `yaml:"ra_allow_slaac"`

	// Enabled is the state of the DHCPv6 service, whether it is enabled or not
	// on the specific interface.
	Enabled bool `yaml:"enabled"`
}
