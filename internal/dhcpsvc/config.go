package dhcpsvc

import (
	"net/netip"
	"time"

	"github.com/google/gopacket/layers"
)

// Config is the configuration for the DHCP service.
type Config struct {
	// Interfaces stores configurations of DHCP server specific for the network
	// interface identified by its name.
	Interfaces map[string]*InterfaceConfig

	// LocalDomainName is the top-level domain name to use for resolving DHCP
	// clients' hostnames.
	LocalDomainName string

	// ICMPTimeout is the timeout for checking another DHCP server's presence.
	ICMPTimeout time.Duration

	// Enabled is the state of the service, whether it is enabled or not.
	Enabled bool
}

// InterfaceConfig is the configuration of a single DHCP interface.
type InterfaceConfig struct {
	// DHCPv4 is the configuration of DHCP protocol for IPv4.
	DHCPv4 *DHCPv4Config

	// DHCPv6 is the configuration of DHCP protocol for IPv6.
	DHCPv6 *DHCPv6Config
}

// DHCPv4Config is the interface-specific configuration for DHCPv4.
type DHCPv4Config struct {
	// GatewayIP is the IPv4 address of the network's gateway.  It is used as
	// the default gateway for DHCP clients and also used in calculating the
	// network-specific broadcast address.
	GatewayIP netip.Addr

	// SubnetMask is the IPv4 subnet mask of the network.  It should be a valid
	// IPv4 subnet mask (i.e. all 1s followed by all 0s).
	SubnetMask netip.Addr

	// RangeStart is the first address in the range to assign to DHCP clients.
	RangeStart netip.Addr

	// RangeEnd is the last address in the range to assign to DHCP clients.
	RangeEnd netip.Addr

	// Options is the list of DHCP options to send to DHCP clients.
	Options layers.DHCPOptions

	// LeaseDuration is the TTL of a DHCP lease.
	LeaseDuration time.Duration

	// Enabled is the state of the DHCPv4 service, whether it is enabled or not
	// on the specific interface.
	Enabled bool
}

// DHCPv6Config is the interface-specific configuration for DHCPv6.
type DHCPv6Config struct {
	// RangeStart is the first address in the range to assign to DHCP clients.
	RangeStart netip.Addr

	// Options is the list of DHCP options to send to DHCP clients.
	Options layers.DHCPOptions

	// LeaseDuration is the TTL of a DHCP lease.
	LeaseDuration time.Duration

	// RASlaacOnly defines whether the DHCP clients should only use SLAAC for
	// address assignment.
	RASLAACOnly bool

	// RAAllowSlaac defines whether the DHCP clients may use SLAAC for address
	// assignment.
	RAAllowSLAAC bool

	// Enabled is the state of the DHCPv6 service, whether it is enabled or not
	// on the specific interface.
	Enabled bool
}
