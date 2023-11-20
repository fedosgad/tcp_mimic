package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Quirk performs additional operations on a packet layer.
type Quirk interface {
	// Name returns p0f-compliant quirk name to be used in raw_sig parsing.
	Name() string
	// Apply performs operations on a packet.
	// It must return ErrNoLayer if packet does not have a layer of required type.
	Apply(gopacket.Packet) error
}

// "don't fragment" set.
// Expects IPv4 layer.
type dfQuirk struct{}

func (q dfQuirk) Name() string {
	return "df"
}

func (q dfQuirk) Apply(packet gopacket.Packet) error {
	layer := packet.Layer(layers.LayerTypeIPv4)
	if layer == nil {
		return ErrNoLayer{layers.LayerTypeIPv4}
	}
	ip := layer.(*layers.IPv4)
	ip.Flags |= layers.IPv4DontFragment
	return nil
}
