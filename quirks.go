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

type idpQuirk struct{}

func (q idpQuirk) Name() string {
	return "id+"
}

func (q idpQuirk) Apply(packet gopacket.Packet) error {
	return nil
}

type idmQuirk struct{}

func (q idmQuirk) Name() string {
	return "id-"
}

func (q idmQuirk) Apply(packet gopacket.Packet) error {
	return nil
}

type ecnQuirk struct{}

func (q ecnQuirk) Name() string {
	return "ecn+"
}

func (q ecnQuirk) Apply(packet gopacket.Packet) error {
	return nil
}

type zeropQuirk struct{}

func (q zeropQuirk) Name() string {
	return "0+"
}

func (q zeropQuirk) Apply(packet gopacket.Packet) error {
	return nil
}

type flowQuirk struct{}

func (q flowQuirk) Name() string {
	return "flow"
}

func (q flowQuirk) Apply(packet gopacket.Packet) error {
	return nil
}

type seqmQuirk struct{}

func (q seqmQuirk) Name() string {
	return "seq-"
}

func (q seqmQuirk) Apply(packet gopacket.Packet) error {
	return nil
}

type ackpQuirk struct{}

func (q ackpQuirk) Name() string {
	return "ack+"
}

func (q ackpQuirk) Apply(packet gopacket.Packet) error {
	return nil
}

type ackmQuirk struct{}

func (q ackmQuirk) Name() string {
	return "ack-"
}

func (q ackmQuirk) Apply(packet gopacket.Packet) error {
	return nil
}

type uptrpQuirk struct{}

func (q uptrpQuirk) Name() string {
	return "uptr+"
}

func (q uptrpQuirk) Apply(packet gopacket.Packet) error {
	return nil
}

type urgfpQuirk struct{}

func (q urgfpQuirk) Name() string {
	return "urgf+"
}

func (q urgfpQuirk) Apply(packet gopacket.Packet) error {
	return nil
}

type pushfpQuirk struct{}

func (q pushfpQuirk) Name() string {
	return "pushf+"
}

func (q pushfpQuirk) Apply(packet gopacket.Packet) error {
	return nil
}

type ts1mQuirk struct{}

func (q ts1mQuirk) Name() string {
	return "ts1-"
}

func (q ts1mQuirk) Apply(packet gopacket.Packet) error {
	return nil
}

type ts2pQuirk struct{}

func (q ts2pQuirk) Name() string {
	return "ts2+"
}

func (q ts2pQuirk) Apply(packet gopacket.Packet) error {
	return nil
}

type optpQuirk struct{}

func (q optpQuirk) Name() string {
	return "opt+"
}

func (q optpQuirk) Apply(packet gopacket.Packet) error {
	return nil
}

type exwsQuirk struct{}

func (q exwsQuirk) Name() string {
	return "exws"
}

func (q exwsQuirk) Apply(packet gopacket.Packet) error {
	return nil
}

type badQuirk struct{}

func (q badQuirk) Name() string {
	return "bad"
}

func (q badQuirk) Apply(packet gopacket.Packet) error {
	return nil
}
