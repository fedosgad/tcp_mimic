package main

import (
	"math/rand"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Quirk performs additional operations on a packet layer.
type Quirk interface {
	// Name returns p0f-compliant quirk name to be used in raw_sig parsing.
	Name() string
	// Apply performs operations on a packet.
	// It must return ErrNoLayer if packet does not have a layer of required type.
	Apply(gopacket.Packet, bool) error
}

// "don't fragment" set.
// Expects IPv4 layer.
type dfQuirk struct{}

func (q dfQuirk) Name() string {
	return "df"
}

func (q dfQuirk) Apply(packet gopacket.Packet, isIn bool) error {
	layer := packet.Layer(layers.LayerTypeIPv4)
	if layer == nil {
		return ErrNoLayer{layers.LayerTypeIPv4}
	}
	ip := layer.(*layers.IPv4)
	ip.Flags |= layers.IPv4DontFragment
	if !isIn {
		ip.Flags &= ^layers.IPv4DontFragment
	}
	return nil
}

// "don't fragment" set but IPID non-zero
// Expects IPv4 layer.
type idpQuirk struct{}

func (q idpQuirk) Name() string {
	return "id+"
}

func (q idpQuirk) Apply(packet gopacket.Packet, isIn bool) error {
	layer := packet.Layer(layers.LayerTypeIPv4)
	if layer == nil {
		return ErrNoLayer{layers.LayerTypeIPv4}
	}
	if !isIn {
		return nil
	}
	ip := layer.(*layers.IPv4)
	ip.Flags |= layers.IPv4DontFragment
	if ip.Id == 0 {
		ip.Id = uint16(rand.Intn(1<<16-1) + 1)
	}
	return nil
}

// DF not set but IPID is zero
// Expects IPv4 layer.
type idmQuirk struct{}

func (q idmQuirk) Name() string {
	return "id-"
}

func (q idmQuirk) Apply(packet gopacket.Packet, isIn bool) error {
	layer := packet.Layer(layers.LayerTypeIPv4)
	if layer == nil {
		return ErrNoLayer{layers.LayerTypeIPv4}
	}
	if !isIn {
		return nil
	}
	ip := layer.(*layers.IPv4)
	ip.Flags &= ^layers.IPv4DontFragment
	ip.Id = 0
	return nil
}

// explicit congestion notification support
type ecnQuirk struct{}

func (q ecnQuirk) Name() string {
	return "ecn"
}

func (q ecnQuirk) Apply(packet gopacket.Packet, isIn bool) error {
	var mask uint8 = 0b11
	layer := packet.Layer(layers.LayerTypeIPv4)
	if layer == nil {
		return ErrNoLayer{layers.LayerTypeIPv4}
	}
	ip := layer.(*layers.IPv4)
	if !isIn {
		ip.TOS &= ^mask
		return nil
	}
	if (ip.TOS&mask != 0b10) && (ip.TOS&mask != 0b01) {
		ip.TOS |= uint8(rand.Intn(3-1) + 1) // b01 || b10
	}
	return nil
}

type zeropQuirk struct{}

func (q zeropQuirk) Name() string {
	return "0+"
}

func (q zeropQuirk) Apply(packet gopacket.Packet, isIn bool) error {
	layer := packet.Layer(layers.LayerTypeIPv4)
	if layer == nil {
		return ErrNoLayer{layers.LayerTypeIPv4}
	}
	ip := layer.(*layers.IPv4)

	ip.Flags |= layers.IPv4EvilBit
	if !isIn {
		ip.Flags &= ^layers.IPv4EvilBit
	}
	return nil
}

// non-zero IPv6 flow ID
// ignored for IPv4 -> skip
type flowQuirk struct{}

func (q flowQuirk) Name() string {
	return "flow"
}

func (q flowQuirk) Apply(packet gopacket.Packet, isIn bool) error {
	// skip
	return nil
}

// sequence number is zero
type seqmQuirk struct{}

func (q seqmQuirk) Name() string {
	return "seq-"
}

func (q seqmQuirk) Apply(packet gopacket.Packet, isIn bool) error {
	layer := packet.Layer(layers.LayerTypeTCP)
	if layer == nil {
		return ErrNoLayer{layers.LayerTypeTCP}
	}
	tcp := layer.(*layers.TCP)
	if !isIn {
		if tcp.Seq == 0 {
			tcp.Seq = uint32(rand.Intn(1<<32-1) + 1)
		}
		return nil
	}
	tcp.Seq = 0
	return nil
}

// ACK number is non-zero, but ACK flag not set
type ackpQuirk struct{}

func (q ackpQuirk) Name() string {
	return "ack+"
}

func (q ackpQuirk) Apply(packet gopacket.Packet, isIn bool) error {
	layer := packet.Layer(layers.LayerTypeTCP)
	if layer == nil {
		return ErrNoLayer{layers.LayerTypeTCP}
	}
	if !isIn {
		return nil
	}
	tcp := layer.(*layers.TCP)

	tcp.ACK = false
	if tcp.Ack == 0 {
		tcp.Ack = uint32(rand.Intn(1<<32-1) + 1)
	}
	return nil
}

// ACK number is zero, but ACK flag set
type ackmQuirk struct{}

func (q ackmQuirk) Name() string {
	return "ack-"
}

func (q ackmQuirk) Apply(packet gopacket.Packet, isIn bool) error {
	layer := packet.Layer(layers.LayerTypeTCP)
	if layer == nil {
		return ErrNoLayer{layers.LayerTypeTCP}
	}
	if !isIn {
		return nil
	}
	tcp := layer.(*layers.TCP)

	tcp.ACK = true
	tcp.Ack = 0
	return nil
}

// URG pointer is non-zero, but URG flag not set
type uptrpQuirk struct{}

func (q uptrpQuirk) Name() string {
	return "uptr+"
}

func (q uptrpQuirk) Apply(packet gopacket.Packet, isIn bool) error {
	layer := packet.Layer(layers.LayerTypeTCP)
	if layer == nil {
		return ErrNoLayer{layers.LayerTypeTCP}
	}
	if !isIn {
		return nil
	}
	tcp := layer.(*layers.TCP)

	if tcp.Urgent == 0 {
		tcp.Urgent = uint16(rand.Intn(1<<16-1) + 1)
	}
	tcp.URG = false
	return nil
}

// URG flag used
type urgfpQuirk struct{}

func (q urgfpQuirk) Name() string {
	return "urgf+"
}

func (q urgfpQuirk) Apply(packet gopacket.Packet, isIn bool) error {
	layer := packet.Layer(layers.LayerTypeTCP)
	if layer == nil {
		return ErrNoLayer{layers.LayerTypeTCP}
	}
	tcp := layer.(*layers.TCP)

	tcp.URG = true
	if !isIn {
		tcp.URG = false
	}
	return nil
}

// PUSH flag used
type pushfpQuirk struct{}

func (q pushfpQuirk) Name() string {
	return "pushf+"
}

func (q pushfpQuirk) Apply(packet gopacket.Packet, isIn bool) error {
	layer := packet.Layer(layers.LayerTypeTCP)
	if layer == nil {
		return ErrNoLayer{layers.LayerTypeTCP}
	}
	tcp := layer.(*layers.TCP)

	tcp.PSH = true
	if !isIn {
		tcp.PSH = false
	}
	return nil
}

// own timestamp specified as zero
type ts1mQuirk struct{}

func (q ts1mQuirk) Name() string {
	return "ts1-"
}

func (q ts1mQuirk) Apply(packet gopacket.Packet, isIn bool) error {
	layer := packet.Layer(layers.LayerTypeTCP)
	if layer == nil {
		return ErrNoLayer{layers.LayerTypeTCP}
	}
	tcp := layer.(*layers.TCP)
	if !isIn {
		return nil
	}
	for _, option := range tcp.Options {
		if option.OptionType == layers.TCPOptionKindTimestamps {
			option.OptionData = []byte{0, 0, 0, 0, 0, 0, 0, 0} //TODO: check it out
		}
	}
	return nil
}

// non-zero peer timestamp on initial SYN
type ts2pQuirk struct{}

func (q ts2pQuirk) Name() string {
	return "ts2+"
}

func (q ts2pQuirk) Apply(packet gopacket.Packet, isIn bool) error {
	layer := packet.Layer(layers.LayerTypeTCP)
	if layer == nil {
		return ErrNoLayer{layers.LayerTypeTCP}
	}
	tcp := layer.(*layers.TCP)
	if !isIn {
		return nil
	}
	for _, option := range tcp.Options {
		if option.OptionType == layers.TCPOptionKindTimestamps {
			option.OptionData = []byte{0, 0, 0, 0, 0, 0, 0, 0} //TODO: check it out
		}
	}
	return nil
}

// trailing non-zero data in options segment
type optpQuirk struct{}

func (q optpQuirk) Name() string {
	return "opt+"
}

func (q optpQuirk) Apply(packet gopacket.Packet, isIn bool) error {
	// TODO
	return nil
}

// excessive window scaling factor (> 14)
type exwsQuirk struct{}

func (q exwsQuirk) Name() string {
	return "exws"
}

func (q exwsQuirk) Apply(packet gopacket.Packet, isIn bool) error {
	layer := packet.Layer(layers.LayerTypeTCP)
	if layer == nil {
		return ErrNoLayer{layers.LayerTypeTCP}
	}
	tcp := layer.(*layers.TCP)
	if !isIn {
		return nil
	}
	//TODO:
	_ = tcp.Options
	return nil
}

// malformed TCP options
type badQuirk struct{}

func (q badQuirk) Name() string {
	return "bad"
}

func (q badQuirk) Apply(packet gopacket.Packet, isIn bool) error {
	layer := packet.Layer(layers.LayerTypeTCP)
	if layer == nil {
		return ErrNoLayer{layers.LayerTypeTCP}
	}
	tcp := layer.(*layers.TCP)
	if !isIn {
		return nil
	}
	// TODO:
	_ = tcp.Options
	return nil
}
