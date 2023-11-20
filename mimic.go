package main

import (
	"github.com/chifflier/nfqueue-go/nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
)

type MimicP0f struct {
	Sig P0FSignature
}

func (m MimicP0f) NFQCallback(payload *nfqueue.Payload) int {
	// Decode a packet.
	// TODO: IP version should be checked here and processed accordingly afterwards.
	packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)

	// Check if packet is TCP packet.
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		// Packet is not a TCP - fall back to default behavior.
		// Actually, this should not happen when iptables rules are properly setup.
		return m.defaultBehavior(payload)
	}
	tcp := tcpLayer.(*layers.TCP)

	// Only modify initial SYN packets (p0f DBs are based on them + it's hard to keep track of TCP stream beyond that).
	if !(tcp.SYN && !(tcp.FIN || tcp.RST || tcp.PSH || tcp.ACK)) {
		_ = payload.SetVerdict(nfqueue.NF_ACCEPT)
		return 0
	}

	// Process IP layer.
	ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip.TTL != m.Sig.ITTL {
		ip.TTL = m.Sig.ITTL
		log.Printf("Change TTL from %d to %d.\n", ip.TTL, m.Sig.ITTL)
	}
	if len(ip.Options) != m.Sig.OLen {
		log.Printf("WARN: IP opts len mismatch: expect %d, got %d. Opts: %v\n", len(ip.Options), m.Sig.OLen, ip.Options)
		// Special case: 0 options expected, got options - omit them entirely.
		// TODO: is it safe to omit options without additional actions?
		if m.Sig.OLen == 0 {
			ip.Options = nil
			log.Printf("Omit IP opts.\n")
		}
	}

	// Process TCP layer.
	tcp.Window = m.Sig.WSize

	// TODO: convert to indexed array maybe?
	tcpOpts := make(map[layers.TCPOptionKind]layers.TCPOption)
	paddingLen := 0
	for _, opt := range tcp.Options {
		tcpOpts[opt.OptionType] = opt
	}
	tcp.Options = tcp.Options[:0]
	for _, kind := range m.Sig.OLayout {
		var opt layers.TCPOption
		switch kind {
		case TCPOptionPaddingByte:
			paddingLen++
		default:
			ok := false
			opt, ok = tcpOpts[kind]
			if !ok {
				// Got no matching TCP option.
				log.Printf("No matching TCP option: sig wants %s", opt.String())
				// TODO: what can be done?
			}
		}
		tcp.Options = append(tcp.Options, opt)
	}

	// Apply quirks.
	for _, quirk := range m.Sig.Quirks {
		if err := quirk.Apply(packet); err != nil {
			log.Printf("Error applying quirk %s: %s", quirk.Name(), err)

			// Quirk failed to apply, packet can be in improper state - fall back to default behavior.
			return m.defaultBehavior(payload)
		}
	}

	// Recalculate checksums.

	// Send modified packet.

	return 0
}

func (m MimicP0f) defaultBehavior(payload *nfqueue.Payload) int {
	// TODO: make it configurable
	_ = payload.SetVerdict(nfqueue.NF_ACCEPT)
	return 0
}
