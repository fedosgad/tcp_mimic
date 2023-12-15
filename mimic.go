package main

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"log"
	"math/rand"

	"github.com/chifflier/nfqueue-go/nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type MimicP0f struct {
	Sig P0FSignature
}

func NFQCallback(payload *nfqueue.Payload) int {
	m := MimicP0f{iosFP}
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
		log.Printf("Change TTL from %d to %d.\n", ip.TTL, m.Sig.ITTL)
		ip.TTL = m.Sig.ITTL
	}
	if len(ip.Options) != m.Sig.OLen {
		log.Printf("WARN: IP opts len mismatch: expect %d, got %d. Opts: %v\n", len(ip.Options), m.Sig.OLen, ip.Options)
		// Special case: 0 options expected, got options - omit them entirely.
		if m.Sig.OLen == 0 {
			ip.Options = nil
			log.Printf("Omit IP opts.\n")
		}
	}

	// Process TCP layer.

	if m.Sig.MSS == -1 {
		// TODO: what do with * (-1) value
		m.Sig.MSS = 1460
	}

	switch m.Sig.WSize {
	case -1:
		// * TODO:
		m.Sig.WSize = 65535
	case -2:
		// mss*4
		m.Sig.WSize = m.Sig.MSS * 4
	case -3:
		// mtu*4 TODO:
		m.Sig.WSize = 65535
	case -4:
		// %8192 TODO:
		m.Sig.WSize = 8192
	}
	tcp.Window = uint16(m.Sig.WSize)

	if m.Sig.Scale == -1 {
		m.Sig.Scale = 0
	}

	// TODO: convert to indexed array maybe?
	tcpOpts := make(map[layers.TCPOptionKind]layers.TCPOption)
	for _, opt := range tcp.Options {
		tcpOpts[opt.OptionType] = opt
	}
	tcp.Options = tcp.Options[:0]
	for _, kind := range m.Sig.OLayout {
		var opt layers.TCPOption
		switch kind {
		case TCPOptionPaddingByte:
			opt = layers.TCPOption{
				OptionType:   layers.TCPOptionKindEndList,
				OptionLength: 1,
				OptionData:   nil,
			}
		case layers.TCPOptionKindNop:
			opt = layers.TCPOption{
				OptionType:   layers.TCPOptionKindNop,
				OptionLength: 1,
				OptionData:   nil,
			}
		case layers.TCPOptionKindMSS:
			bs := make([]byte, 2)
			binary.LittleEndian.PutUint16(bs, uint16(m.Sig.MSS))
			bs[0], bs[1] = bs[1], bs[0]
			opt = layers.TCPOption{
				OptionType:   layers.TCPOptionKindMSS,
				OptionLength: 4,
				OptionData:   bs,
			}
		case layers.TCPOptionKindWindowScale:
			opt = layers.TCPOption{
				OptionType:   layers.TCPOptionKindWindowScale,
				OptionLength: 3,
				OptionData:   []byte{byte(m.Sig.Scale)},
			}
		case layers.TCPOptionKindSACKPermitted:
			opt = layers.TCPOption{
				OptionType:   layers.TCPOptionKindSACKPermitted,
				OptionLength: 2,
				OptionData:   nil,
			}
		case layers.TCPOptionKindSACK:
			var ok bool
			opt, ok = tcpOpts[kind]
			if !ok {
				// TODO: check data
				opt = layers.TCPOption{
					OptionType:   layers.TCPOptionKindSACK,
					OptionLength: 2,
					OptionData:   nil,
				}
			}
		case layers.TCPOptionKindTimestamps:
			var ok bool
			opt, ok = tcpOpts[kind]
			if !ok {
				// TODO: check data
				opt = layers.TCPOption{
					OptionType:   layers.TCPOptionKindTimestamps,
					OptionLength: 10,
					OptionData:   []byte{0, 0, 0, 0, 0, 0, 0, 0},
				}
			}
		default:
			ok := false
			opt, ok = tcpOpts[kind]
			if !ok {
				// Got no matching TCP option.
				log.Fatalf("No matching TCP option: sig wants %s", opt.String())
			}
		}
		tcp.Options = append(tcp.Options, opt)
	}

	// Apply quirks.
	quirksInSig := make(map[string]struct{})
	for _, quirk := range m.Sig.Quirks {
		quirksInSig[quirk.Name()] = struct{}{}
	}

	for quirkName, quirk := range QuirkMap {
		_, present := quirksInSig[quirkName]
		if err := quirk.Apply(packet, present); err != nil {
			log.Printf("Error applying quirk %s: %s", quirk.Name(), err)

			// Quirk failed to apply, packet can be in improper state - fall back to default behavior.
			return m.defaultBehavior(payload)
		}
	}

	switch m.Sig.PClass {
	// *
	case -1:
		// do nothing
		_ = nil
	// 0
	case 0:
		tcp.Payload = nil
	// +
	case 1:
		if len(tcp.Payload) == 0 {
			buf := make([]byte, rand.Intn(9)+1)
			_, err := cryptorand.Read(buf)
			if err != nil {
				log.Fatalf("error while generating random string: %s", err)
			}
			tcp.Payload = buf
		}
	}
	// Recalculate checksums.
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		log.Printf("Error setting network layer ip: %s", err)
		return m.defaultBehavior(payload)
	}

	// Serialize Packet to get raw bytes
	if err := gopacket.SerializePacket(buffer, options, packet); err != nil {
		log.Printf("Can't serialize packet: %s", err)
		return m.defaultBehavior(payload)
	}

	// Send modified packet.
	_ = payload.SetVerdictModified(nfqueue.NF_ACCEPT, buffer.Bytes())

	return 0
}

func (m MimicP0f) defaultBehavior(payload *nfqueue.Payload) int {
	// TODO: make it configurable
	_ = payload.SetVerdict(nfqueue.NF_ACCEPT)
	return 0
}
