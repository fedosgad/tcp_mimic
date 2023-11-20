package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type IPVersion int

const (
	IPv4    = IPVersion(4)
	IPv6    = IPVersion(6)
	IPvBoth = IPVersion(-1)
)

// TCPOptionPaddingByte is used as a placeholder for each padding byte after
// the explicit layers.TCPOptionKindEndList.
const TCPOptionPaddingByte = layers.TCPOptionKind(255)

type ErrNoLayer struct {
	expected gopacket.LayerType
}

func (e ErrNoLayer) Error() string {
	return fmt.Sprintf("no expected %s layer in packet", e.expected)
}

type PayloadClass int

const (
	PCAny     = -1
	PCZero    = 0
	PCNonZero = 1
)

// P0FSignature represents p0f's raw_sig.
type P0FSignature struct {
	// IP layer.

	Ver  IPVersion // IP protocol version.
	ITTL uint8     // Initial TTL used by the OS.
	OLen int       // Length of IPv4 options or IPv6 extension headers

	// TCP layer.

	MSS     int                    // Maximum segment size, if specified in TCP options. '*' == -1.
	WSize   uint16                 // Window size. TODO: '*', 'mss*4', '%8192'
	Scale   int                    // Window scaling factor, if specified in TCP options. '*' == -1
	OLayout []layers.TCPOptionKind // Layout and ordering of TCP options, if any.
	Quirks  []Quirk                // Properties and quirks observed in IP or TCP headers.
	PClass  PayloadClass           // Payload size classification.
}

// ParseRawSig creates new P0FSignature from raw_sig p0f record.
func ParseRawSig(rawSig string) (P0FSignature, error) {
	panic("not implemented")
}

var iosFP = P0FSignature{
	Ver:  IPv4, // Probably should be IPvBoth
	ITTL: 64,
	OLen: 0,

	MSS:   1460,
	WSize: 65535,
	Scale: 5,
	OLayout: []layers.TCPOptionKind{
		layers.TCPOptionKindMSS,                           //"mss",
		layers.TCPOptionKindNop,                           //"nop",
		layers.TCPOptionKindWindowScale,                   //"ws",
		layers.TCPOptionKindNop,                           //"nop",
		layers.TCPOptionKindNop,                           //"nop",
		layers.TCPOptionKindTimestamps,                    //"ts",
		layers.TCPOptionKindSACKPermitted,                 //"sok",
		layers.TCPOptionKindEndList, TCPOptionPaddingByte, //"eol+1",
	},
	Quirks: []Quirk{dfQuirk{}},
	PClass: 0,
}
