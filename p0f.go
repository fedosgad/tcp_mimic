package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"strconv"
	"strings"
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
	WSize   int                    // Window size. '*' == -1, 'mss*4' == -2, 'mtu*4' == -3, '%8192' == -4
	Scale   int                    // Window scaling factor, if specified in TCP options. '*' == -1
	OLayout []layers.TCPOptionKind // Layout and ordering of TCP options, if any.
	Quirks  []Quirk                // Properties and quirks observed in IP or TCP headers.
	PClass  PayloadClass           // Payload size classification.
}

var QuirkMap = map[string]Quirk{
	"df":     dfQuirk{},
	"id+":    idpQuirk{},
	"id-":    idmQuirk{},
	"ecn":    ecnQuirk{},
	"0+":     zeropQuirk{},
	"flow":   flowQuirk{},
	"seq-":   seqmQuirk{},
	"ack+":   ackpQuirk{},
	"ack-":   ackmQuirk{},
	"uptr+":  uptrpQuirk{},
	"urgf+":  urgfpQuirk{},
	"pushf+": pushfpQuirk{},
	"ts1-":   ts1mQuirk{},
	"ts2+":   ts2pQuirk{},
	"opt+":   optpQuirk{},
	"exws":   exwsQuirk{},
	"bad":    badQuirk{},
}

// ParseRawSig creates new P0FSignature from raw_sig p0f record.
func ParseRawSig(rawSig string) (P0FSignature, error) {
	// example - 4:64+0:0:1460:65535,9:mss,sok,ts,nop,ws:df,id+:0
	signatures := strings.Split(rawSig, ":")
	p0f := P0FSignature{}
	sigAliases := []string{"ver", "ittl", "olen", "mss", "wsize", "olayout", "quirks", "pclass"}
	for i, sigAlias := range sigAliases {
		switch sigAlias {
		case "ver":
			num, err := strconv.Atoi(signatures[i])
			if err != nil {
				return P0FSignature{}, fmt.Errorf("unknown version: %s", err)
			}
			p0f.Ver = IPVersion(num)
		case "ittl":
			sum := strings.Split(signatures[i], "+")
			ittl, err := strconv.Atoi(sum[0])
			if err != nil {
				return P0FSignature{}, fmt.Errorf("unknown ittl: %s", err)
			}
			if len(sum) == 2 {
				secondPath, err := strconv.Atoi(sum[1])
				if !(err != nil) {
					ittl += secondPath
				}
			}
			p0f.ITTL = uint8(ittl)
		case "olen":
			olen, _ := strconv.Atoi(signatures[i])
			// ignore errors
			p0f.OLen = olen
		case "mss":
			mss, err := strconv.Atoi(signatures[i])
			if err != nil {
				// capture mss="*"
				mss = -1
			}
			p0f.MSS = mss
		case "wsize":
			var (
				wsize, scale int
				err          error
			)
			wSizeAndScale := strings.Split(signatures[i], ",")
			switch wSizeAndScale[0] {
			case "mss*4":
				p0f.WSize = -2
			case "mtu*4":
				p0f.WSize = -3
			case "%8192":
				p0f.WSize = -4
			case "*":
				p0f.WSize = -1
			default:
				wsize, err = strconv.Atoi(wSizeAndScale[0])
				if err != nil {
					return P0FSignature{}, fmt.Errorf("unknown wsize: %s", err)
				}
			}
			if wSizeAndScale[1] == "*" {
				scale = -1
			}
			scale, err = strconv.Atoi(wSizeAndScale[1])
			if err != nil {
				return P0FSignature{}, fmt.Errorf("unknown scale: %s", err)
			}
			p0f.WSize = wsize
			p0f.Scale = scale
		case "olayout":
			olayout := make([]layers.TCPOptionKind, 0, 8)
			lst := strings.Split(signatures[i], ",")
			layouts := map[string]layers.TCPOptionKind{
				"eol": layers.TCPOptionKindEndList,
				"nop": layers.TCPOptionKindNop,
				"mss": layers.TCPOptionKindMSS,
				"ws":  layers.TCPOptionKindWindowScale,
				"sok": layers.TCPOptionKindSACKPermitted,
				"ts":  layers.TCPOptionKindTimestamps,
			}
			for _, layout := range lst {
				if strings.HasPrefix(layout, "eol+") {
					padStr := strings.TrimPrefix(layout, "eol+")
					pad, err := strconv.Atoi(padStr)
					if err != nil {
						return P0FSignature{}, fmt.Errorf("unknown scale: %s", err)
					}
					olayout = append(olayout, layers.TCPOptionKind(pad*255))
					continue
				}
				olayout = append(olayout, layouts[layout])
			}
			p0f.OLayout = olayout
		case "quirks":
			lst := strings.Split(signatures[i], ",")
			for _, quirk := range lst {
				p0f.Quirks = append(p0f.Quirks, QuirkMap[quirk])
			}
		case "pclass":
			switch signatures[i] {
			case "0":
				p0f.PClass = 0
			case "*":
				p0f.PClass = -1
			case "+":
				p0f.PClass = 1
			}
		}
	}
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
		layers.TCPOptionKindTimestamps,                    //"ts",
		layers.TCPOptionKindSACKPermitted,                 //"sok",
		layers.TCPOptionKindEndList, TCPOptionPaddingByte, //"eol+1",
	},
	Quirks: []Quirk{dfQuirk{}},
	PClass: 0,
}
