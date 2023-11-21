package main

import (
	"encoding/hex"
	"fmt"
	"github.com/chifflier/nfqueue-go/nfqueue"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func realCallback(payload *nfqueue.Payload) int {
	fmt.Println("Real callback")
	fmt.Printf("  id: %d\n", payload.Id)
	fmt.Println(hex.Dump(payload.Data))
	// Decode a packet
	packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)
	// Get the TCP layer from this packet
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		fmt.Println("This is a TCP packet!")
		// Get actual TCP data from this layer
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
	}
	// Iterate over all layers, printing out each layer type
	for _, layer := range packet.Layers() {
		fmt.Println("PACKET LAYER:", layer.LayerType())
		fmt.Println(gopacket.LayerDump(layer))
	}
	fmt.Println("-- ")
	payload.SetVerdict(nfqueue.NF_ACCEPT)
	return 0
}

func main() {
	q := new(nfqueue.Queue)

	_ = q.SetCallback(NFQCallback)

	err := q.Init()
	if err != nil {
		log.Fatal(err)
	}

	err = q.Unbind(syscall.AF_INET)
	if err != nil {
		log.Fatal(err)
	}
	_ = q.Bind(syscall.AF_INET)

	err = q.CreateQueue(0)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = q.DestroyQueue()
		q.Close()
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			// sig is a ^C, handle it
			_ = sig
			q.StopLoop()
		}
	}()

	err = q.Loop()
	if err != nil {
		log.Fatal(err)
	}
}
