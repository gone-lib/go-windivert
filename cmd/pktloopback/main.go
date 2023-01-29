// Prints every ICMP packet. This program works in non-sniff mode, so packets must be re-injected.
// Usage:
//
//	pktloopback
package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"

	"github.com/gone-lib/go-windivert/pkg/diverter"
	"github.com/gone-lib/go-windivert/pkg/ffi"
	"github.com/google/gopacket"
)

var d *diverter.Diverter
var cleanupOnce sync.Once

func cleanup() {
	cleanupOnce.Do(func() {
		err := d.Stop()
		if err != nil {
			panic(err)
		}
	})
}

func main() {
	var err error

	config := diverter.Config{
		DLLPath: "WinDivert.dll",
		Flag:    ffi.Fragments,
		// Flag:    ffi.None,
		Filter: "icmp",
		// Filter: "true",
		// Filter: "udp",
		// Filter: "icmp or icmpv6",
		// Filter: "udp or icmp or icmpv6",
		// Filter: "udp.DstPort == 53",
		// Filter:  "outbound and !loopback and udp",
		// Filter: "outbound and !loopback and udp and udp.DstPort == 53",
		// Filter: "outbound and !loopback and udp and udp.DstPort == 53",
	}

	d, err = diverter.New(&config)
	if err != nil {
		panic(err)
	}

	err = d.Start()
	if err != nil {
		panic(err)
	}
	defer cleanup()

	c := make(chan os.Signal, 1)
	go func() {
		<-c
		cleanup()
	}()
	signal.Notify(c, os.Interrupt)

	for pkt := range d.RecvChan() {
		fmt.Println(pkt)
		packet := pkt.Decode(gopacket.Default)
		fmt.Println(packet)
		d.SendChan() <- pkt
	}
}
