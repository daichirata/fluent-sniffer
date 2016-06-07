package main

import (
	"flag"

	"github.com/daichirata/fluent-sniffer"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	iface = flag.String("i", "", "Listen on interface.")
	port  = flag.String("p", "24224", "Port number.")
)

func main() {
	flag.Parse()

	handle, err := pcap.OpenLive(*iface, 65535, false, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("tcp and port " + *port); err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		handlePacket(packet)
	}
}

func handlePacket(packet gopacket.Packet) {
	app := packet.ApplicationLayer()
	if app == nil {
		return
	}
	sniffer.Decode(app.Payload())
}
