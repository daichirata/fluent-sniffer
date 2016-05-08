package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/msgpack/msgpack-go"
)

var (
	device      string = "lo0"
	snaplen     int32  = 1024
	promiscuous bool   = false
)

func main() {
	handle, err := pcap.OpenLive(device, snaplen, promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("tcp and port 24224"); err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		handlePacket(packet)
	}
}

func handlePacket(packet gopacket.Packet) {
	if app := packet.ApplicationLayer(); app != nil {
		fmt.Println("Application layer/Payload found.")
		v, _, _ := msgpack.Unpack(bytes.NewReader(app.Payload()))
		fmt.Printf("%s\n", v)
	}
}
