package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/ugorji/go/codec"
)

var mh = &codec.MsgpackHandle{RawToString: true}

type Record map[string]interface{}

func init() {
	mh.MapType = reflect.TypeOf(Record(nil))
}

func main() {
	handle, err := pcap.OpenLive("lo0", 1024, false, pcap.BlockForever)
	if err != nil {
		panic(err)
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
	app := packet.ApplicationLayer()
	if app == nil {
		return
	}

	payload := bytes.NewReader(app.Payload())
	decoder := codec.NewDecoder(payload, mh)

	message := []interface{}{nil, nil, nil}
	if err := decoder.Decode(&message); err != nil {
		fmt.Println("Incoming chunk is broken")
		return
	}

	tag, ok := message[0].(string)
	if !ok {
		fmt.Println("Failed to decode tag")
		return
	}

	entries := message[1]
	switch entries.(type) {
	case []byte: // PackedForward
		rawEntries, ok := entries.([]byte)
		if !ok {
			fmt.Println("Failed to decode entries")
			return
		}

		reader := bytes.NewReader(rawEntries)
		decoder := codec.NewDecoder(reader, mh)

		for reader.Len() > 0 {
			entries := []interface{}{}
			if err := decoder.Decode(&entries); err != nil {
				if err == io.EOF {
					break
				}
				return
			}
			printEntries(tag, entries)
		}
	case []interface{}: // Forward
		entries, ok := entries.([]interface{})
		if !ok {
			fmt.Println("Failed to decode entries")
			return
		}

		printEntries(tag, entries)
	default: // Message
		timestamp, ok := message[1].(uint64)
		if !ok {
			fmt.Println("Failed to decode timestamp")
			return
		}

		record, ok := message[2].(Record)
		if !ok {
			fmt.Println("Failed to decode record")
			return
		}

		printJson(tag, timestamp, record)
	}
}

func printEntries(tag string, entries []interface{}) {
	for _, entry := range entries {
		entry, ok := entry.([]interface{})
		if !ok || len(entry) != 2 {
			fmt.Println("Failed to decode entry")
			return
		}

		timestamp, ok := entry[0].(uint64)
		if !ok {
			fmt.Println("Failed to decode timestamp")
			return
		}

		record, ok := entry[1].(Record)
		if !ok {
			fmt.Println("Failed to decode record")
			return
		}

		printJson(tag, timestamp, record)
	}
}

func printJson(tag string, timestamp uint64, record Record) {
	jsonRecord, err := json.Marshal(record)
	if err != nil {
		fmt.Println(err)
		return
	}

	t := time.Unix(int64(timestamp), 0)
	t.Format("2006-01-02 15:04:06 -0700")

	fmt.Printf("%s %s: %s\n", t, tag, jsonRecord)
}
