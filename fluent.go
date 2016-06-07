package sniffer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/ugorji/go/codec"
)

var mh = &codec.MsgpackHandle{RawToString: true}

func init() {
	mh.MapType = reflect.TypeOf(map[string]interface{}(nil))
}

func Decode(payload []byte) {
	r := bytes.NewReader(payload)
	d := codec.NewDecoder(r, mh)

	message := []interface{}{nil, nil, nil}
	if err := d.Decode(&message); err != nil {
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
	case []byte:
		decodePackedForward(tag, entries)
	case []interface{}:
		decodeForward(tag, entries)
	default:
		decodeMessage(tag, message[1:])
	}
}

func decodePackedForward(tag string, entries interface{}) {
	rawEntries, ok := entries.([]byte)
	if !ok {
		fmt.Println("Failed to decode entries")
		return
	}

	r := bytes.NewReader(rawEntries)
	d := codec.NewDecoder(r, mh)

	for r.Len() > 0 {
		e := []interface{}{}
		if err := d.Decode(&e); err != nil {
			if err == io.EOF {
				break
			}
			return
		}
		decodeForward(tag, e)
	}
}

func decodeForward(tag string, entries interface{}) {
	es, ok := entries.([]interface{})
	if !ok {
		fmt.Println("Failed to decode entries")
		return
	}
	for _, e := range es {
		decodeMessage(tag, e)
	}
}

func decodeMessage(tag string, entry interface{}) {
	e, ok := entry.([]interface{})
	if !ok || len(e) != 2 {
		fmt.Println("Failed to decode entry")
		return
	}
	timestamp, ok := e[0].(uint64)
	if !ok {
		fmt.Println("Failed to decode timestamp")
		return
	}
	record, ok := e[1].(map[string]interface{})
	if !ok {
		fmt.Println("Failed to decode record")
		return
	}
	printJSON(tag, timestamp, record)
}

func printJSON(tag string, timestamp uint64, record map[string]interface{}) {
	r, err := json.Marshal(record)
	if err != nil {
		fmt.Println(err)
		return
	}

	t := time.Unix(int64(timestamp), 0).Format("2006-01-02 15:04:05 -0700")

	fmt.Printf("%s %s: %s\n", t, tag, r)
}
