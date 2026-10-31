package main

import (
	"encoding/hex"
	"github.com/metacubex/jls-quic-go/internal/protocol"
	"github.com/metacubex/jls-quic-go/internal/wire"
	"testing"
)

func TestControlledVersionInformation(t *testing.T) {
	cases := []struct {
		body  string
		valid bool
	}{
		{"11086b3343cf6b3343cf", true},
		{"1108000000006b3343cf", false},
		{"11086b3343cf00000000", false},
		{"11086b3343cf00000001", false},
		{"11076b3343cf6b3343", false},
		{"11086b3343cf6b3343cf11086b3343cf6b3343cf", false},
	}
	for _, c := range cases {
		data, err := hex.DecodeString("0f00" + c.body)
		if err != nil {
			t.Fatal(err)
		}
		var p wire.TransportParameters
		err = p.Unmarshal(data, protocol.PerspectiveClient)
		if (err == nil) != c.valid {
			t.Fatalf("传输参数有效性不符：%s: %v", c.body, err)
		}
	}
}
