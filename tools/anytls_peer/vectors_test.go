package session

// Prints the byte vectors that protocols/anytls/shared/src/vectors.rs carries. It is a white-box
// test of mihomo 1.19.33's transport/anytls/session: copy this file into that directory of a
// mihomo-v1.19.33 tree and run
//
//	go test -count=1 -run TestKerlicoVectors -v ./transport/anytls/session/

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/transport/anytls/padding"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

type recordConn struct {
	net.Conn
	writes [][]byte
}

func (c *recordConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

func (c *recordConn) SetWriteDeadline(time.Time) error { return nil }
func (c *recordConn) SetDeadline(time.Time) error      { return nil }

func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7) + seed
	}
	return b
}

func dump(name string, writes [][]byte) {
	for i, w := range writes {
		if len(w) <= 2048 {
			fmt.Printf("%s %d %d %s\n", name, i, len(w), hex.EncodeToString(w))
		} else {
			sum := sha256.Sum256(w)
			fmt.Printf("%s %d %d sha256=%s\n", name, i, len(w), hex.EncodeToString(sum[:]))
		}
	}
}

const vectorScheme = "stop=6\n0=30-30\n1=120-120\n2=40-40,c,60-60,c,70-70\n3=9-9,50-50\n4=20-20,c,30-30\n5=300-300"

func TestKerlicoVectors(t *testing.T) {
	fmt.Printf("DEFAULT_MD5 %x\n", md5.Sum(padding.DefaultPaddingScheme))
	fmt.Printf("VECTOR_MD5 %x\n", md5.Sum([]byte(vectorScheme)))

	// The client's first TLS record (transport/anytls/client.go), with the vector scheme's 30.
	pw := sha256.Sum256([]byte("secret"))
	auth := append([]byte(nil), pw[:]...)
	auth = binary.BigEndian.AppendUint16(auth, 30)
	auth = append(auth, make([]byte, 30)...)
	fmt.Printf("AUTH %s\n", hex.EncodeToString(auth))

	var p atomic.Pointer[padding.PaddingFactory]
	if !padding.UpdatePaddingScheme([]byte(vectorScheme), &p) {
		t.Fatal("scheme")
	}
	c := &recordConn{}
	s := NewClientSession(c, &p, "kerlico-test")
	// Run() with the settings in a fixed order; Go's map order is random.
	f := newFrame(cmdSettings, 0)
	f.data = []byte("v=2\nclient=kerlico-test\npadding-md5=" + p.Load().Md5)
	s.buffering = true
	s.writeControlFrame(f)
	st, err := s.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	M.SocksaddrSerializer.WriteAddrPort(st, M.ParseSocksaddrHostPort("example.com", 443)) // pkt 1
	st.Write(pattern(50, 1))    // pkt 2: 40 payload, then 10 + waste to 60, check stops
	st.Write(pattern(200, 2))   // pkt 3: 9, then 50, then the rest
	st.Write(pattern(5, 3))     // pkt 4: 5 + waste to 20, check stops
	st.Write(nil)               // writeDataFrame returns early: no packet
	st2, _ := s.OpenStream()    // pkt 5: SYN 2 padded to 300
	st2.Write(pattern(70000, 4)) // pkt 6 >= stop: two PSH frames in one write
	st.Close()                   // FIN 1
	dump("CLIENT", c.writes)

	// An all-padding packet: the payload is used up before the list ends.
	c2 := &recordConn{}
	s2 := NewClientSession(c2, &p, "")
	s2.pktCounter.Store(3) // next packet is 4: 20-20,c,30-30
	s2.writeConn([]byte{})
	s3 := NewClientSession(c2, &p, "")
	s3.pktCounter.Store(2) // next packet is 3: 9-9,50-50 with 4 bytes: 4 + waste would be -3 -> raw 4, then 57-byte waste
	s3.writeConn([]byte{1, 2, 3, 4})
	dump("PADONLY", c2.writes)

	// Server sessions never pad.
	c3 := &recordConn{}
	sv := NewServerSession(c3, nil, &p)
	sv.writeControlFrame(newFrame(cmdSYNACK, 7))
	sv.writeDataFrame(7, pattern(3, 5))
	fsv := newFrame(cmdServerSettings, 0)
	fsv.data = []byte("v=2")
	sv.writeControlFrame(fsv)
	dump("SERVER", c3.writes)

	addrs := []M.Socksaddr{
		M.ParseSocksaddrHostPort("1.2.3.4", 80),
		M.ParseSocksaddrHostPort("2001:db8::1", 8080),
		M.ParseSocksaddrHostPort("example.com", 443),
		uot.RequestDestination(2),
		uot.RequestDestination(1),
	}
	for _, a := range addrs {
		b := buf.New()
		M.SocksaddrSerializer.WriteAddrPort(b, a)
		u := buf.New()
		uot.AddrParser.WriteAddrPort(u, a)
		fmt.Printf("ADDR %s socks=%s uot=%s\n", a.String(), hex.EncodeToString(b.Bytes()), hex.EncodeToString(u.Bytes()))
	}
	req, _ := uot.EncodeRequest(uot.Request{Destination: M.ParseSocksaddrHostPort("1.2.3.4", 53)})
	fmt.Printf("UOT_REQUEST %s\n", hex.EncodeToString(req.Bytes()))
	req2, _ := uot.EncodeRequest(uot.Request{IsConnect: true, Destination: M.ParseSocksaddrHostPort("example.com", 53)})
	fmt.Printf("UOT_REQUEST_CONNECT %s\n", hex.EncodeToString(req2.Bytes()))
	c4 := &recordConn{}
	lazy := uot.NewLazyConn(c4, uot.Request{Destination: M.ParseSocksaddrHostPort("1.2.3.4", 53)})
	lazy.WriteTo([]byte("dns?"), M.ParseSocksaddrHostPort("1.2.3.4", 53).UDPAddr())
	lazy.WriteTo([]byte("v6"), M.ParseSocksaddrHostPort("2001:db8::1", 5353).UDPAddr())
	dump("UOT_LAZY", c4.writes)
}
