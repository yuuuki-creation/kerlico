// 只用合成数据核对官方 UDP 段内 nonce 复用；不连接网络或尝试伪造认证。
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	c "github.com/enfein/mieru/v3/pkg/cipher"
	"os"
)

func main() {
	password := c.HashPassword([]byte("synthetic-password"), []byte("node-user"))
	meta := make([]byte, 32)
	meta[0] = 6
	meta[9] = 1
	meta[13] = 1
	meta[19] = 16
	meta[23] = 32
	body := bytes.Repeat([]byte{0x43}, 32)
	udp, err := c.BlockCipherFromPassword(password, true)
	if err != nil {
		panic(err)
	}
	udp.SetBlockContext(c.BlockContext{UserName: "node-user"})
	encryptedMeta := make([]byte, 24+32+16)
	if err = udp.Encrypt(encryptedMeta[:0], meta); err != nil {
		panic(err)
	}
	nonce := encryptedMeta[:24]
	encryptedBody := make([]byte, len(body)+16)
	if err = udp.EncryptWithNonce(encryptedBody[:0], nonce, body); err != nil {
		panic(err)
	}
	recovered := make([]byte, 32)
	for i := range recovered {
		recovered[i] = meta[i] ^ encryptedMeta[24+i] ^ encryptedBody[i]
	}
	if !bytes.Equal(recovered, body) {
		panic("未复现官方 UDP 调用顺序的同 nonce 异或关系")
	}
	tcp, err := c.BlockCipherFromPassword(password, false)
	if err != nil {
		panic(err)
	}
	tcp.SetBlockContext(c.BlockContext{UserName: "node-user"})
	tcpMeta := make([]byte, 24+32+16)
	if err = tcp.Encrypt(tcpMeta[:0], meta); err != nil {
		panic(err)
	}
	tcpBody := make([]byte, len(body)+16)
	if err = tcp.Encrypt(tcpBody[:0], body); err != nil {
		panic(err)
	}
	different := make([]byte, 32)
	for i := range different {
		different[i] = meta[i] ^ tcpMeta[24+i] ^ tcpBody[i]
	}
	if bytes.Equal(different, body) {
		panic("TCP 递增 nonce 的控制组未区分")
	}
	version := "unrecorded"
	if len(os.Args) > 1 {
		version = os.Args[1]
	}
	result := map[string]any{"version": version, "udp_shared_nonce_xor_relation": true, "known_metadata_recovered_payload_bytes": 32, "tcp_implicit_nonce_breaks_relation": true, "network_used": false}
	data, _ := json.Marshal(result)
	fmt.Println(string(data))
}
