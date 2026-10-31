package handshake

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"github.com/metacubex/jls-quic-go/internal/protocol"
	"testing"
)

// RFC9001/RFC9369 附录 A.5；直接验证库正在使用的密钥更新函数。
func TestControlledKeyUpdateVectors(t *testing.T) {
	secret, _ := hex.DecodeString("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
	cases := []struct {
		name     string
		version  protocol.Version
		expected string
	}{
		{"v1", protocol.Version1, "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"},
		{"v2", protocol.Version2, "c69374c49e3d2a9466fa689e49d476db5d0dfbc87d32ceeaa6343fd0ae4c7d88"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			expected, _ := hex.DecodeString(c.expected)
			a := &updatableAEAD{version: c.version}
			actual := a.getNextTrafficSecret(crypto.SHA256, secret)
			if !bytes.Equal(actual, expected) {
				t.Fatalf("固定密钥更新向量不符：%x", actual)
			}
		})
	}
}
