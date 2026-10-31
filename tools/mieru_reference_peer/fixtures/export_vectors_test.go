package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
	"os"
	"testing"
	"time"
)

// 固定时间/nonce 的独立向量。复用官方 Marshal 和低熵 codec，不修改上游运行代码。
func TestKerlicoMieruExportVectors(t *testing.T) {
	path := os.Getenv("KERLICO_MIERU_VECTOR_OUTPUT")
	if path == "" {
		t.Fatal("未指定固定向量输出位置")
	}
	const seconds int64 = 1700000040
	user, password := "node-user", "synthetic-password"
	secret := cipher.HashPassword([]byte(password), []byte(user))
	bucket := time.Unix(seconds, 0).Round(cipher.KeyRefreshInterval).Unix()
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(bucket))
	salt := sha256.Sum256(timestamp[:])
	key := pbkdf2.Key(secret, salt[:], cipher.KeyIter, 32, sha256.New)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 24)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	input := append([]byte(user), nonce[:16]...)
	h := sha256.Sum256(input)
	copy(nonce[20:], h[:4])
	if !cipher.CheckUserFromHint([]byte(user), nonce) {
		t.Fatal("官方 hint 校验不符")
	}
	frames := []map[string]any{}
	entropyVectors := []map[string]any{}
	lengths := []map[string]any{}
	add := func(meta metadata, body []byte, mode int, rotation int, half uint32, prefix, suffix int) {
		plain := meta.Marshal()
		binary.BigEndian.PutUint32(plain[2:6], uint32(seconds/60))
		for _, transport := range []string{"tcp", "udp"} {
			wire := append([]byte{}, nonce...)
			wire = append(wire, aead.Seal(nil, nonce, plain, nil)...)
			wire = append(wire, bytes.Repeat([]byte{'a'}, prefix)...)
			if len(body) > 0 {
				n := append([]byte{}, nonce...)
				if transport == "tcp" {
					for i := len(n) - 1; i >= 0; i-- {
						n[i]++
						if n[i] != 0 {
							break
						}
					}
				}
				encrypted := aead.Seal(nil, n, body, nil)
				if mode > 0 {
					tag := encrypted[len(body):]
					encoded, err := encodeLowEntropyPayloadWithPaddingBit(encrypted[:len(body)], pb.LowEntropyMode(mode), half, pb.LowEntropyMaskRotation(rotation), uint8(mode%2))
					if err != nil {
						t.Fatal(err)
					}
					encrypted = append(encoded, tag...)
				}
				wire = append(wire, encrypted...)
			}
			wire = append(wire, bytes.Repeat([]byte{'b'}, suffix)...)
			frames = append(frames, map[string]any{"transport": transport, "kind": plain[0], "unix_seconds": seconds, "epoch": bucket, "username": user, "password": password, "key_hex": hex.EncodeToString(key), "nonce_hex": hex.EncodeToString(nonce), "metadata_hex": hex.EncodeToString(plain), "payload_hex": hex.EncodeToString(body), "wire_hex": hex.EncodeToString(wire), "mode": mode, "rotation": rotation, "half_mask": half, "prefix": prefix, "suffix": suffix})
		}
	}
	for kind := 2; kind <= 5; kind++ {
		body := []byte{}
		if kind == 2 {
			body = []byte("synthetic-open")
		}
		seq := uint32(0)
		if kind >= 4 {
			seq = 7
		}
		s := &sessionStruct{baseStruct: baseStruct{protocol: uint8(kind)}, sessionID: 0x10203040, seq: seq, payloadLen: uint16(len(body)), suffixLen: 13}
		add(s, body, 0, 0, 0, 0, 13)
	}
	for kind := 6; kind <= 9; kind++ {
		body := []byte{}
		if kind <= 7 {
			body = bytes.Repeat([]byte{0x37}, 37)
		}
		m := &dataAckStruct{baseStruct: baseStruct{protocol: uint8(kind)}, sessionID: 0x10203040, seq: 7, unAckSeq: 11, windowSize: 128, fragment: 3, prefixLen: 9, payloadLen: uint16(len(body)), suffixLen: 7}
		add(m, body, 0, 0, 0, 9, 7)
	}
	halves := []uint32{0, 0x0f0f0f0f, 0x1f1f1f1f, 0x3f3f3f3f, 0x7f7f7f7f}
	for mode := 1; mode <= 4; mode++ {
		for _, rotation := range []int{0, 7, 48} {
			for _, kind := range []int{10, 11} {
				body := bytes.Repeat([]byte{0x52}, 37)
				encodedLen, err := lowEntropyEncodedPayloadLen(len(body), pb.LowEntropyMode(mode))
				if err != nil {
					t.Fatal(err)
				}
				m := &dataAckStruct{baseStruct: baseStruct{protocol: uint8(kind)}, sessionID: 0x10203040, seq: 7, unAckSeq: 11, windowSize: 128, fragment: 3, prefixLen: 9, payloadLen: encodedLen, suffixLen: 7, lowEntropyMode: uint8(mode), lowEntropyMask: halves[mode], extractedPayloadLen: uint16(len(body)), lowEntropyMaskRotation: uint8(rotation)}
				add(m, body, mode, rotation, halves[mode], 9, 7)
			}
			for _, polarity := range []uint8{0, 1} {
				for _, length := range []int{1, mode + 2, mode + 3, mode + 4} {
					src := make([]byte, length)
					for i := range src {
						src[i] = byte(i*7 + 3)
					}
					encoded, err := encodeLowEntropyPayloadWithPaddingBit(src, pb.LowEntropyMode(mode), halves[mode], pb.LowEntropyMaskRotation(rotation), polarity)
					if err != nil {
						t.Fatal(err)
					}
					entropyVectors = append(entropyVectors, map[string]any{"mode": mode, "rotation": rotation, "half_mask": halves[mode], "polarity": polarity, "source_hex": hex.EncodeToString(src), "encoded_hex": hex.EncodeToString(encoded)})
				}
			}
		}
		for _, length := range []int{32764, 32768} {
			n, err := lowEntropyEncodedPayloadLen(length, pb.LowEntropyMode(mode))
			lengths = append(lengths, map[string]any{"mode": mode, "raw": length, "encoded": n, "valid": err == nil})
		}
	}
	result := map[string]any{"frames": frames, "entropy": entropyVectors, "lengths": lengths, "source": "official-" + os.Getenv("KERLICO_MIERU_SOURCE_VERSION") + "-protocol-Marshal-and-codec-with-fixed-time"}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
