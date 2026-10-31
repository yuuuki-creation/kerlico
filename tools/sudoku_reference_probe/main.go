// 仅使用合成材料研究固定参考实现，不进入Rust内核业务路径。
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/metacubex/mihomo/transport/sudoku"
	obfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

type memory struct { bytes.Buffer }
func (*memory) Close() error { return nil }
func (*memory) LocalAddr() net.Addr { return nil }
func (*memory) RemoteAddr() net.Addr { return nil }
func (*memory) SetDeadline(time.Time) error { return nil }
func (*memory) SetReadDeadline(time.Time) error { return nil }
func (*memory) SetWriteDeadline(time.Time) error { return nil }

func main() {
	private, public, err := sudoku.GenKeyPair()
	if err != nil { panic(err) }
	serverSeed := sudoku.ServerAEADSeed(public)
	if sudoku.ClientAEADSeed(private) != serverSeed || sudoku.ClientAEADSeed(public) != serverSeed { panic("参考种子规范化结果不符") }
	table := sudoku.NewTable(serverSeed, "prefer_ascii")
	identities := []map[string]any{}
	for _, method := range []string{"aes-128-gcm", "chacha20-poly1305"} {
		for _, material := range []struct{name, key string}{{"private-material",private},{"public-material-only",public}} {
			for index := byte(1); index <= 2; index++ {
				var selected [8]byte
				selected[7] = index
				clientCfg := sudoku.EarlyCodecConfig{PSK:sudoku.ClientAEADSeed(material.key),AEAD:method,EnablePureDownlink:true}
				state, err := sudoku.NewEarlyClientState(clientCfg,table,table.Hint(),true,selected,sudoku.KIPFeatAll)
				if err != nil { panic(err) }
				server, err := sudoku.ProcessEarlyClientPayload(sudoku.EarlyCodecConfig{PSK:serverSeed,AEAD:method,EnablePureDownlink:true},[]*obfs.Table{table},state.RequestPayload,nil)
				if err != nil { panic(err) }
				if server.UserHash != hex.EncodeToString(selected[:]) { panic("参考UserHash没有保留客户端所选值") }
				if err := state.ProcessResponse(server.ResponsePayload); err != nil { panic(err) }
				identities = append(identities,map[string]any{"method":method,"client_material":material.name,"chosen_user_hash":server.UserHash,"native_early_handshake":true})
			}
		}
		wrong := sudoku.EarlyCodecConfig{PSK:"synthetic-wrong-seed",AEAD:method,EnablePureDownlink:true}
		state, err := sudoku.NewEarlyClientState(wrong,table,table.Hint(),true,[8]byte{1},sudoku.KIPFeatAll)
		if err != nil { panic(err) }
		if _,err := sudoku.ProcessEarlyClientPayload(sudoku.EarlyCodecConfig{PSK:serverSeed,AEAD:method,EnablePureDownlink:true},[]*obfs.Table{table},state.RequestPayload,nil); err == nil { panic("错误AEAD种子没有被拒绝") }
		identities = append(identities,map[string]any{"method":method,"wrong_seed_rejected":true})
	}
	seedText := "synthetic-sudoku-wire-vector"
	seedHash := sha256.Sum256([]byte(seedText))
	seed := int64(binary.BigEndian.Uint64(seedHash[:8]))
	permutation := rand.New(rand.NewSource(seed)).Perm(288)
	// 实际table使用Shuffle；单独记录而非用Perm冒充其生成顺序。
	shuffle := make([]int,288)
	for i := range shuffle { shuffle[i]=i }
	rand.New(rand.NewSource(seed)).Shuffle(len(shuffle),func(i,j int){shuffle[i],shuffle[j]=shuffle[j],shuffle[i]})
	plain := make([]byte,256)
	for i := range plain { plain[i]=byte(i) }
	vectors := []map[string]any{}
	for _, mode := range []string{"prefer_ascii","prefer_entropy","up_ascii_down_entropy","up_entropy_down_ascii"} {
		for _, pattern := range []string{"","xpxvvpvv"} {
			t, err := obfs.NewTableWithCustom(seedText,mode,pattern)
			if err != nil { panic(err) }
			first := make([]byte,0,1024)
			for i:=0;i<256;i++ { if len(t.EncodeTable[i])==0 {panic("参考表没有编码")};first=append(first,t.EncodeTable[i][0][:]...) }
			pureRaw := &memory{}
			pure := obfs.NewConn(pureRaw,t,0,0,false)
			if _,err := pure.Write(plain);err!=nil {panic(err)}
			packedRaw := &memory{}
			packed := obfs.NewPackedConn(packedRaw,t,0,0)
			if _,err := packed.Write(plain);err!=nil {panic(err)}
			if err := packed.Flush();err!=nil {panic(err)}
			vectors=append(vectors,map[string]any{"mode":mode,"custom_pattern":pattern,"hint":t.Hint(),"first_puzzles_hex":hex.EncodeToString(first),"pure_hex":hex.EncodeToString(pureRaw.Bytes()),"packed_hex":hex.EncodeToString(packedRaw.Bytes())})
		}
	}
	result:=map[string]any{"fixed_commit":"3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8","identity_semantics":identities,"synthetic_vector_seed":seedText,"math_rand_seed":fmt.Sprint(seed),"perm":permutation,"shuffle":shuffle,"vectors":vectors,"network_connections":0}
	if err:=json.NewEncoder(os.Stdout).Encode(result);err!=nil {panic(err)}
}
