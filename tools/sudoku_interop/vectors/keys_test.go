// 仅在固定上游源码的隔离副本添加此导出桥接；不改生产算法，不连接网络。
package sudoku

import (
    "bytes"
    "crypto/ecdh"
    "encoding/hex"
    "encoding/json"
    "io"
    "os"
    "path/filepath"
    "testing"
    "time"
)

func TestKerlicoExportControlVectors(t *testing.T) {
    seed := "synthetic-sudoku-crypto-vector"
    private := bytes.Repeat([]byte{0x11},32)
    peer,err:=ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x22},32));if err!=nil {t.Fatal(err)}
    secret,err:=ecdh.X25519().NewPrivateKey(private);if err!=nil {t.Fatal(err)}
    shared,err:=x25519SharedSecret(secret,peer.PublicKey().Bytes());if err!=nil {t.Fatal(err)}
    var nonce [16]byte;for i:=range nonce {nonce[i]=byte(i+1)}
    initialC,initialS:=derivePSKDirectionalBases(seed)
    sessionC,sessionS,err:=deriveSessionDirectionalBases(seed,shared,nonce);if err!=nil {t.Fatal(err)}
    if bytes.Equal(initialC,initialS)||bytes.Equal(sessionC,sessionS)||bytes.Equal(initialC,sessionC){t.Fatal("原生双向密钥分离不符")}
    kdf:=map[string]any{"seed":seed,"client_private_hex":hex.EncodeToString(private),"server_public_hex":hex.EncodeToString(peer.PublicKey().Bytes()),"nonce_hex":hex.EncodeToString(nonce[:]),"shared_hex":hex.EncodeToString(shared),"initial_c2s_hex":hex.EncodeToString(initialC),"initial_s2c_hex":hex.EncodeToString(initialS),"session_c2s_hex":hex.EncodeToString(sessionC),"session_s2c_hex":hex.EncodeToString(sessionS)}
    var user [8]byte;copy(user[:],[]byte{1,2,3,4,5,6,7,8});var public [32]byte;copy(public[:],peer.PublicKey().Bytes())
    hello:=KIPClientHello{Timestamp:time.Unix(1000,0),UserHash:user,Nonce:nonce,ClientPub:public,Features:KIPFeatAll,TableHint:0x10203040,HasTableHint:true}
    server:=KIPServerHello{Nonce:nonce,ServerPub:public,SelectedFeats:KIPFeatAll}
    messages:=[]map[string]any{}
    for _,item:=range []struct{kind byte;payload []byte}{{KIPTypeClientHello,hello.EncodePayload()},{KIPTypeServerHello,server.EncodePayload()},{KIPTypeOpenTCP,[]byte{1,192,0,2,1,1,187}},{KIPTypeStartMux,nil},{KIPTypeStartUoT,nil},{KIPTypeKeepAlive,nil}} {
        var wire bytes.Buffer;if err:=WriteKIPMessage(&wire,item.kind,item.payload);err!=nil {t.Fatal(err)}
        decoded,err:=ReadKIPMessage(bytes.NewReader(wire.Bytes()));if err!=nil||decoded.Type!=item.kind||!bytes.Equal(decoded.Payload,item.payload){t.Fatalf("KIP自检: %v",err)}
        messages=append(messages,map[string]any{"kind":item.kind,"payload_hex":hex.EncodeToString(item.payload),"wire_hex":hex.EncodeToString(wire.Bytes())})
    }
    datagrams:=[]map[string]any{}
    for _,address:=range []string{"192.0.2.1:53","[2001:db8::1]:5353","target.invalid:853"} {
        for _,size:=range []int{0,17,65507} {
            payload:=bytes.Repeat([]byte{0x5a},size);var wire bytes.Buffer
            if err:=WriteDatagram(&wire,address,payload);err!=nil {t.Fatal(err)}
            addr,got,err:=NewUoTReader(bytes.NewReader(wire.Bytes())).ReadDatagram();if err!=nil||addr.String()!=address||!bytes.Equal(got,payload){t.Fatalf("UoT自检: %v",err)}
            datagrams=append(datagrams,map[string]any{"address":address,"size":size,"payload_hex":hex.EncodeToString(payload),"wire_hex":hex.EncodeToString(wire.Bytes())})
        }
    }
    // 固定参考允许65535；本项目普通IP包策略在65507处收紧，两者分别登记。
    var large bytes.Buffer;referenceLargeErr:=WriteDatagram(&large,"192.0.2.1:53",make([]byte,65508))
    _,_,truncatedErr:=NewUoTReader(bytes.NewReader([]byte{0,7,0,1,1})).ReadDatagram()
    if truncatedErr==nil||truncatedErr==io.EOF {t.Fatalf("截断自检: %v",truncatedErr)}
    output:=map[string]any{"kdf":kdf,"kip":messages,"uot":datagrams,"reference_uot_accepts_65508":referenceLargeErr==nil,"network_connections":0}
    data,err:=json.MarshalIndent(output,"","  ");if err!=nil {t.Fatal(err)}
    directory:=os.Getenv("KERLICO_VECTOR_OUT");if directory=="" {t.Fatal("须设置KERLICO_VECTOR_OUT")}
    if err:=os.WriteFile(filepath.Join(directory,"control.json"),append(data,'\n'),0600);err!=nil {t.Fatal(err)}
}
