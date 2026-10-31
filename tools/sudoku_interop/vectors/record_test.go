// 只在同包测试内设置确定epoch/seq，实际帧由原RecordConn.Write生成。
package crypto

import (
    "bytes"
    "encoding/hex"
    "encoding/json"
    "io"
    "net"
    "os"
    "path/filepath"
    "sync/atomic"
    "testing"
    "time"
)

type kerlicoMemory struct {bytes.Buffer}
func (*kerlicoMemory) Close() error{return nil}
func (*kerlicoMemory) LocalAddr() net.Addr{return nil}
func (*kerlicoMemory) RemoteAddr() net.Addr{return nil}
func (*kerlicoMemory) SetDeadline(time.Time) error{return nil}
func (*kerlicoMemory) SetReadDeadline(time.Time) error{return nil}
func (*kerlicoMemory) SetWriteDeadline(time.Time) error{return nil}

func kerlicoFrame(t *testing.T,method string,base []byte,epoch uint32,sequence uint64,payload []byte) []byte {
    t.Helper();memory:=&kerlicoMemory{};writer,err:=NewRecordConn(memory,method,base,base);if err!=nil {t.Fatal(err)}
    writer.sendEpoch=epoch;writer.sendSeq=sequence
    if _,err:=writer.Write(payload);err!=nil {t.Fatal(err)}
    return append([]byte(nil),memory.Bytes()...)
}
func TestKerlicoExportRecordVectors(t *testing.T) {
    previous:=atomic.SwapInt64(&KeyUpdateAfterBytes,32);defer atomic.StoreInt64(&KeyUpdateAfterBytes,previous)
    base:=bytes.Repeat([]byte{0x37},32);output:=[]map[string]any{}
    for _,method:=range []string{"aes-128-gcm","chacha20-poly1305"} {
        frames:=[]map[string]any{}
        for _,position:=range []struct{epoch uint32;seq uint64;size int}{{7,11,17},{7,12,17},{8,31,65507},{16,41,33}} {
            payload:=bytes.Repeat([]byte{0xab},position.size);frame:=kerlicoFrame(t,method,base,position.epoch,position.seq,payload)
            memory:=&kerlicoMemory{};memory.Write(frame);reader,err:=NewRecordConn(memory,method,base,base);if err!=nil {t.Fatal(err)}
            got:=make([]byte,len(payload));if _,err:=io.ReadFull(reader,got);err!=nil||!bytes.Equal(got,payload){t.Fatalf("记录自检: %v",err)}
            frames=append(frames,map[string]any{"epoch":position.epoch,"sequence":position.seq,"plain_hex":hex.EncodeToString(payload),"wire_hex":hex.EncodeToString(frame),"epoch_key_hex":hex.EncodeToString(deriveEpochKey(base,position.epoch,method))})
        }
        memory:=&kerlicoMemory{};writer,err:=NewRecordConn(memory,method,base,base);if err!=nil {t.Fatal(err)};writer.sendEpoch=7;writer.sendSeq=11
        if _,err:=writer.Write(make([]byte,17));err!=nil {t.Fatal(err)};if _,err:=writer.Write(make([]byte,17));err!=nil {t.Fatal(err)}
        if writer.sendEpoch!=8||writer.sendEpochUpdates!=1 {t.Fatal("32字节重钥边界不符")}
        jump:=kerlicoFrame(t,method,base,16,51,[]byte("jump-nine"))
        bad:=append([]byte(nil),jump...);bad[len(bad)-1]^=1
        position:=&RecordConn{recvInitialized:true,recvEpoch:7,recvSeq:12}
        if position.validateRecvPosition(15,51)!=nil||position.validateRecvPosition(16,51)==nil||position.validateRecvPosition(7,11)==nil {t.Fatal("原生epoch/sequence控制不符")}
        damaged:=&kerlicoMemory{};damaged.Write(bad);badReader,err:=NewRecordConn(damaged,method,base,base);if err!=nil {t.Fatal(err)}
        if _,err:=badReader.Read(make([]byte,64));err==nil {t.Fatal("原生坏MAC未拒绝")}
        output=append(output,map[string]any{"method":method,"base_hex":hex.EncodeToString(base),"frames":frames,"jump_nine_wire_hex":hex.EncodeToString(jump),"bad_mac_wire_hex":hex.EncodeToString(bad),"native_threshold_rekey":true,"native_epoch_sequence_and_mac_controls":true})
    }
    directory:=os.Getenv("KERLICO_VECTOR_OUT");if directory=="" {t.Fatal("须设置KERLICO_VECTOR_OUT")};data,err:=json.MarshalIndent(output,"","  ");if err!=nil {t.Fatal(err)}
    if err:=os.WriteFile(filepath.Join(directory,"records.json"),append(data,'\n'),0600);err!=nil {t.Fatal(err)}
}
