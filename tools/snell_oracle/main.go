// 仅在 worker 生成固定对端的合成测试向量，不参与内核或业务转发。
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv6"
	"os"
	"reflect"
)

func main() {
	path := flag.String("output", "", "私有结果文件")
	flag.Parse()
	if *path == "" {
		panic("缺少私有结果文件")
	}
	rows := make([]map[string]any, 0, 64)
	for index := range 64 {
		psk := fmt.Sprintf("snell-profile-test-key-%d", index)
		profile := reflect.ValueOf(snellv6.NewProfile([]byte(psk))).Elem()
		values := make(map[string]any)
		for i := range profile.NumField() {
			name := profile.Type().Field(i).Name
			value := profile.Field(i)
			switch value.Kind() {
			case reflect.Int:
				values[name] = value.Int()
			case reflect.Uint32, reflect.Uint64:
				values[name] = value.Uint()
			case reflect.Array:
				array := make([]int64, value.Len())
				for n := range value.Len() {
					array[n] = value.Index(n).Int()
				}
				values[name] = array
			case reflect.Struct:
				ns := make(map[string]uint64)
				for n := range value.NumField() {
					ns[value.Type().Field(n).Name] = value.Field(n).Uint()
				}
				values[name] = ns
			}
		}
		salt := make([]byte, 16)
		for n := range salt {
			salt[n] = byte(n)
		}
		aead, err := snell.NewAEAD(snell.DeriveKey([]byte(psk), salt))
		if err != nil {
			panic("对端测试原语不可用")
		}
		sealed := aead.Seal(nil, make([]byte, 12), []byte("snell-reference-vector"), []byte("aad"))
		rows = append(rows, map[string]any{"psk": psk, "profile": values, "cipher": hex.EncodeToString(sealed)})
	}
	data, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		panic("向量序列化失败")
	}
	if os.WriteFile(*path, data, 0600) != nil {
		panic("向量写入失败")
	}
	fmt.Println("已生成 64 组固定 Snell 对端 profile 与加密向量")
}
