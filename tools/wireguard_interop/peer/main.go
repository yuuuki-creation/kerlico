package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type target struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}
func (t target) address() (netip.AddrPort, error) {
	ip, err := netip.ParseAddr(t.Host)
	if err != nil || t.Port == 0 { return netip.AddrPort{}, errors.New("验证目标必须为字面IP与非零端口") }
	return netip.AddrPortFrom(ip, t.Port), nil
}
type echoTarget struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
	Protocol string `json:"protocol"`
}
type config struct {
	PrivateKey string `json:"private_key"`
	PublicKey string `json:"public_key"`
	PresharedKey string `json:"preshared_key"`
	Endpoint string `json:"endpoint"`
	ListenPort uint16 `json:"listen_port"`
	Addresses []string `json:"addresses"`
	AllowedIPs []string `json:"allowed_ips"`
	Keepalive uint16 `json:"persistent_keepalive"`
	Echo []echoTarget `json:"echo"`
}
type packet struct {
	Target target `json:"target"`
	Payload string `json:"payload"`
}
type request struct {
	Op string `json:"op"`
	Target target `json:"target"`
	Payload string `json:"payload"`
	Payloads []string `json:"payloads"`
	Packets []packet `json:"packets"`
	ExtraReceives int `json:"extra_receives"`
}
func emit(value any) { _ = json.NewEncoder(os.Stdout).Encode(value) }
func key(value string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(data) != 32 { return "", errors.New("验证密钥格式不合法") }
	return hex.EncodeToString(data), nil
}
func decode(value string) ([]byte, error) {
	if len(value) > 24 * 1024 * 1024 { return nil, errors.New("验证载荷超过边界") }
	return base64.StdEncoding.DecodeString(value)
}
func settings(c config) (string, error) {
	private, err := key(c.PrivateKey); if err != nil { return "", err }
	public, err := key(c.PublicKey); if err != nil { return "", err }
	var out strings.Builder
	fmt.Fprintf(&out, "private_key=%s\nlisten_port=%d\npublic_key=%s\nreplace_allowed_ips=true\n", private, c.ListenPort, public)
	if c.PresharedKey != "" { psk, err := key(c.PresharedKey); if err != nil { return "", err }; fmt.Fprintf(&out, "preshared_key=%s\n", psk) }
	if c.Endpoint != "" { if _, err := netip.ParseAddrPort(c.Endpoint); err != nil { return "", err }; fmt.Fprintf(&out, "endpoint=%s\n", c.Endpoint) }
	fmt.Fprintf(&out, "persistent_keepalive_interval=%d\n", c.Keepalive)
	for _, prefix := range c.AllowedIPs { if _, err := netip.ParsePrefix(prefix); err != nil { return "", err }; fmt.Fprintf(&out, "allowed_ip=%s\n", prefix) }
	return out.String(), nil
}
func snapshot(dev *device.Device) map[string]any {
	result := map[string]any{"ok": true}
	text, err := dev.IpcGet(); if err != nil { return map[string]any{"ok": false, "error": "官方peer查询失败"} }
	for _, line := range strings.Split(text, "\n") {
		name, value, ok := strings.Cut(line, "="); if !ok { continue }
		switch name {
		case "listen_port", "last_handshake_time_sec", "last_handshake_time_nsec", "tx_bytes", "rx_bytes":
			parsed, err := strconv.ParseUint(value, 10, 64); if err == nil { result[name] = parsed }
		}
	}
	return result
}
func echo(tnet *netstack.Net, targets []echoTarget) ([]io.Closer, error) {
	var resources []io.Closer
	for _, item := range targets {
		address, err := (target{item.Host, item.Port}).address(); if err != nil { return resources, err }
		switch item.Protocol {
		case "tcp":
			listener, err := tnet.ListenTCPAddrPort(address); if err != nil { return resources, err }
			resources = append(resources, listener)
			go func(port uint16) {
				for { stream, err := listener.Accept(); if err != nil { return }; go func() {
					defer stream.Close(); _ = stream.SetDeadline(time.Now().Add(20 * time.Second))
					data, err := io.ReadAll(io.LimitReader(stream, 16 * 1024 * 1024)); if err != nil { return }
					prefix := make([]byte, 2); binary.BigEndian.PutUint16(prefix, port)
					_, _ = io.Copy(stream, bytes.NewReader(append(prefix, data...)))
				}() }
			}(item.Port)
		case "udp":
			socket, err := tnet.ListenUDPAddrPort(address); if err != nil { return resources, err }
			resources = append(resources, socket)
			go func() { data := make([]byte, 65535); for {
				size, source, err := socket.ReadFrom(data); if err != nil { return }; _, _ = socket.WriteTo(data[:size], source)
				if string(data[:size]) == "fullcone" { other, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(address.Addr(), 0)); if err == nil { _, _ = other.WriteTo([]byte("unsolicited"), source); _ = other.Close() } }
			} }()
		default: return resources, errors.New("验证回显协议不合法")
		}
	}
	return resources, nil
}
func local(addresses []netip.Addr, ipv4 bool) (netip.AddrPort, error) {
	for _, ip := range addresses { if ip.Is4() == ipv4 { return netip.AddrPortFrom(ip, 0), nil } }
	return netip.AddrPort{}, errors.New("验证peer未配置目标地址族")
}
func business(tnet *netstack.Net, addresses []netip.Addr, req request) (any, error) {
	switch req.Op {
	case "tcp":
		address, err := req.Target.address(); if err != nil { return nil, err }
		ctx, cancel := context.WithTimeout(context.Background(), 15 * time.Second); defer cancel()
		stream, err := tnet.DialContextTCPAddrPort(ctx, address); if err != nil { return nil, err }; defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(20 * time.Second))
		data, err := decode(req.Payload); if err != nil { return nil, err }
		if _, err = io.Copy(stream, bytes.NewReader(data)); err != nil { return nil, err }
		if err = stream.CloseWrite(); err != nil { return nil, err }
		data, err = io.ReadAll(io.LimitReader(stream, 16 * 1024 * 1024)); if err != nil { return nil, err }
		return map[string]any{"ok":true,"payload":base64.StdEncoding.EncodeToString(data)}, nil
	case "fixed_udp", "association_udp":
		packets := req.Packets
		if req.Op == "fixed_udp" { for _, payload := range req.Payloads { packets = append(packets, packet{req.Target, payload}) } }
		var v4, v6 net.PacketConn
		defer func() { if v4 != nil { _ = v4.Close() }; if v6 != nil { _ = v6.Close() } }()
		var replies []any
		var last net.PacketConn
		for _, item := range packets {
			address, err := item.Target.address(); if err != nil { return nil, err }
			slot := &v6; if address.Addr().Is4() { slot = &v4 }
			if *slot == nil { local, err := local(addresses, address.Addr().Is4()); if err != nil { return nil, err }; socket, err := tnet.ListenUDPAddrPort(local); if err != nil { return nil, err }; *slot = socket }
			last = *slot
			data, err := decode(item.Payload); if err != nil { return nil, err }
			_ = (*slot).SetDeadline(time.Now().Add(5 * time.Second))
			size, err := (*slot).WriteTo(data, net.UDPAddrFromAddrPort(address)); if err != nil || size != len(data) { return nil, errors.New("官方peer未发送完整数据报") }
			buffer := make([]byte, 65535); size, source, err := (*slot).ReadFrom(buffer); if err != nil { return nil, err }
			replies = append(replies, map[string]any{"source":source.String(),"payload":base64.StdEncoding.EncodeToString(buffer[:size])})
		}
		for count := 0; count < req.ExtraReceives && count < 8 && last != nil; count++ {
			buffer := make([]byte, 65535); size, source, err := last.ReadFrom(buffer); if err != nil { return nil, err }
			replies = append(replies, map[string]any{"source":source.String(),"payload":base64.StdEncoding.EncodeToString(buffer[:size])})
		}
		return map[string]any{"ok":true,"packets":replies}, nil
	default: return nil, errors.New("未知验证操作")
	}
}
func run(path string) error {
	file, err := os.Open(path); if err != nil { return errors.New("验证配置不可读") }; defer file.Close()
	var c config
	decoder := json.NewDecoder(file); decoder.DisallowUnknownFields(); if err = decoder.Decode(&c); err != nil { return errors.New("验证配置不合法") }
	var addresses []netip.Addr
	for _, text := range c.Addresses { ip, err := netip.ParseAddr(text); if err != nil { return err }; addresses = append(addresses, ip) }
	tun, tnet, err := netstack.CreateNetTUN(addresses, nil, 1280); if err != nil { return err }
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "")); defer dev.Close()
	ipc, err := settings(c); if err != nil { return err }
	if err = dev.IpcSet(ipc); err != nil { return errors.New("官方peer拒绝配置") }
	if err = dev.Up(); err != nil { return errors.New("官方peer载体启动失败") }
	resources, err := echo(tnet, c.Echo); if err != nil { return err }
	defer func() { for _, resource := range resources { _ = resource.Close() } }()
	ready := snapshot(dev); ready["ready"] = true; emit(ready)
	scanner := bufio.NewScanner(os.Stdin); scanner.Buffer(make([]byte, 4096), 32 * 1024 * 1024)
	for scanner.Scan() {
		var req request; if err := json.Unmarshal(scanner.Bytes(), &req); err != nil { emit(map[string]any{"ok":false,"error":"验证请求不合法"}); continue }
		if req.Op == "stop" { emit(map[string]any{"stopped":true,"clean":true}); return nil }
		if req.Op == "snapshot" { emit(snapshot(dev)); continue }
		result, err := business(tnet, addresses, req); if err != nil { emit(map[string]any{"ok":false,"error":"官方peer业务失败"}) } else { emit(result) }
	}
	return scanner.Err()
}
func main() {
	if len(os.Args) == 2 && os.Args[1] == "keygen" {
		data := make([]byte, 32); if _, err := rand.Read(data); err != nil { os.Exit(1) }
		private, err := ecdh.X25519().NewPrivateKey(data); if err != nil { os.Exit(1) }
		emit(map[string]any{"private_key":base64.StdEncoding.EncodeToString(data),"public_key":base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())}); return
	}
	if len(os.Args) != 2 { fmt.Fprintln(os.Stderr, "用法为wireguard-go-peer 配置文件，或keygen"); os.Exit(2) }
	if err := run(os.Args[1]); err != nil { fmt.Fprintln(os.Stderr, "官方验证peer运行失败"); os.Exit(1) }
}
