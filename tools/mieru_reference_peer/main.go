// 专用 worker 的独立官方 API 对端；只允许回环入口和目标，不供 Rust 内核调用。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	mc "github.com/enfein/mieru/v3/apis/client"
	common "github.com/enfein/mieru/v3/apis/common"
	model "github.com/enfein/mieru/v3/apis/model"
	ms "github.com/enfein/mieru/v3/apis/server"
	tp "github.com/enfein/mieru/v3/apis/trafficpattern"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"
)

type listener struct {
	Type      string            `json:"type"`
	Listen    string            `json:"listen"`
	Port      string            `json:"port"`
	Target    string            `json:"target"`
	Network   []string          `json:"network"`
	Transport string            `json:"transport"`
	Users     map[string]string `json:"users"`
	Pattern   string            `json:"traffic-pattern"`
	Hint      bool              `json:"user-hint-is-mandatory"`
}
type proxy struct {
	Server       string `json:"server"`
	Port         int    `json:"port"`
	Transport    string `json:"transport"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Multiplexing string `json:"multiplexing"`
	Handshake    string `json:"handshake-mode"`
	Pattern      string `json:"traffic-pattern"`
}
type config struct {
	Listeners []listener `json:"listeners"`
	Proxies   []proxy    `json:"proxies"`
}

func transport(value string) (pb.TransportProtocol, error) {
	switch value {
	case "TCP":
		return pb.TransportProtocol_TCP, nil
	case "UDP":
		return pb.TransportProtocol_UDP, nil
	}
	return 0, errors.New("参照载体不合法")
}
func local(address string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return nil, errors.New("参照端口不合法")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("参照入口必须是 IP 字面量回环地址")
	}
	return &net.UDPAddr{IP: ip, Port: int(p)}, nil
}
func target(address string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	return local(net.JoinHostPort(host, port))
}
func pattern(encoded string) (*pb.TrafficPattern, error) {
	if encoded == "" {
		return nil, nil
	}
	return tp.Decode(encoded)
}
func traffic(mode, rotation, padding int) *pb.TrafficPattern {
	return &pb.TrafficPattern{TcpFragment: &pb.TCPFragment{Enable: proto.Bool(false)}, Nonce: &pb.NoncePattern{Type: pb.NonceType_NONCE_TYPE_RANDOM.Enum()}, Padding: &pb.PaddingPattern{MaxMiddlePaddingLen: proto.Int32(int32(padding)), MaxEndPaddingLen: proto.Int32(int32(padding))}, LowEntropy: &pb.LowEntropyPattern{Mode: pb.LowEntropyMode(mode).Enum(), MaskRotation: pb.LowEntropyMaskRotation(rotation).Enum()}}
}
func bridge(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
	<-done
}

// 官方 UDPAssociateWrapper 对空负载可返回 io.EOF；这里直接保留原包边界，明确测试合法空包。
type packetTunnel struct {
	inner *common.PacketOverStreamTunnel
	write sync.Mutex
}

func (p *packetTunnel) read() ([]byte, *net.UDPAddr, error) {
	buf := make([]byte, 65535)
	n, err := p.inner.Read(buf)
	if err != nil {
		return nil, nil, err
	}
	buf = buf[:n]
	if len(buf) < 7 || !bytes.Equal(buf[:3], []byte{0, 0, 0}) {
		return nil, nil, errors.New("UDP 内层头不合法")
	}
	reader := bytes.NewReader(buf[3:])
	var a model.AddrSpec
	if err = a.ReadFromSocks5(reader); err != nil {
		return nil, nil, err
	}
	from, err := target(a.String())
	if err != nil {
		return nil, nil, err
	}
	body, err := io.ReadAll(reader)
	return body, from, err
}
func (p *packetTunnel) send(data []byte, addr *net.UDPAddr) error {
	var out bytes.Buffer
	out.Write([]byte{0, 0, 0})
	a := model.AddrSpec{IP: addr.IP, Port: addr.Port}
	if err := a.WriteToSocks5(&out); err != nil {
		return err
	}
	out.Write(data)
	p.write.Lock()
	defer p.write.Unlock()
	_, err := p.inner.Write(out.Bytes())
	return err
}
func serveUDP(conn net.Conn) {
	defer conn.Close()
	socket, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return
	}
	defer socket.Close()
	tunnel := &packetTunnel{inner: common.NewPacketOverStreamTunnel(conn)}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := socket.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !from.IP.IsLoopback() {
				continue
			}
			if err = tunnel.send(buf[:n], from); err != nil {
				return
			}
		}
	}()
	for {
		body, to, err := tunnel.read()
		if err != nil {
			return
		}
		if _, err = socket.WriteToUDP(body, to); err != nil {
			return
		}
	}
}
func startServer(l listener) (func(), error) {
	address := net.JoinHostPort(l.Listen, l.Port)
	addr, err := local(address)
	if err != nil {
		return nil, err
	}
	kind, err := transport(l.Transport)
	if err != nil {
		return nil, err
	}
	pat, err := pattern(l.Pattern)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(l.Users))
	for name := range l.Users {
		names = append(names, name)
	}
	sort.Strings(names)
	users := make([]*pb.User, 0, len(names))
	for _, name := range names {
		users = append(users, &pb.User{Name: proto.String(name), Password: proto.String(l.Users[name])})
	}
	server := ms.NewServer()
	err = server.Store(&ms.ServerConfig{Config: &pb.ServerConfig{ListenIPAddress: proto.String(l.Listen), PortBindings: []*pb.PortBinding{{Port: proto.Int32(int32(addr.Port)), Protocol: kind.Enum()}}, Users: users, TrafficPattern: pat, AdvancedSettings: &pb.ServerAdvancedSettings{UserHintIsMandatory: proto.Bool(l.Hint)}}})
	if err != nil {
		return nil, err
	}
	if err = server.Start(); err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, req, err := server.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn, req *model.Request) {
				if req.Command == 1 {
					dst, err := target(req.DstAddr.String())
					if err != nil {
						conn.Close()
						return
					}
					up, err := net.DialTimeout("tcp", dst.String(), 4*time.Second)
					if err != nil {
						conn.Close()
						return
					}
					resp := model.Response{Reply: 0, BindAddr: model.AddrSpec{IP: net.IPv4zero}}
					if err = resp.WriteToSocks5(conn); err != nil {
						conn.Close()
						up.Close()
						return
					}
					bridge(conn, up)
				} else if req.Command == 3 {
					resp := model.Response{Reply: 0, BindAddr: model.AddrSpec{IP: net.IPv4zero}}
					if err = resp.WriteToSocks5(conn); err != nil {
						conn.Close()
						return
					}
					serveUDP(conn)
				} else {
					conn.Close()
				}
			}(conn, req)
		}
	}()
	return func() { _ = server.Stop() }, nil
}
func startClient(c config) (func(), error) {
	if len(c.Proxies) != 1 {
		return nil, errors.New("参照需要一个出站")
	}
	p := c.Proxies[0]
	address := net.JoinHostPort(p.Server, strconv.Itoa(p.Port))
	if _, err := local(address); err != nil {
		return nil, err
	}
	kind, err := transport(p.Transport)
	if err != nil {
		return nil, err
	}
	pat, err := pattern(p.Pattern)
	if err != nil {
		return nil, err
	}
	level, ok := pb.MultiplexingLevel_value[p.Multiplexing]
	if !ok {
		return nil, errors.New("复用级别不合法")
	}
	handshake, ok := pb.HandshakeMode_value[p.Handshake]
	if !ok {
		return nil, errors.New("握手模式不合法")
	}
	client := mc.NewClient()
	err = client.Store(&mc.ClientConfig{Profile: &pb.ClientProfile{ProfileName: proto.String("synthetic"), User: &pb.User{Name: proto.String(p.Username), Password: proto.String(p.Password)}, Servers: []*pb.ServerEndpoint{{IpAddress: proto.String(p.Server), PortBindings: []*pb.PortBinding{{Port: proto.Int32(int32(p.Port)), Protocol: kind.Enum()}}}}, Multiplexing: &pb.MultiplexingConfig{Level: pb.MultiplexingLevel(level).Enum()}, HandshakeMode: pb.HandshakeMode(handshake).Enum(), TrafficPattern: pat}})
	if err != nil {
		return nil, err
	}
	if err = client.Start(); err != nil {
		return nil, err
	}
	var closers []io.Closer
	for _, l := range c.Listeners {
		address := net.JoinHostPort(l.Listen, l.Port)
		if _, err = local(address); err != nil {
			return nil, err
		}
		dest, err := target(l.Target)
		if err != nil {
			return nil, err
		}
		if len(l.Network) != 1 {
			return nil, errors.New("需要一种监听网络")
		}
		if strings.ToLower(l.Network[0]) == "tcp" {
			listener, err := net.Listen("tcp", address)
			if err != nil {
				return nil, err
			}
			closers = append(closers, listener)
			go func(l net.Listener, d *net.UDPAddr) {
				for {
					conn, err := l.Accept()
					if err != nil {
						return
					}
					go func() {
						ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
						defer cancel()
						up, err := client.DialContext(ctx, &net.TCPAddr{IP: d.IP, Port: d.Port})
						if err != nil {
							conn.Close()
							return
						}
						bridge(conn, up)
					}()
				}
			}(listener, dest)
		} else if strings.ToLower(l.Network[0]) == "udp" {
			socket, err := net.ListenPacket("udp", address)
			if err != nil {
				return nil, err
			}
			closers = append(closers, socket)
			go func(s net.PacketConn, d *net.UDPAddr) {
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				conn, err := client.DialContext(ctx, d)
				if err != nil {
					return
				}
				defer conn.Close()
				tunnel := &packetTunnel{inner: common.NewPacketOverStreamTunnel(conn)}
				var mu sync.Mutex
				var peer net.Addr
				go func() {
					for {
						body, _, err := tunnel.read()
						if err != nil {
							return
						}
						mu.Lock()
						r := peer
						mu.Unlock()
						if r != nil {
							_, _ = s.WriteTo(body, r)
						}
					}
				}()
				buf := make([]byte, 65535)
				for {
					n, from, err := s.ReadFrom(buf)
					if err != nil {
						return
					}
					mu.Lock()
					peer = from
					mu.Unlock()
					if err = tunnel.send(buf[:n], d); err != nil {
						return
					}
				}
			}(socket, dest)
		} else {
			return nil, errors.New("监听网络不合法")
		}
	}
	return func() {
		for _, c := range closers {
			c.Close()
		}
		_ = client.Stop()
	}, nil
}
func main() {
	file := flag.String("f", "", "合成配置")
	_ = flag.String("d", "", "兼容互通工具参数")
	encode := flag.Bool("encode-traffic", false, "输出合成 traffic pattern")
	mode := flag.Int("mode", 0, "低熵模式")
	rotation := flag.Int("rotation", 0, "掩码旋转")
	padding := flag.Int("padding", 32, "填充上限")
	flag.Parse()
	if *encode {
		p := traffic(*mode, *rotation, *padding)
		if err := tp.Validate(p); err != nil {
			panic(err)
		}
		fmt.Println(tp.Encode(p))
		return
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		panic(err)
	}
	var c config
	if err = json.Unmarshal(data, &c); err != nil {
		panic(err)
	}
	var stop func()
	if len(c.Listeners) == 1 && c.Listeners[0].Type == "mieru" {
		stop, err = startServer(c.Listeners[0])
	} else {
		stop, err = startClient(c)
	}
	if err != nil {
		panic(err)
	}
	defer stop()
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGTERM, syscall.SIGINT)
	<-signalCh
}
