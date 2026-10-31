// 仅供专用 worker 的回环 ShadowQUIC 参照；不属于 Rust 内核运行路径。
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	quic "github.com/metacubex/jls-quic-go"
	tls "github.com/metacubex/jls-tls"
	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	sq "github.com/metacubex/mihomo/transport/shadowquic"
	"github.com/metacubex/mihomo/transport/socks5"
)

type identity struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type listener struct {
	Type     string     `json:"type"`
	Listen   string     `json:"listen"`
	Port     string     `json:"port"`
	Target   string     `json:"target"`
	Network  []string   `json:"network"`
	Users    []identity `json:"users"`
	Upstream struct {
		Addr string `json:"addr"`
		SNI  string `json:"sni"`
	} `json:"jls-upstream"`
	Versions []string `json:"quic-versions"`
}
type proxy struct {
	Server   string   `json:"server"`
	Port     uint16   `json:"port"`
	SNI      string   `json:"sni"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	Versions []string `json:"quic-versions"`
	Stream   bool     `json:"udp-over-stream"`
}
type config struct {
	Listeners []listener `json:"listeners"`
	Proxies   []proxy    `json:"proxies"`
}

func version(values []string) (quic.Version, error) {
	if len(values) != 1 {
		return 0, errors.New("参照必须固定一个 QUIC 版本")
	}
	switch values[0] {
	case "v1":
		return quic.Version1, nil
	case "v2":
		return quic.Version2, nil
	}
	return 0, errors.New("QUIC 版本不合法")
}
func loopback(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("参照仅允许字面回环地址")
	}
	return nil
}
func quicConfig(v quic.Version) *quic.Config {
	return &quic.Config{Versions: []quic.Version{v}, EnableDatagrams: true, MaxDatagramFrameSize: 1400, MaxIdleTimeout: 10 * time.Second, MaxIncomingStreams: 128, MaxIncomingUniStreams: 128}
}
func clientTLS(p proxy) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: p.SNI, NextProtos: []string{"h3"}, JLSConfig: &tls.JLSConfig{Enable: true, User: tls.JLSUser{Username: p.Username, Password: p.Password}}}
}
func dial(p proxy) (*quic.Conn, error) {
	v, err := version(p.Versions)
	if err != nil {
		return nil, err
	}
	address := net.JoinHostPort(p.Server, strconv.Itoa(int(p.Port)))
	if err = loopback(address); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, address, clientTLS(p), quicConfig(v))
	if err != nil {
		return nil, err
	}
	if conn.ConnectionState().TLS.JLS.Status != tls.JLSAuthenticated {
		conn.CloseWithError(0, "")
		return nil, errors.New("JLS 未认证")
	}
	return conn, nil
}
func serverTLS(l listener) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cover.invalid"}, DNSNames: []string{"cover.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
	if err != nil {
		return nil, err
	}
	users := make([]tls.JLSUser, 0, len(l.Users))
	for _, u := range l.Users {
		users = append(users, tls.JLSUser{Username: u.Username, Password: u.Password})
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, Certificates: []tls.Certificate{pair}, SessionTicketsDisabled: true, JLSConfig: &tls.JLSConfig{Enable: true, Users: users, ServerName: l.Upstream.SNI}}, nil
}
func bridge(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(b, a)
		if w, ok := b.(interface{ CloseWrite() error }); ok {
			_ = w.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(a, b)
	if w, ok := a.(interface{ CloseWrite() error }); ok {
		_ = w.CloseWrite()
	}
	<-done
}
func runServer(l listener) (func(), error) {
	address := net.JoinHostPort(l.Listen, l.Port)
	if err := loopback(address); err != nil {
		return nil, err
	}
	if err := loopback(l.Upstream.Addr); err != nil {
		return nil, err
	}
	v, err := version(l.Versions)
	if err != nil {
		return nil, err
	}
	crypto, err := serverTLS(l)
	if err != nil {
		return nil, err
	}
	socket, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, err
	}
	qc := quicConfig(v)
	qc.JLSConfig = &quic.JLSConfig{UpstreamAddr: l.Upstream.Addr, RateLimit: 16000000,
		PacketDialer: func(ctx context.Context, network, address string) (net.PacketConn, net.Addr, error) {
			if err := loopback(address); err != nil {
				return nil, nil, err
			}
			target, err := net.ResolveUDPAddr("udp", address)
			if err != nil {
				return nil, nil, err
			}
			bind := "0.0.0.0:0"
			if target.IP.To4() == nil {
				bind = "[::]:0"
			}
			var lc net.ListenConfig
			pc, err := lc.ListenPacket(ctx, "udp", bind)
			return pc, target, err
		},
	}
	var mu sync.Mutex
	assocs := map[string]*net.UDPConn{}
	server, err := sq.NewServer(&sq.ServerOption{TLSConfig: crypto, QUICConfig: qc, CongestionController: "cubic",
		HandleTcpFn: func(conn net.Conn, addr socks5.Addr, _ ...inbound.Addition) error {
			if err := loopback(addr.String()); err != nil {
				return err
			}
			target, err := net.DialTimeout("tcp", addr.String(), 4*time.Second)
			if err != nil {
				return err
			}
			go bridge(conn, target)
			return nil
		},
		HandleUdpFn: func(addr socks5.Addr, packet C.UDPPacket, _ ...inbound.Addition) error {
			defer packet.Drop()
			if err := loopback(addr.String()); err != nil {
				return err
			}
			target, err := net.ResolveUDPAddr("udp", addr.String())
			if err != nil {
				return err
			}
			key := packet.LocalAddr().String()
			mu.Lock()
			socket := assocs[key]
			if socket == nil {
				socket, err = net.ListenUDP("udp", &net.UDPAddr{Port: 0})
				if err != nil {
					mu.Unlock()
					return err
				}
				assocs[key] = socket
				go func(s *net.UDPConn, p C.UDPPacket) {
					buf := make([]byte, 65535)
					for {
						n, from, err := s.ReadFromUDP(buf)
						if err != nil {
							return
						}
						if _, err = p.WriteBack(buf[:n], from); err != nil {
							return
						}
					}
				}(socket, packet)
			}
			mu.Unlock()
			_, err = socket.WriteToUDP(packet.Data(), target)
			return err
		}}, socket)
	if err != nil {
		socket.Close()
		return nil, err
	}
	go func() { _ = server.Serve() }()
	return func() {
		server.Close()
		socket.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, s := range assocs {
			s.Close()
		}
	}, nil
}
func runClient(c config) (func(), error) {
	if len(c.Proxies) != 1 {
		return nil, errors.New("参照需要一个出站")
	}
	p := c.Proxies[0]
	client := sq.NewClient(&sq.ClientOption{Dial: func(context.Context) (*quic.Conn, error) { return dial(p) }, UDPOverStream: p.Stream, CongestionController: "cubic"})
	var closers []io.Closer
	for _, l := range c.Listeners {
		address := net.JoinHostPort(l.Listen, l.Port)
		if err := loopback(address); err != nil {
			return nil, err
		}
		if err := loopback(l.Target); err != nil {
			return nil, err
		}
		metadata := &C.Metadata{}
		if err := metadata.SetRemoteAddress(l.Target); err != nil {
			return nil, err
		}
		if len(l.Network) != 1 {
			return nil, errors.New("参照监听必须固定一种网络")
		}
		if l.Network[0] == "tcp" {
			listener, err := net.Listen("tcp", address)
			if err != nil {
				return nil, err
			}
			closers = append(closers, listener)
			go func(l net.Listener, m *C.Metadata) {
				for {
					conn, err := l.Accept()
					if err != nil {
						return
					}
					go func() {
						ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
						defer cancel()
						upstream, err := client.DialContext(ctx, m)
						if err != nil {
							conn.Close()
							return
						}
						bridge(conn, upstream)
					}()
				}
			}(listener, metadata)
		} else if l.Network[0] == "udp" {
			socket, err := net.ListenPacket("udp", address)
			if err != nil {
				return nil, err
			}
			closers = append(closers, socket)
			go func(s net.PacketConn, target string, m *C.Metadata) {
				defer s.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				pc, err := client.ListenPacket(ctx, m)
				if err != nil {
					return
				}
				defer pc.Close()
				addr, _ := net.ResolveUDPAddr("udp", target)
				var remote net.Addr
				var lock sync.Mutex
				go func() {
					buf := make([]byte, 65535)
					for {
						n, _, err := pc.ReadFrom(buf)
						if err != nil {
							return
						}
						lock.Lock()
						r := remote
						lock.Unlock()
						if r != nil {
							_, _ = s.WriteTo(buf[:n], r)
						}
					}
				}()
				buf := make([]byte, 65535)
				for {
					n, from, err := s.ReadFrom(buf)
					if err != nil {
						return
					}
					lock.Lock()
					remote = from
					lock.Unlock()
					if _, err = pc.WriteTo(buf[:n], addr); err != nil {
						return
					}
				}
			}(socket, l.Target, metadata)
		} else {
			return nil, errors.New("参照网络不合法")
		}
	}
	return func() {
		for _, c := range closers {
			c.Close()
		}
		client.Close()
	}, nil
}
func main() {
	file := flag.String("f", "", "合成配置文件")
	_ = flag.String("d", "", "兼容测试工具的私有目录参数")
	probe := flag.Bool("probe", false, "只验证合成 JLS 握手")
	flag.Parse()
	data, err := os.ReadFile(*file)
	if err != nil {
		panic(err)
	}
	var c config
	if err = json.Unmarshal(data, &c); err != nil {
		panic(err)
	}
	if *probe {
		if len(c.Proxies) != 1 {
			panic("需要一个合成出站")
		}
		conn, err := dial(c.Proxies[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		conn.CloseWithError(0, "")
		fmt.Println("受控 Go JLS 握手通过")
		return
	}
	var closeFn func()
	if len(c.Listeners) == 1 && c.Listeners[0].Type == "shadowquic" {
		closeFn, err = runServer(c.Listeners[0])
	} else {
		closeFn, err = runClient(c)
	}
	if err != nil {
		panic(err)
	}
	defer closeFn()
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGTERM, syscall.SIGINT)
	<-signalCh
}
