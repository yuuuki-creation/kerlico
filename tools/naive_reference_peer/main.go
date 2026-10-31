// 独立测试参照：仅在 worker 启动，不链接进 kerlico 业务程序。
package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var role = flag.String("role", "", "server 或 probe")
var transport = flag.String("transport", "h2", "h1、h2 或 h3")
var listen = flag.String("listen", "127.0.0.1:0", "参照监听")
var server = flag.String("server", "", "参照代理接入")
var name = flag.String("server-name", "proxy.invalid", "TLS校验名称")
var cert = flag.String("cert", "", "服务器证书")
var key = flag.String("key", "", "服务器私钥")
var ca = flag.String("ca", "", "独立客户端CA")
var username = flag.String("username", "test-user", "测试身份")
var password = flag.String("password", "synthetic-secret", "测试口令")
var uotVersion = flag.Uint("uot-version", 2, "UoT版本")

func authorization() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(*username+":"+*password))
}
func fail(err error) { fmt.Fprintln(os.Stderr, "参照失败:", err); os.Exit(1) }

type rawConn struct {
	io.Reader
	io.Writer
	close      func() error
	closeWrite func() error
}

func (c *rawConn) Close() error { return c.close() }
func (c *rawConn) CloseWrite() error {
	if c.closeWrite != nil {
		return c.closeWrite()
	}
	return nil
}
func (c *rawConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *rawConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *rawConn) SetDeadline(time.Time) error      { return nil }
func (c *rawConn) SetReadDeadline(time.Time) error  { return nil }
func (c *rawConn) SetWriteDeadline(time.Time) error { return nil }

type padded struct {
	net.Conn
	raw net.Conn
}

func (c *padded) CloseWrite() error {
	if w, ok := c.raw.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return errors.New("载体无半关闭")
}
func padding(c net.Conn) net.Conn { return &padded{Conn: naive.ReferencePadding(c), raw: c} }

type flushWriter struct{ w http.ResponseWriter }

func (w flushWriter) Write(b []byte) (int, error) {
	n, e := w.w.Write(b)
	if e == nil {
		e = http.NewResponseController(w.w).Flush()
	}
	return n, e
}
func dual(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		if w, ok := b.(interface{ CloseWrite() error }); ok {
			w.CloseWrite()
		}
	}()
	io.Copy(a, b)
	if w, ok := a.(interface{ CloseWrite() error }); ok {
		w.CloseWrite()
	}
	wg.Wait()
}
func packetSocket() (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var err error
		e := c.Control(func(fd uintptr) { err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0) })
		if e != nil {
			return e
		}
		return err
	}}
	return lc.ListenPacket(context.Background(), "udp6", "[::]:0")
}
func relayUOT(stream net.Conn, version uint8) error {
	request := uot.Request{}
	var err error
	if version == 2 {
		r, e := uot.ReadRequest(stream)
		if e != nil {
			return e
		}
		request = *r
	}
	wire := uot.NewConn(stream, request)
	socket, err := packetSocket()
	if err != nil {
		return err
	}
	defer socket.Close()
	_ = socket.SetDeadline(time.Now().Add(12 * time.Second))
	done := make(chan error, 1)
	go func() {
		for {
			packet := buf.NewSize(65535)
			target, e := wire.ReadPacket(packet)
			if e != nil {
				packet.Release()
				done <- e
				return
			}
			address, e := net.ResolveUDPAddr("udp", target.String())
			if e == nil {
				_, e = socket.WriteTo(packet.Bytes(), address)
			}
			packet.Release()
			if e != nil {
				done <- e
				return
			}
		}
	}()
	output := make(chan error, 1)
	go func() {
		for {
			packet := buf.NewSize(65535)
			n, source, e := socket.ReadFrom(packet.FreeBytes())
			if e != nil {
				packet.Release()
				output <- e
				return
			}
			packet.Truncate(n)
			e = wire.WritePacket(packet, M.SocksaddrFromNet(source))
			packet.Release()
			if e != nil {
				output <- e
				return
			}
		}
	}()
	select {
	case err = <-done:
	case err = <-output:
	}
	return err
}
func handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "CONNECT" || r.Header.Get("Padding") == "" || r.Header.Get("Padding-Type-Request") != "" && !strings.Contains(r.Header.Get("Padding-Type-Request"), "1") {
		http.Error(w, "请求拒绝", 400)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Proxy-Authorization")), []byte(authorization())) != 1 {
		http.Error(w, "认证拒绝", 407)
		return
	}
	if r.ProtoMajor > 1 && (r.URL.Scheme != "" || r.URL.Path != "") {
		http.Error(w, "CONNECT伪头不合法", 400)
		return
	}
	host := r.Host
	if r.URL.Host != "" {
		host = r.URL.Host
	}
	target := M.ParseSocksaddr(host)
	version := uint8(0)
	if target.Fqdn == uot.MagicAddress {
		version = 2
	} else if target.Fqdn == uot.LegacyMagicAddress {
		version = 1
	}
	var upstream net.Conn
	var err error
	if version == 0 {
		upstream, err = net.DialTimeout("tcp", host, 4*time.Second)
		if err != nil {
			http.Error(w, "目标不可达", 502)
			return
		}
		defer upstream.Close()
	}
	w.Header().Set("Padding", strings.Repeat("~", 40))
	w.Header().Set("Padding-Type-Reply", "1")
	var raw net.Conn
	if r.ProtoMajor == 1 {
		connection, reader, e := http.NewResponseController(w).Hijack()
		if e != nil {
			return
		}
		defer connection.Close()
		fmt.Fprint(reader, "HTTP/1.1 200 OK\r\nPadding: ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\r\nPadding-Type-Reply: 1\r\n\r\n")
		reader.Flush()
		raw = &rawConn{Reader: reader, Writer: connection, close: connection.Close, closeWrite: func() error {
			if w, ok := connection.(interface{ CloseWrite() error }); ok {
				return w.CloseWrite()
			}
			return nil
		}}
	} else {
		w.WriteHeader(200)
		http.NewResponseController(w).Flush()
		raw = &rawConn{Reader: r.Body, Writer: flushWriter{w}, close: r.Body.Close}
		defer r.Body.Close()
	}
	stream := padding(raw)
	if version > 0 {
		_ = relayUOT(stream, version)
	} else {
		dual(stream, upstream)
	}
}
func serve() error {
	certificate, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		return err
	}
	config := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *transport == "h3" {
		config.NextProtos = []string{"h3"}
		s := &http3.Server{Addr: *listen, Handler: http.HandlerFunc(handler), TLSConfig: config, QUICConfig: &quic.Config{Versions: []quic.Version{quic.Version1}, MaxIncomingStreams: 64, MaxIncomingUniStreams: 16, MaxIdleTimeout: 10 * time.Second}, MaxHeaderBytes: 16384}
		go func() { <-ctx.Done(); s.Close() }()
		return s.ListenAndServe()
	}
	if *transport == "h2" {
		config.NextProtos = []string{"h2"}
	} else if *transport == "h1" {
		config.NextProtos = []string{"http/1.1"}
	} else {
		return errors.New("载体不合法")
	}
	s := &http.Server{Addr: *listen, Handler: http.HandlerFunc(handler), TLSConfig: config, ReadHeaderTimeout: 4 * time.Second, MaxHeaderBytes: 16384}
	if *transport == "h2" {
		if e := http2.ConfigureServer(s, &http2.Server{MaxConcurrentStreams: 64, MaxReadFrameSize: 16384}); e != nil {
			return e
		}
	}
	go func() { <-ctx.Done(); s.Close() }()
	return s.ListenAndServeTLS("", "")
}

type client struct {
	tls   *tls.Config
	round http.RoundTripper
}

func newClient() (*client, error) {
	pem, err := os.ReadFile(*ca)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("CA不合法")
	}
	config := &tls.Config{RootCAs: roots, ServerName: *name, MinVersion: tls.VersionTLS12}
	c := &client{tls: config}
	if *transport == "h2" {
		config.NextProtos = []string{"h2"}
		c.round = &http2.Transport{TLSClientConfig: config}
	} else if *transport == "h3" {
		config.NextProtos = []string{"h3"}
		c.round = &http3.Transport{TLSClientConfig: config, QUICConfig: &quic.Config{Versions: []quic.Version{quic.Version1}}}
	} else if *transport == "h1" {
		config.NextProtos = []string{"http/1.1"}
	} else {
		return nil, errors.New("载体不合法")
	}
	return c, nil
}
func (c *client) dial(target M.Socksaddr) (net.Conn, error) {
	if *transport == "h1" {
		tcp, e := net.DialTimeout("tcp", *server, 4*time.Second)
		if e != nil {
			return nil, e
		}
		connection := tls.Client(tcp, c.tls)
		if e = connection.Handshake(); e != nil {
			tcp.Close()
			return nil, e
		}
		fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\nPadding: ~~~~~~~~~~~~~~~~~~~~~~~~\r\nPadding-Type-Request: 1\r\n\r\n", target.String(), target.String(), authorization())
		reader := bufio.NewReader(connection)
		response, e := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
		if e != nil || response.StatusCode != 200 {
			connection.Close()
			return nil, errors.New("CONNECT拒绝")
		}
		return padding(&rawConn{Reader: reader, Writer: connection, close: connection.Close, closeWrite: connection.CloseWrite}), nil
	}
	uploadReader, uploadWriter := io.Pipe()
	request := &http.Request{Method: "CONNECT", URL: &url.URL{Scheme: "https", Host: *server}, Host: target.String(), Header: make(http.Header), Body: uploadReader}
	request.Header.Set("Proxy-Authorization", authorization())
	request.Header.Set("Padding", strings.Repeat("~", 24))
	request.Header.Set("Padding-Type-Request", "1")
	response, err := c.round.RoundTrip(request)
	if err != nil {
		uploadWriter.Close()
		return nil, err
	}
	if response.StatusCode != 200 || response.Header.Get("Padding") == "" {
		uploadWriter.Close()
		response.Body.Close()
		return nil, errors.New("CONNECT拒绝")
	}
	raw := &rawConn{Reader: response.Body, Writer: uploadWriter, close: func() error { uploadWriter.Close(); return response.Body.Close() }, closeWrite: uploadWriter.Close}
	return padding(raw), nil
}

type command struct {
	Network     string `json:"network"`
	Host        string `json:"host"`
	Port        uint16 `json:"port"`
	Payload     string `json:"payload"`
	ReadLen     int    `json:"read_len"`
	Shutdown    bool   `json:"shutdown"`
	Association string `json:"association"`
}
type reply struct {
	OK      bool   `json:"ok"`
	Payload string `json:"payload,omitempty"`
	Host    string `json:"host,omitempty"`
	Port    uint16 `json:"port,omitempty"`
	Error   string `json:"error,omitempty"`
}

func probe() error {
	c, err := newClient()
	if err != nil {
		return err
	}
	associations := make(map[string]*uot.Conn)
	defer func() {
		for _, connection := range associations {
			connection.Close()
		}
	}()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var cmd command
		var response reply
		e := json.Unmarshal(scanner.Bytes(), &cmd)
		if e == nil {
			response, e = c.command(cmd, associations)
		}
		if e != nil {
			response = reply{Error: e.Error()}
		}
		if err = encoder.Encode(response); err != nil {
			return err
		}
	}
	return scanner.Err()
}
func (c *client) command(cmd command, associations map[string]*uot.Conn) (reply, error) {
	payload, err := base64.StdEncoding.DecodeString(cmd.Payload)
	if err != nil {
		return reply{}, err
	}
	target := M.ParseSocksaddrHostPort(cmd.Host, cmd.Port)
	if cmd.Network == "tcp" {
		connection, e := c.dial(target)
		if e != nil {
			return reply{}, e
		}
		defer connection.Close()
		if _, e = connection.Write(payload); e != nil {
			return reply{}, e
		}
		if cmd.Shutdown {
			if w, ok := connection.(interface{ CloseWrite() error }); ok {
				if e = w.CloseWrite(); e != nil {
					return reply{}, e
				}
			}
		}
		if cmd.ReadLen < 0 || cmd.ReadLen > 2*1024*1024 {
			return reply{}, errors.New("读取长度超限")
		}
		packet := make([]byte, cmd.ReadLen)
		_, e = io.ReadFull(connection, packet)
		return reply{OK: e == nil, Payload: base64.StdEncoding.EncodeToString(packet)}, e
	}
	if cmd.Network != "udp" && cmd.Network != "udp-receive" {
		return reply{}, errors.New("业务类型不合法")
	}
	id := cmd.Association
	if id == "" {
		id = "default"
	}
	connection := associations[id]
	if connection == nil {
		magic := uot.RequestDestination(uint8(*uotVersion))
		raw, e := c.dial(magic)
		if e != nil {
			return reply{}, e
		}
		client := uot.Client{Version: uint8(*uotVersion)}
		connection, e = client.DialConn(raw, false, target)
		if e != nil {
			raw.Close()
			return reply{}, e
		}
		associations[id] = connection
	}
	if cmd.Network == "udp" {
		packet := buf.As(payload)
		if e := connection.WritePacket(packet, target); e != nil {
			return reply{}, e
		}
	}
	packet := buf.NewSize(65535)
	defer packet.Release()
	source, e := connection.ReadPacket(packet)
	if e != nil {
		return reply{}, e
	}
	return reply{OK: true, Payload: base64.StdEncoding.EncodeToString(packet.Bytes()), Host: source.AddrString(), Port: source.Port}, nil
}
func main() {
	flag.Parse()
	if os.Getenv("KERLICO_WORKER_ONLY") != "1" {
		fail(errors.New("只允许专用worker执行"))
	}
	if *uotVersion != 1 && *uotVersion != 2 {
		fail(errors.New("UoT版本不合法"))
	}
	var err error
	switch *role {
	case "server":
		err = serve()
	case "probe":
		err = probe()
	default:
		err = errors.New("角色不合法")
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !strings.Contains(err.Error(), "closed") {
		fail(err)
	}
}
