// mieru-peer 使用官方公开 Go API 进行真实双向互通验收。
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	apiClient "github.com/enfein/mieru/v3/apis/client"
	apiCommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/model"
	apiServer "github.com/enfein/mieru/v3/apis/server"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"
)

const upstreamSHA = "1367cf2d2dd81c5f27d455be7cea691d7948c420"

type options struct {
	listen, transport, multiplexing, handshake, password string
	port, mtu, low, sessions                             int
	timeout                                              time.Duration
	tcpTargets, udpTargets                               string
}

type packetFailure struct {
	stage    string
	evidence map[string]any
}

func (e *packetFailure) Error() string { return e.stage }

func udpFailure(stage string, index, expected, actual int, target, source string, payload []byte, err error) error {
	detail := map[string]any{"index": index, "expected_length": expected, "actual_length": actual,
		"target": target, "source": source, "error": nil}
	if err != nil {
		detail["error"] = err.Error()
	}
	if len(payload) > 24 {
		payload = payload[:24]
	}
	detail["actual_prefix"] = fmt.Sprintf("%x", payload)
	return &packetFailure{stage: stage, evidence: detail}
}

func main() {
	if len(os.Args) < 2 {
		fail("command")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o := options{}
	fs.StringVar(&o.listen, "listen", "127.0.0.1", "代理端点 IP")
	fs.IntVar(&o.port, "port", 0, "代理端点端口")
	fs.StringVar(&o.transport, "transport", "TCP", "TCP 或 UDP")
	fs.IntVar(&o.mtu, "mtu", 1400, "UDP MTU")
	fs.IntVar(&o.low, "low", 0, "低熵模式 0..4")
	fs.StringVar(&o.multiplexing, "multiplexing", "MULTIPLEXING_LOW", "官方复用枚举名")
	fs.StringVar(&o.handshake, "handshake", "HANDSHAKE_STANDARD", "官方握手枚举名")
	fs.StringVar(&o.password, "password", "test-password", "合成测试密码")
	fs.StringVar(&o.tcpTargets, "tcp-targets", "", "以逗号分隔的真实 TCP 回显目标")
	fs.StringVar(&o.udpTargets, "udp-targets", "", "以逗号分隔的真实 UDP 回显目标")
	fs.IntVar(&o.sessions, "sessions", 8, "并发 TCP 会话数")
	fs.DurationVar(&o.timeout, "timeout", 25*time.Second, "操作期限")
	if fs.Parse(os.Args[2:]) != nil || o.port < 1025 || o.port > 65535 || o.mtu < 1280 || o.mtu > 1400 || o.low < 0 || o.low > 4 || o.sessions < 1 || o.timeout <= 0 || net.ParseIP(o.listen) == nil {
		fail("arguments")
	}
	if o.transport != "TCP" && o.transport != "UDP" {
		fail("transport")
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = serve(o)
	case "probe":
		err = probe(o)
	default:
		fail("command")
	}
	if err != nil {
		var packet *packetFailure
		if errors.As(err, &packet) {
			emit(map[string]any{"status": "fail", "stage": packet.stage, "message": "UDP 逐包证据", "evidence": packet.evidence, "upstream_sha": upstreamSHA})
			os.Exit(1)
		}
		fail(err.Error())
	}
}

func emit(value any) { _ = json.NewEncoder(os.Stdout).Encode(value) }
func fail(stage string) {
	emit(map[string]any{"status": "fail", "stage": stage, "message": "官方对端验收失败，请按 stage 定位", "upstream_sha": upstreamSHA})
	os.Exit(1)
}
func traffic(low int) *pb.TrafficPattern {
	return &pb.TrafficPattern{LowEntropy: &pb.LowEntropyPattern{Mode: pb.LowEntropyMode(low).Enum(), MaskRotation: pb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION.Enum()}}
}
func binding(o options) *pb.PortBinding {
	transport := pb.TransportProtocol_TCP
	if o.transport == "UDP" {
		transport = pb.TransportProtocol_UDP
	}
	return &pb.PortBinding{Port: proto.Int32(int32(o.port)), Protocol: transport.Enum()}
}
func account(password string) *pb.User {
	return &pb.User{Name: proto.String("test-user"), Password: proto.String(password)}
}

func serve(o options) error {
	s := apiServer.NewServer()
	err := s.Store(&apiServer.ServerConfig{Config: &pb.ServerConfig{
		ListenIPAddress: proto.String(o.listen), PortBindings: []*pb.PortBinding{binding(o)},
		Users: []*pb.User{account("test-password")}, Mtu: proto.Int32(int32(o.mtu)), TrafficPattern: traffic(o.low),
	}})
	if err != nil {
		return errors.New("server-config")
	}
	if s.Start() != nil {
		return errors.New("server-start")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var mu sync.Mutex
	connections := make(map[net.Conn]struct{})
	var workers sync.WaitGroup
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		mu.Lock()
		owned := make([]net.Conn, 0, len(connections))
		for c := range connections {
			owned = append(owned, c)
		}
		mu.Unlock()
		// API Stop 不保证终止现有连接；先关闭夹具拥有的连接，避免
		// Stop 与应用复制循环互相等待，也不持有登记锁进行网络关闭。
		// 官方每个 Session.Close 可能各自等待约一秒；并行关闭独立会话，
		// 避免串行 N 次优雅等待人为耗尽进程的三秒退出预算。
		started := time.Now()
		emit(map[string]any{"status": "stopping", "phase": "connections", "count": len(owned)})
		var closing sync.WaitGroup
		for _, c := range owned {
			closing.Add(1)
			go func(conn net.Conn) { defer closing.Done(); _ = conn.Close() }(c)
		}
		closing.Wait()
		emit(map[string]any{"status": "stopping", "phase": "api-stop", "connections_ms": time.Since(started).Milliseconds()})
		_ = s.Stop()
	}()
	emit(map[string]any{"status": "ready", "upstream_sha": upstreamSHA})
	for ctx.Err() == nil {
		c, req, err := s.Accept()
		if err != nil {
			if c != nil {
				_ = c.Close()
			}
			if ctx.Err() != nil {
				break
			}
			// 非法握手只关闭对应连接，不终止整个监听。
			continue
		}
		mu.Lock()
		if ctx.Err() != nil {
			mu.Unlock()
			_ = c.Close()
			break
		}
		connections[c] = struct{}{}
		mu.Unlock()
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { _ = c.Close(); mu.Lock(); delete(connections, c); mu.Unlock() }()
			_ = c.SetDeadline(time.Now().Add(o.timeout))
			if req.Command == 1 {
				relayTCP(ctx, c, req, o.timeout)
			} else if req.Command == 3 {
				relayUDP(ctx, c, o.timeout)
			} else {
				_ = reply(c, 7)
			}
		}()
	}
	workers.Wait()
	<-stopped
	emit(map[string]any{"status": "stopped"})
	return nil
}

func reply(c net.Conn, code byte) error {
	return model.WriteSocks5Response(c, code, model.AddrSpec{IP: net.IPv4zero, Port: 0})
}

func relayTCP(ctx context.Context, c net.Conn, req *model.Request, timeout time.Duration) {
	remote, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", req.DstAddr.String())
	if err != nil {
		_ = reply(c, 5)
		return
	}
	defer remote.Close()
	_ = remote.SetDeadline(time.Now().Add(timeout))
	if reply(c, 0) != nil {
		return
	}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(remote, c); _ = remote.Close(); _ = c.Close(); close(done) }()
	_, _ = io.Copy(c, remote)
	_ = c.Close()
	_ = remote.Close()
	<-done
}

func relayUDP(ctx context.Context, c net.Conn, timeout time.Duration) {
	if reply(c, 0) != nil {
		return
	}
	packets := apiCommon.NewUDPAssociateWrapper(apiCommon.NewPacketOverStreamTunnel(c), apiCommon.UDPAssociateReadFromFQDN{})
	var writeMu sync.Mutex
	remotes := make(map[string]net.Conn)
	var readers sync.WaitGroup
	defer func() {
		_ = c.Close()
		for _, r := range remotes {
			_ = r.Close()
		}
		readers.Wait()
	}()
	buf := make([]byte, 65535)
	for ctx.Err() == nil {
		n, addr, err := packets.ReadFrom(buf)
		if err != nil {
			return
		}
		key := addr.String()
		r := remotes[key]
		if r == nil {
			r, err = (&net.Dialer{Timeout: timeout}).DialContext(ctx, "udp", key)
			if err != nil {
				return
			}
			_ = r.SetDeadline(time.Now().Add(timeout))
			remotes[key] = r
			readers.Add(1)
			go func(remote net.Conn) {
				defer readers.Done()
				response := make([]byte, 65535)
				for {
					n, err := remote.Read(response)
					if err != nil {
						return
					}
					writeMu.Lock()
					_, err = packets.WriteTo(response[:n], remote.RemoteAddr())
					writeMu.Unlock()
					if err != nil {
						return
					}
				}
			}(r)
		}
		if _, err = r.Write(buf[:n]); err != nil {
			return
		}
	}
}

func address(network, text string) (model.NetAddrSpec, error) {
	a := model.NetAddrSpec{Net: network}
	err := a.AddrSpec.From(text)
	return a, err
}

func probe(o options) error {
	m, ok := pb.MultiplexingLevel_value[o.multiplexing]
	if !ok || m < 1 || m > 4 {
		return errors.New("multiplexing")
	}
	h, ok := pb.HandshakeMode_value[o.handshake]
	if !ok {
		return errors.New("handshake")
	}
	c := apiClient.NewClient()
	profile := &pb.ClientProfile{
		ProfileName: proto.String("fixture"), User: account(o.password),
		Servers: []*pb.ServerEndpoint{{IpAddress: proto.String(o.listen), PortBindings: []*pb.PortBinding{binding(o)}}},
		Mtu:     proto.Int32(int32(o.mtu)), Multiplexing: &pb.MultiplexingConfig{Level: pb.MultiplexingLevel(m).Enum()},
		HandshakeMode: pb.HandshakeMode(h).Enum(), TrafficPattern: traffic(o.low),
	}
	if c.Store(&apiClient.ClientConfig{Profile: profile}) != nil {
		return errors.New("client-config")
	}
	if c.Start() != nil {
		return errors.New("client-start")
	}
	defer c.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	var tcpTargets, udpTargets []string
	if o.tcpTargets != "" {
		tcpTargets = strings.Split(o.tcpTargets, ",")
	}
	if o.udpTargets != "" {
		udpTargets = strings.Split(o.udpTargets, ",")
	}
	if len(tcpTargets) == 0 || len(udpTargets) == 0 {
		return errors.New("targets")
	}
	results := make(chan error, o.sessions)
	for i := 0; i < o.sessions; i++ {
		go func(i int) {
			a, err := address("tcp", tcpTargets[i%len(tcpTargets)])
			if err != nil {
				results <- errors.New("tcp-address")
				return
			}
			conn, err := c.DialContext(ctx, a)
			if err != nil {
				results <- errors.New("tcp-dial")
				return
			}
			defer conn.Close()
			deadline, _ := ctx.Deadline()
			_ = conn.SetDeadline(deadline)
			payload := bytes.Repeat([]byte("session-"+strconv.Itoa(i)+":"), 9000)
			written := make(chan error, 1)
			go func() { _, err := io.Copy(conn, bytes.NewReader(payload)); written <- err }()
			got := make([]byte, len(payload))
			_, err = io.ReadFull(conn, got)
			_ = conn.Close()
			writeErr := <-written
			if err != nil || writeErr != nil || !bytes.Equal(payload, got) {
				results <- errors.New("tcp-bytes")
				return
			}
			results <- nil
		}(i)
	}
	for i := 0; i < o.sessions; i++ {
		if err := <-results; err != nil {
			return err
		}
	}
	a, err := address("udp", udpTargets[0])
	if err != nil {
		return errors.New("udp-address")
	}
	conn, err := c.DialContext(ctx, a)
	if err != nil {
		return errors.New("udp-dial")
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	packets := apiCommon.NewUDPAssociateWrapper(apiCommon.NewPacketOverStreamTunnel(conn), apiCommon.UDPAssociateReadFromFQDN{})
	lengths := []int{0, 1, 1279, 1400, 8192, 32000, 3, 0}
	for i, length := range lengths {
		a, err := address("udp", udpTargets[i%len(udpTargets)])
		if err != nil {
			return errors.New("udp-target")
		}
		payload := bytes.Repeat([]byte{byte(i + 1)}, length)
		if _, err = packets.WriteTo(payload, a); err != nil {
			return udpFailure("udp-write", i, length, -1, a.String(), "", nil, err)
		}
		buf := make([]byte, 65535)
		n, from, err := packets.ReadFrom(buf)
		source := ""
		if from != nil {
			source = from.String()
		}
		if err != nil || !bytes.Equal(payload, buf[:n]) {
			return udpFailure("udp-bytes", i, length, n, a.String(), source, buf[:n], err)
		}
		_, port, splitErr := net.SplitHostPort(from.String())
		if splitErr != nil || port != strconv.Itoa(a.Port) {
			return udpFailure("udp-source", i, length, n, a.String(), source, buf[:n], splitErr)
		}
	}
	emit(map[string]any{"status": "pass", "tcp_sessions": o.sessions, "udp_packets": len(lengths), "upstream_sha": upstreamSHA})
	return nil
}
