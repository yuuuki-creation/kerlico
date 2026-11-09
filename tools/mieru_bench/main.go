// mieru-bench 使用同一个官方客户端，对固定配置的服务端做有效载荷验收与计时。
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/bits"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	apiClient "github.com/enfein/mieru/v3/apis/client"
	"github.com/enfein/mieru/v3/apis/model"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"
)

const upstreamSHA = "1367cf2d2dd81c5f27d455be7cea691d7948c420"

var outputMu sync.Mutex

func emit(value any) {
	outputMu.Lock()
	defer outputMu.Unlock()
	_ = json.NewEncoder(os.Stdout).Encode(value)
}

func reject(stage string) int {
	emit(map[string]any{"event": "error", "status": "fail", "stage": stage, "errors": 1, "message": "基准未完成，不能用部分结果报告成功"})
	return 1
}

func main() {
	if len(os.Args) < 2 {
		os.Exit(reject("command"))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := 1
	switch os.Args[1] {
	case "echo":
		code = runEcho(ctx, os.Args[2:])
	case "load":
		code = runLoad(ctx, os.Args[2:])
	default:
		code = reject("command")
	}
	stop()
	os.Exit(code)
}

type addresses []string

func (a *addresses) String() string         { return "监听地址列表" }
func (a *addresses) Set(value string) error { *a = append(*a, value); return nil }

func validEndpoint(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil || net.ParseIP(host) == nil {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func validLabel(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

type cpuTimes struct {
	User   float64 `json:"user_seconds"`
	System float64 `json:"system_seconds"`
}

func cpuNow() cpuTimes {
	var r syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &r) != nil {
		return cpuTimes{User: -1, System: -1}
	}
	return cpuTimes{User: float64(r.Utime.Sec) + float64(r.Utime.Usec)/1e6, System: float64(r.Stime.Sec) + float64(r.Stime.Usec)/1e6}
}

func writeAll(c net.Conn, data []byte) (int, error) {
	total := 0
	for total < len(data) {
		n, err := c.Write(data[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

type echoCounts struct{ readBytes, writeBytes, reads, writes, connections, closed, active, errors atomic.Uint64 }

func (c *echoCounts) snapshot() map[string]uint64 {
	return map[string]uint64{"read_bytes": c.readBytes.Load(), "write_bytes": c.writeBytes.Load(), "read_calls": c.reads.Load(), "write_batches": c.writes.Load(), "connections": c.connections.Load(), "closed_connections": c.closed.Load(), "active_connections": c.active.Load(), "errors": c.errors.Load()}
}

func runEcho(parent context.Context, args []string) int {
	fs := flag.NewFlagSet("echo", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var binds addresses
	fs.Var(&binds, "listen", "监听 IP:端口，可重复；输出仅记录 listener-0 等别名")
	idle := fs.Duration("idle-timeout", 2*time.Minute, "单连接空闲期限")
	if fs.Parse(args) != nil || len(binds) == 0 || *idle <= 0 {
		return reject("echo-arguments")
	}
	for _, a := range binds {
		if !validEndpoint(a) {
			return reject("echo-listen")
		}
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	listeners := make([]net.Listener, 0, len(binds))
	for _, address := range binds {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			return reject("echo-bind")
		}
		listeners = append(listeners, listener)
	}
	started := time.Now()
	counts := &echoCounts{}
	var mu sync.Mutex
	owned := make(map[net.Conn]struct{})
	var accepting, workers sync.WaitGroup
	for index, listener := range listeners {
		accepting.Add(1)
		go func(index int, l net.Listener) {
			defer accepting.Done()
			for {
				conn, err := l.Accept()
				if err != nil {
					if ctx.Err() == nil {
						counts.errors.Add(1)
						cancel()
					}
					return
				}
				mu.Lock()
				owned[conn] = struct{}{}
				mu.Unlock()
				counts.connections.Add(1)
				counts.active.Add(1)
				workers.Add(1)
				go func(c net.Conn) {
					defer workers.Done()
					defer func() {
						_ = c.Close()
						mu.Lock()
						delete(owned, c)
						mu.Unlock()
						counts.active.Add(^uint64(0))
						counts.closed.Add(1)
					}()
					buf := make([]byte, 64*1024)
					for {
						_ = c.SetDeadline(time.Now().Add(*idle))
						n, err := c.Read(buf)
						if n > 0 {
							counts.readBytes.Add(uint64(n))
							counts.reads.Add(1)
							written, writeErr := writeAll(c, buf[:n])
							counts.writeBytes.Add(uint64(written))
							counts.writes.Add(1)
							if writeErr != nil {
								if ctx.Err() == nil {
									counts.errors.Add(1)
								}
								return
							}
						}
						if err != nil {
							if !errors.Is(err, io.EOF) && ctx.Err() == nil {
								counts.errors.Add(1)
							}
							return
						}
					}
				}(conn)
			}
		}(index, listener)
	}
	emit(map[string]any{"event": "ready", "mode": "echo", "start_unix_ns": started.UnixNano(), "listeners": len(listeners)})
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	previous := counts.snapshot()
	previousAt := started
sample:
	for {
		select {
		case <-ctx.Done():
			break sample
		case now := <-ticker.C:
			current := counts.snapshot()
			emit(map[string]any{"event": "sample", "mode": "echo", "at_unix_ns": now.UnixNano(), "sample_seconds": now.Sub(previousAt).Seconds(), "read_bytes": current["read_bytes"] - previous["read_bytes"], "write_bytes": current["write_bytes"] - previous["write_bytes"], "counts": current})
			previous, previousAt = current, now
		}
	}
	for _, l := range listeners {
		_ = l.Close()
	}
	accepting.Wait()
	mu.Lock()
	sockets := make([]net.Conn, 0, len(owned))
	for c := range owned {
		sockets = append(sockets, c)
	}
	mu.Unlock()
	for _, c := range sockets {
		_ = c.Close()
	}
	workers.Wait()
	ended := time.Now()
	status := "pass"
	if counts.errors.Load() > 0 {
		status = "fail"
	}
	emit(map[string]any{"event": "final", "mode": "echo", "status": status, "start_unix_ns": started.UnixNano(), "end_unix_ns": ended.UnixNano(), "duration_seconds": ended.Sub(started).Seconds(), "counts": counts.snapshot(), "cpu": cpuNow()})
	if status != "pass" {
		return 1
	}
	return 0
}

type countedDialer struct{ opened, active atomic.Int64 }
type countedConn struct {
	net.Conn
	owner *countedDialer
	once  sync.Once
}

func (c *countedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.owner.active.Add(-1) })
	return err
}
func (d *countedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	d.opened.Add(1)
	d.active.Add(1)
	return &countedConn{Conn: c, owner: d}, nil
}

// 对数直方图有界；每个数量级分十六档，分位数报告桶上界，避免无限存样本。
type histogram [1024]uint64

func (h *histogram) add(d time.Duration) {
	u := uint64(d / time.Microsecond)
	if u < 1 {
		u = 1
	}
	index := int(u)
	if u >= 16 {
		b := bits.Len64(u) - 1
		index = 16 + (b-4)*16 + int((u-(uint64(1)<<b))>>(b-4))
	}
	if index >= len(h) {
		index = len(h) - 1
	}
	h[index]++
}
func (h *histogram) merge(other *histogram) {
	for i, n := range other {
		h[i] += n
	}
}
func (h *histogram) percentile(p float64) float64 {
	var total uint64
	for _, n := range h {
		total += n
	}
	if total == 0 {
		return 0
	}
	target := uint64(math.Ceil(float64(total) * p))
	if target < 1 {
		target = 1
	}
	var seen uint64
	for i, n := range h {
		seen += n
		if seen < target {
			continue
		}
		if i < 16 {
			return float64(i+1) / 1000
		}
		b := 4 + (i-16)/16
		sub := (i - 16) % 16
		return float64((uint64(1)<<b)+(uint64(sub+1)<<(b-4))) / 1000
	}
	return 0
}
func (h *histogram) summary() map[string]float64 {
	return map[string]float64{"p50_ms_upper": h.percentile(.50), "p95_ms_upper": h.percentile(.95), "p99_ms_upper": h.percentile(.99)}
}

type secondCounts struct {
	Second     int    `json:"second"`
	BulkBytes  uint64 `json:"bulk_ack_bytes"`
	BulkOps    uint64 `json:"bulk_completions"`
	ProbeBytes uint64 `json:"probe_ack_bytes"`
	ProbeOps   uint64 `json:"probe_completions"`
}
type flowResult struct {
	ID         int            `json:"flow"`
	Probe      bool           `json:"probe"`
	Bytes      uint64         `json:"ack_bytes"`
	Ops        uint64         `json:"completions"`
	LateBytes  uint64         `json:"late_ack_bytes"`
	LateOps    uint64         `json:"late_completions"`
	Errors     uint64         `json:"errors"`
	Timeouts   uint64         `json:"timeouts"`
	Mismatches uint64         `json:"mismatches"`
	ErrorStage string         `json:"error_stage,omitempty"`
	ErrorType  string         `json:"error_type,omitempty"`
	Errno      string         `json:"errno,omitempty"`
	RTT        histogram      `json:"-"`
	Seconds    []secondCounts `json:"-"`
}

func recordError(result *flowResult, stage string, err error) {
	result.Errors++
	result.ErrorStage = stage
	result.ErrorType = fmt.Sprintf("%T", err)
	var netError net.Error
	if errors.As(err, &netError) && netError.Timeout() {
		result.Timeouts++
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		result.Errno = errno.Error()
	}
}
func payload(size, id int) []byte {
	data := make([]byte, size)
	x := uint64(id+1) * 0x9e3779b97f4a7c15
	for i := range data {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		data[i] = byte(x)
	}
	return data
}
func exchange(c net.Conn, sent, received []byte, sequence uint64, deadline time.Time) (time.Duration, string, error) {
	binary.LittleEndian.PutUint64(sent[:8], sequence)
	_ = c.SetDeadline(deadline)
	started := time.Now()
	if _, err := writeAll(c, sent); err != nil {
		return 0, "write", err
	}
	if _, err := io.ReadFull(c, received); err != nil {
		return 0, "read", err
	}
	if !bytes.Equal(sent, received) {
		return 0, "compare", errors.New("字节不符")
	}
	return time.Since(started), "", nil
}

func waitUntil(ctx context.Context, at time.Time) bool {
	left := time.Until(at)
	if left <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(left)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func runFlow(ctx context.Context, c net.Conn, id, size int, probe bool, start, end time.Time, drain, ioBudget time.Duration) flowResult {
	result := flowResult{ID: id, Probe: probe, Seconds: make([]secondCounts, int(end.Sub(start)/time.Second)+1)}
	sent, received := payload(size, id), make([]byte, size)
	sequence := uint64(1) << 63
	for time.Now().Before(end) {
		if ctx.Err() != nil {
			recordError(&result, "cancel", ctx.Err())
			break
		}
		deadline := time.Now().Add(ioBudget)
		if end.Add(drain).Before(deadline) {
			deadline = end.Add(drain)
		}
		operationStart := time.Now()
		rtt, stage, err := exchange(c, sent, received, sequence, deadline)
		sequence++
		completed := time.Now()
		if err != nil {
			recordError(&result, stage, err)
			if stage == "compare" {
				result.Mismatches++
			}
			break
		}
		if completed.Before(end) {
			result.Bytes += uint64(size)
			result.Ops++
			result.RTT.add(rtt)
			index := int(completed.Sub(start) / time.Second)
			if probe {
				result.Seconds[index].ProbeBytes += uint64(size)
				result.Seconds[index].ProbeOps++
			} else {
				result.Seconds[index].BulkBytes += uint64(size)
				result.Seconds[index].BulkOps++
			}
		} else {
			result.LateBytes += uint64(size)
			result.LateOps++
		}
		if probe {
			_ = waitUntil(ctx, operationStart.Add(10*time.Millisecond))
		}
	}
	return result
}

func closeTogether(connections []net.Conn) {
	var wg sync.WaitGroup
	for _, c := range connections {
		wg.Add(1)
		go func(c net.Conn) { defer wg.Done(); _ = c.Close() }(c)
	}
	wg.Wait()
}

func runLoad(parent context.Context, args []string) int {
	fs := flag.NewFlagSet("load", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	peer := fs.String("peer", "", "代理 IP:端口，只用于连接，不写入结果")
	target := fs.String("target", "", "真实回显目标 IP:端口，不写入结果")
	label := fs.String("label", "candidate", "匿名结果别名，只允许字母数字和连字符")
	direct := fs.Bool("direct", false, "直连回显目标，作为链路基线")
	duration := fs.Duration("duration", 60*time.Second, "有效载荷计时区间")
	warmup := fs.Duration("warmup", 5*time.Second, "所有连接建立后的预热区间")
	concurrency := fs.Int("concurrency", 8, "持久 bulk 流数，另加一条延迟探针")
	blockSize := fs.Int("block-size", 32768, "bulk 每次写入并读回的字节数")
	latencySize := fs.Int("latency-size", 64, "低速延迟探针的字节数")
	startAt := fs.Int64("start-at", 0, "预热后开始计时的 Unix 毫秒；0 为 READY 后约半秒")
	drain := fs.Duration("drain", 5*time.Second, "到期后只允许已开始操作排空的最长时间")
	hold := fs.Duration("hold-after-final", 0, "结果输出后保留进程的时间，供资源采样收尾；不计入性能窗口")
	ioBudget := fs.Duration("io-timeout", 10*time.Second, "每次完整写入与读回的合计期限")
	if fs.Parse(args) != nil || !validEndpoint(*target) || (!*direct && !validEndpoint(*peer)) || !validLabel(*label) || *duration < time.Second || *duration > 10*time.Minute || *warmup < 0 || *warmup > time.Minute || *concurrency < 1 || *concurrency > 256 || *blockSize < 8 || *blockSize > 1024*1024 || *latencySize < 8 || *latencySize > 1024*1024 || *drain < 0 || *drain > 30*time.Second || *hold < 0 || *hold > 30*time.Second || *ioBudget <= 0 {
		return reject("load-arguments")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	dialer := &countedDialer{}
	var sdk apiClient.Client
	if !*direct {
		host, portText, _ := net.SplitHostPort(*peer)
		port, _ := strconv.Atoi(portText)
		sdk = apiClient.NewClient()
		profile := &pb.ClientProfile{ProfileName: proto.String("benchmark"), User: &pb.User{Name: proto.String("test-user"), Password: proto.String("test-password")},
			Servers: []*pb.ServerEndpoint{{IpAddress: proto.String(host), PortBindings: []*pb.PortBinding{{Port: proto.Int32(int32(port)), Protocol: pb.TransportProtocol_TCP.Enum()}}}},
			Mtu:     proto.Int32(1400), Multiplexing: &pb.MultiplexingConfig{Level: pb.MultiplexingLevel_MULTIPLEXING_LOW.Enum()}, HandshakeMode: pb.HandshakeMode_HANDSHAKE_STANDARD.Enum(),
			TrafficPattern: &pb.TrafficPattern{LowEntropy: &pb.LowEntropyPattern{Mode: pb.LowEntropyMode_LOW_ENTROPY_MODE_OFF.Enum(), MaskRotation: pb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION.Enum()}}}
		if sdk.Store(&apiClient.ClientConfig{Profile: profile, Dialer: dialer}) != nil {
			return reject("client-config")
		}
		if sdk.Start() != nil {
			_ = sdk.Stop()
			return reject("client-start")
		}
	}
	connections := make([]net.Conn, 0, *concurrency+1)
	defer func() {
		closeTogether(connections)
		if sdk != nil {
			_ = sdk.Stop()
		}
	}()
	dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
	defer dialCancel()
	for i := 0; i < *concurrency+1; i++ {
		var c net.Conn
		var err error
		if *direct {
			c, err = (&net.Dialer{Timeout: 10 * time.Second}).DialContext(dialCtx, "tcp", *target)
		} else {
			address := model.NetAddrSpec{Net: "tcp"}
			_ = address.AddrSpec.From(*target)
			c, err = sdk.DialContext(dialCtx, address)
		}
		if err != nil {
			if c != nil {
				_ = c.Close()
			}
			return reject("connect")
		}
		connections = append(connections, c)
	}
	// 取消时关闭拥有的全部会话，唤醒阻塞 I/O；主路径仍等待所有工作者返回。
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
			closeTogether(connections)
		case <-watchDone:
		}
	}()
	warmStarted := time.Now()
	warmEnd := warmStarted.Add(*warmup)
	warmResults := make(chan error, len(connections))
	for i, c := range connections {
		go func(i int, c net.Conn) {
			size := *blockSize
			if i == *concurrency {
				size = *latencySize
			}
			sent, received := payload(size, i), make([]byte, size)
			var seq uint64
			for time.Now().Before(warmEnd) {
				_, _, err := exchange(c, sent, received, seq, time.Now().Add(*ioBudget))
				seq++
				if err != nil {
					warmResults <- err
					return
				}
				if i == *concurrency {
					_ = waitUntil(ctx, time.Now().Add(10*time.Millisecond))
				}
			}
			warmResults <- nil
		}(i, c)
	}
	warmOK := true
	for range connections {
		if <-warmResults != nil {
			warmOK = false
		}
	}
	if !warmOK || ctx.Err() != nil {
		return reject("warmup")
	}
	warmFinished := time.Now()
	planned := time.Now().Add(500 * time.Millisecond)
	if *startAt != 0 {
		planned = time.UnixMilli(*startAt)
	}
	if !planned.After(time.Now()) {
		return reject("start-at-expired")
	}
	emit(map[string]any{"event": "ready", "mode": "load", "label": *label, "scheduled_start_unix_ns": planned.UnixNano(), "warmup_seconds": warmup.Seconds(), "actual_warmup_seconds": warmFinished.Sub(warmStarted).Seconds(), "streams": len(connections), "direct": *direct, "upstream_sha": upstreamSHA})
	if !waitUntil(ctx, planned) {
		return reject("cancel-before-start")
	}
	started := time.Now()
	end := started.Add(*duration)
	cpuStart := cpuNow()
	emit(map[string]any{"event": "start", "mode": "load", "label": *label, "start_unix_ns": started.UnixNano(), "end_unix_ns": end.UnixNano()})
	results := make(chan flowResult, len(connections))
	for i, c := range connections {
		go func(i int, c net.Conn) {
			size := *blockSize
			if i == *concurrency {
				size = *latencySize
			}
			results <- runFlow(ctx, c, i, size, i == *concurrency, started, end, *drain, *ioBudget)
		}(i, c)
	}
	_ = waitUntil(ctx, end)
	cpuEndAt := time.Now()
	cpuEnd := cpuNow()
	flowResults := make([]flowResult, 0, len(connections))
	bulkHist, probeHist := histogram{}, histogram{}
	seconds := make([]secondCounts, int((*duration+time.Second-1)/time.Second))
	for i := range seconds {
		seconds[i].Second = i
	}
	var bulkBytes, probeBytes, bulkOps, probeOps, lateBytes, lateOps, failures, timeouts, mismatches uint64
	for range connections {
		r := <-results
		flowResults = append(flowResults, r)
		failures += r.Errors
		timeouts += r.Timeouts
		mismatches += r.Mismatches
		lateBytes += r.LateBytes
		lateOps += r.LateOps
		if r.Probe {
			probeBytes += r.Bytes
			probeOps += r.Ops
			probeHist.merge(&r.RTT)
		} else {
			bulkBytes += r.Bytes
			bulkOps += r.Ops
			bulkHist.merge(&r.RTT)
		}
		for i := range seconds {
			seconds[i].BulkBytes += r.Seconds[i].BulkBytes
			seconds[i].BulkOps += r.Seconds[i].BulkOps
			seconds[i].ProbeBytes += r.Seconds[i].ProbeBytes
			seconds[i].ProbeOps += r.Seconds[i].ProbeOps
		}
	}
	finished := time.Now()
	cpuAvailable := cpuStart.User >= 0 && cpuEnd.User >= 0
	status := "pass"
	if failures > 0 || ctx.Err() != nil || bulkOps == 0 || probeOps == 0 || !cpuAvailable {
		status = "fail"
	}
	cpuUser, cpuSystem := cpuEnd.User-cpuStart.User, cpuEnd.System-cpuStart.System
	for _, sample := range seconds {
		emit(map[string]any{"event": "second", "label": *label, "counts": sample})
	}
	profile := map[string]any{"transport": "TCP", "multiplexing": "MULTIPLEXING_LOW", "handshake": "HANDSHAKE_STANDARD", "low_entropy": 0, "mtu": 1400}
	emit(map[string]any{"event": "final", "mode": "load", "status": status, "label": *label, "direct": *direct, "upstream_sha": upstreamSHA, "profile": profile,
		"start_unix_ns": started.UnixNano(), "end_unix_ns": end.UnixNano(), "drain_finished_unix_ns": finished.UnixNano(), "duration_seconds": duration.Seconds(), "cpu_window_seconds": cpuEndAt.Sub(started).Seconds(),
		"bulk_ack_bytes": bulkBytes, "bulk_completions": bulkOps, "probe_ack_bytes": probeBytes, "probe_completions": probeOps, "late_ack_bytes": lateBytes, "late_completions": lateOps,
		"effective_one_way_mbps": float64(bulkBytes) * 8 / duration.Seconds() / 1e6, "effective_bidirectional_mbps": float64(bulkBytes) * 16 / duration.Seconds() / 1e6,
		"bulk_rtt": bulkHist.summary(), "probe_rtt": probeHist.summary(), "errors": failures, "timeouts": timeouts, "mismatches": mismatches,
		"tcp_underlays_opened": dialer.opened.Load(), "tcp_underlays_active_before_close": dialer.active.Load(), "client_cpu_available": cpuAvailable, "client_cpu_user_seconds": cpuUser, "client_cpu_system_seconds": cpuSystem, "client_cpu_percent_one_core_basis": (cpuUser + cpuSystem) / cpuEndAt.Sub(started).Seconds() * 100,
		"concurrency": *concurrency, "block_size": *blockSize, "latency_size": *latencySize, "flows": flowResults})
	if *hold > 0 {
		_ = waitUntil(ctx, time.Now().Add(*hold))
	}
	if status != "pass" {
		return 1
	}
	return 0
}
