package naive

import "net"

// ReferencePadding 只导出固定上游的现有 codec，供独立测试对端使用。
func ReferencePadding(conn net.Conn) net.Conn { return &naiveConn{Conn: conn} }
