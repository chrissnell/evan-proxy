package logging

import (
	"encoding/json"
	"net"
)

// JSONUDPBackend sends JSON-encoded log messages as UDP datagrams.
// Fire-and-forget: errors are silently dropped.
type JSONUDPBackend struct {
	conn *net.UDPConn
}

func NewJSONUDPBackend(addr string) (*JSONUDPBackend, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	return &JSONUDPBackend{conn: conn}, nil
}

func (b *JSONUDPBackend) Log(msg Message) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	b.conn.Write(data)
}

func (b *JSONUDPBackend) Close() error {
	return b.conn.Close()
}
