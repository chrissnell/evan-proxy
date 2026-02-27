package logging

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestJSONUDPBackend(t *testing.T) {
	// Start a UDP listener
	laddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUDP("udp", laddr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	addr := listener.LocalAddr().String()
	backend, err := NewJSONUDPBackend(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	// Send an access log entry
	ts := time.Date(2026, 2, 20, 14, 30, 0, 0, time.UTC)
	backend.Log(Message{Access: &Entry{
		Timestamp: ts, ClientIP: "10.0.0.1", Method: "CONNECT",
		Host: "example.com:443", User: "alice", Status: 200,
	}})

	// Read the datagram
	buf := make([]byte, 4096)
	listener.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := listener.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf[:n], &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, buf[:n])
	}

	access, ok := parsed["Access"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing Access field in: %s", buf[:n])
	}
	if access["client_ip"] != "10.0.0.1" {
		t.Errorf("client_ip = %v", access["client_ip"])
	}
	if access["method"] != "CONNECT" {
		t.Errorf("method = %v", access["method"])
	}
}

func TestJSONUDPBackendServerMessage(t *testing.T) {
	laddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUDP("udp", laddr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	backend, err := NewJSONUDPBackend(listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	backend.Log(Message{Server: &ServerMessage{
		Timestamp: time.Now(), Level: "error", Component: "proxy", Text: "something broke",
	}})

	buf := make([]byte, 4096)
	listener.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := listener.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf[:n], &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	server, ok := parsed["Server"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing Server field in: %s", buf[:n])
	}
	if server["level"] != "error" {
		t.Errorf("level = %v", server["level"])
	}
	if server["component"] != "proxy" {
		t.Errorf("component = %v", server["component"])
	}
}
