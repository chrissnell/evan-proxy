package main

import "testing"

func TestIsLoopbackListen(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:6060", true},
		{"127.0.0.5:6060", true},
		{"[::1]:6060", true},
		{"localhost:6060", true},
		{"0.0.0.0:6060", false},
		{"[::]:6060", false},
		{"192.168.1.10:6060", false},
		{":6060", false},
		{"6060", false}, // missing host:port separator
		{"garbage", false},
	}
	for _, tt := range tests {
		if got := isLoopbackListen(tt.addr); got != tt.want {
			t.Errorf("isLoopbackListen(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}
