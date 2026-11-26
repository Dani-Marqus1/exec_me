package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	ports, err := parsePorts("443,80,80,1000-1002")
	if err != nil {
		t.Fatal(err)
	}
	got := []int{80, 443, 1000, 1001, 1002}
	if len(ports) != len(got) {
		t.Fatalf("got %v", ports)
	}
	for i := range got {
		if ports[i] != got[i] {
			t.Fatalf("got %v", ports)
		}
	}
	for _, invalid := range []string{"", "0", "65536", "8-5", "1-2-3", "abc", "1,,2"} {
		if _, err := parsePorts(invalid); err == nil {
			t.Errorf("accepted invalid port spec %q", invalid)
		}
	}
}
func TestValidateTarget(t *testing.T) {
	for _, valid := range []string{"localhost", "test.lab", "192.168.56.10", "::1", "2001:db8::1"} {
		if err := validateTarget(valid); err != nil {
			t.Errorf("rejected valid %q: %v", valid, err)
		}
	}
	for _, invalid := range []string{"", "https://test.lab", "example.org:22", "192.168.1.0/24", "foo bar", "-invalid", "bad..host"} {
		if err := validateTarget(invalid); err == nil {
			t.Errorf("accepted invalid %q", invalid)
		}
	}
}
func TestSMBParse(t *testing.T) {
	text := "Disk|public|A public share\nIPC|IPC$|IPC Service\nDisk|public|duplicate\nPrinter|print$|Printer drivers\n"
	got := parseSMBShares(text)
	if len(got) != 3 || got[0].name != "public" || got[1].name != "IPC$" || got[2].name != "print$" {
		t.Fatalf("unexpected: %#v", got)
	}
}
func TestFTPDataPort(t *testing.T) {
	checks := []struct {
		code int
		msg  string
		want int
	}{
		{229, "Entering Extended Passive Mode (|||49152|)", 49152},
		{227, "Entering Passive Mode (10,10,10,10,195,80)", 50000},
	}
	for _, test := range checks {
		port, err := parseFTPDataPort(test.code, test.msg)
		if err != nil || port != test.want {
			t.Errorf("%q: %d, %v", test.msg, port, err)
		}
	}
	if _, err := parseFTPDataPort(229, "bad"); err == nil {
		t.Fatal("bad EPSV accepted")
	}
}
func TestSanitizeTerminalOutput(t *testing.T) {
	cleaned := clean("Hello\x1b[31mWorld\x1b[0m\n")
	if strings.ContainsRune(cleaned, '\x1b') || strings.ContainsRune(cleaned, '\n') {
		t.Fatalf("unsafe output: %q", cleaned)
	}
}
func TestScanLocalTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local sockets unavailable: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	open := scanPorts(context.Background(), "127.0.0.1", []int{port}, 2, 350*time.Millisecond)
	if len(open) != 1 || open[0] != port {
		t.Fatalf("expected port %s open, got %v", strconv.Itoa(port), open)
	}
}

func TestGobusterArgumentConstruction(t *testing.T) {
	opts := gobusterOptions{enabled: true, threads: 7, insecure: true, extensions: "php,txt"}
	args := gobusterArgs("https://127.0.0.1:8443/", "/tmp/common.txt", opts)
	joined := strings.Join(args, " ")
	for _, expected := range []string{"dir", "-u https://127.0.0.1:8443/", "-w /tmp/common.txt", "-t 7", "-k", "-x php,txt", "--no-progress"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing %q in %q", expected, joined)
		}
	}
}

func TestGobusterWebPorts(t *testing.T) {
	for _, port := range []int{80, 443, 8000, 8080, 8443, 8888, 5985, 5986, 9200} {
		if !isWebPort(port) {
			t.Fatalf("expected %d to be a web port", port)
		}
	}
	if isWebPort(445) || isSecureWebPort(80) {
		t.Fatal("incorrect web port classification")
	}
}

func TestResolveWebWordlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(path, []byte("admin\nlogin\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveWebWordlist(path)
	if err != nil || got != path {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := resolveWebWordlist(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing wordlist accepted")
	}
}
