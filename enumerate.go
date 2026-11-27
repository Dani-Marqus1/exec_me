package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func enumeratePort(ctx context.Context, target string, port int, out printer, smbList bool) {
	switch port {
	case 21:
		checkFTP(ctx, target, port, out)
	case 139, 445:
		checkSMB(ctx, target, port, out, smbList)
	case 80, 8000, 8080, 8888, 5985, 9200:
		checkHTTP(ctx, target, port, false, out)
	case 443, 8443, 5986:
		checkTLS(ctx, target, port, out)
		checkHTTP(ctx, target, port, true, out)
	case 22, 23, 25, 110, 143, 587:
		checkBanner(ctx, target, port, out)
	case 465, 636, 993, 995:
		checkTLS(ctx, target, port, out)
	default:
		// An open port is not automatically proof of any particular protocol.
	}
}

func checkBanner(ctx context.Context, target string, port int, out printer) {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(target, strconv.Itoa(port)))
	if err != nil {
		out.warn(port, "Banner read: "+err.Error())
		return
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		out.finding(port, "Banner", "not available (server may wait for client)")
		return
	}
	banner := strings.TrimSpace(line)
	if banner != "" {
		out.finding(port, "Banner", banner)
	}
}

func tcpAddress(target string, port int) string { return net.JoinHostPort(target, strconv.Itoa(port)) }
func baseURL(target string, port int, secure bool) string {
	scheme := "http"
	if secure {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/", scheme, tcpAddress(target, port))
}

func isWebPort(port int) bool {
	switch port {
	case 80, 443, 8000, 8080, 8443, 8888, 5985, 5986, 9200:
		return true
	default:
		return false
	}
}

func isSecureWebPort(port int) bool {
	return port == 443 || port == 8443 || port == 5986
}
