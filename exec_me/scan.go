package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const commonPorts = "21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2049,2375,3306,3389,5432,5900,5985,5986,6379,8000,8080,8443,8888,9200,27017"

var hostnamePattern = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.?$`)

func validateTarget(target string) error {
	if target == "" {
		return errors.New("use -t to specify a target")
	}
	if net.ParseIP(target) != nil {
		return nil
	}
	if strings.ContainsAny(target, "/:@\\\n\r\t ") {
		return errors.New("provide only one host or IP, without URL scheme, port or CIDR")
	}
	if len(target) > 253 || !hostnamePattern.MatchString(target) {
		return errors.New("must be a valid IP or DNS hostname")
	}
	for _, label := range strings.Split(strings.TrimSuffix(target, "."), ".") {
		if len(label) > 63 {
			return errors.New("hostname label too long")
		}
	}
	return nil
}

func parsePorts(spec string) ([]int, error) {
	if strings.EqualFold(spec, "common") {
		spec = commonPorts
	}
	seen := make(map[int]bool)
	for _, field := range strings.Split(spec, ",") {
		part := strings.TrimSpace(field)
		if part == "" {
			return nil, fmt.Errorf("empty port entry")
		}
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid range %q", part)
		}
		a, err := strconv.Atoi(bounds[0])
		if err != nil || a < 1 || a > 65535 {
			return nil, fmt.Errorf("invalid port %q", bounds[0])
		}
		b := a
		if len(bounds) == 2 {
			b, err = strconv.Atoi(bounds[1])
			if err != nil || b < a || b > 65535 {
				return nil, fmt.Errorf("invalid range %q", part)
			}
		}
		for p := a; p <= b; p++ {
			seen[p] = true
		}
	}
	if len(seen) == 0 {
		return nil, errors.New("no ports")
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

func scanPorts(ctx context.Context, target string, ports []int, workers int, timeout time.Duration) []int {
	jobs := make(chan int)
	results := make(chan int, workers)
	var wg sync.WaitGroup
	if workers > len(ports) {
		workers = len(ports)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := net.Dialer{Timeout: timeout}
			for p := range jobs {
				addr := net.JoinHostPort(target, strconv.Itoa(p))
				conn, err := dialer.DialContext(ctx, "tcp", addr)
				if err == nil {
					conn.Close()
					results <- p
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, p := range ports {
			select {
			case jobs <- p:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	var open []int
	for p := range results {
		open = append(open, p)
	}
	sort.Ints(open)
	return open
}

var knownServices = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPCBind",
	135: "MSRPC", 139: "NetBIOS/SMB", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
	587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
	2049: "NFS", 2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
	5985: "WinRM/HTTP", 5986: "WinRM/HTTPS", 6379: "Redis", 8000: "HTTP-alt", 8080: "HTTP-alt",
	8443: "HTTPS-alt", 8888: "HTTP-alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

func portName(port int) string {
	if name, ok := knownServices[port]; ok {
		return name
	}
	return "unknown"
}
