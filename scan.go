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

// Conventional TCP port assignments, not protocol fingerprints.
var knownServices = map[int]string{
	7: "Echo", 9: "Discard", 13: "Daytime", 19: "CHARGEN",
	20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
	37: "Time", 43: "WHOIS", 49: "TACACS+", 53: "DNS", 70: "Gopher",
	79: "Finger", 80: "HTTP", 88: "Kerberos", 109: "POP2", 110: "POP3",
	111: "RPCBind", 113: "Ident", 119: "NNTP", 135: "MSRPC",
	139: "NetBIOS/SMB", 143: "IMAP", 179: "BGP", 199: "SMUX",
	389: "LDAP", 427: "SLP", 443: "HTTPS", 445: "SMB", 464: "Kerberos password change",
	465: "SMTPS", 512: "rexec", 513: "rlogin", 514: "rsh", 515: "LPD",
	548: "AFP", 554: "RTSP", 563: "NNTPS", 587: "SMTP", 593: "RPC over HTTP",
	631: "IPP", 636: "LDAPS", 873: "rsync", 902: "VMware authd",
	989: "FTPS-data", 990: "FTPS", 993: "IMAPS", 995: "POP3S",
	1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
	1883: "MQTT", 2049: "NFS", 2082: "cPanel", 2083: "cPanel HTTPS",
	2181: "ZooKeeper", 2375: "Docker API", 2376: "Docker API TLS",
	2379: "etcd client", 2380: "etcd peer", 3000: "HTTP-alt (common)",
	3128: "HTTP proxy (common)", 3268: "LDAP Global Catalog", 3269: "LDAPS Global Catalog",
	3306: "MySQL", 3389: "RDP", 4369: "Erlang EPMD", 5000: "HTTP-alt (common)",
	5060: "SIP", 5061: "SIP TLS", 5222: "XMPP client", 5269: "XMPP server",
	5432: "PostgreSQL", 5671: "AMQP TLS", 5672: "AMQP", 5900: "VNC",
	5985: "WinRM/HTTP", 5986: "WinRM/HTTPS", 5984: "CouchDB", 6379: "Redis",
	6443: "Kubernetes API (common)", 6667: "IRC", 7000: "Cassandra internode (common)",
	7001: "WebLogic (common)", 8000: "HTTP-alt", 8009: "AJP", 8080: "HTTP-alt",
	8081: "HTTP-alt (common)", 8088: "HTTP-alt (common)", 8443: "HTTPS-alt",
	8883: "MQTT TLS", 8888: "HTTP-alt", 9000: "Application service (varies)",
	9042: "Cassandra CQL", 9092: "Kafka (common)", 9100: "Raw printing",
	9200: "Elasticsearch", 9300: "Elasticsearch transport", 9389: "AD Web Services",
	10000: "Webmin (common)", 11211: "Memcached", 15672: "RabbitMQ management (common)",
	27017: "MongoDB", 27018: "MongoDB (common)",
}

func portName(port int) string {
	if name, ok := knownServices[port]; ok {
		return name
	}
	return "unknown"
}

// A high port alone does not identify RPC. Use the existing open-port
// observations only, and retain an explicitly tentative label.
func scanPortName(port int, openPorts []int) string {
	if name := portName(port); name != "unknown" {
		return name
	}
	if port < 49152 || port > 65535 {
		return "unknown"
	}
	var rpc, smb, directory bool
	for _, p := range openPorts {
		switch p {
		case 135:
			rpc = true
		case 445:
			smb = true
		case 88, 389, 593, 3268, 9389:
			directory = true
		}
	}
	if rpc && smb && directory {
		return "Possible Dynamic RPC (unverified)"
	}
	return "unknown"
}
