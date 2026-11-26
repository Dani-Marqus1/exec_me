package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const version = "0.5.0"

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "-help" || os.Args[1] == "help" {
		printHelp(os.Stdout)
		return
	}
	if os.Args[1] == "auth" {
		authCommand(os.Args[2:])
		return
	}
	if os.Args[1] == "services" {
		printServices(os.Stdout)
		return
	}
	if os.Args[1] == "--version" || os.Args[1] == "-version" || os.Args[1] == "version" {
		fmt.Println("exec_me", version)
		return
	}
	if os.Args[1] != "scan" {
		fmt.Fprintln(os.Stderr, "Unknown command:", os.Args[1])
		printHelp(os.Stderr)
		os.Exit(2)
	}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	target := fs.String("t", "", "IP or hostname")
	portSpec := fs.String("p", "common", "ports")
	concurrency := fs.Int("c", 100, "workers")
	timeout := fs.Duration("timeout", 1200*time.Millisecond, "connect timeout")
	enumerate := fs.Bool("enum", true, "service enumeration")
	smbList := fs.Bool("smb-list", false, "list top-level SMB entries")
	subdomains := fs.Bool("subdomains", false, "passive crt.sh lookup")
	color := fs.Bool("color", true, "ANSI colors")
	gobuster := fs.Bool("gobuster", false, "run gobuster directory discovery")
	gobusterWordlist := fs.String("gobuster-wordlist", "", "gobuster directory wordlist")
	gobusterThreads := fs.Int("gobuster-threads", 10, "gobuster concurrency")
	gobusterTimeout := fs.Duration("gobuster-timeout", 3*time.Minute, "gobuster timeout per service")
	gobusterExt := fs.String("gobuster-ext", "", "gobuster file extensions")
	gobusterInsecure := fs.Bool("gobuster-insecure", false, "gobuster -k skip TLS certificate validation")
	fs.Usage = func() { printHelp(os.Stdout) }
	if err := fs.Parse(os.Args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		os.Exit(2)
	}

	if err := validateTarget(*target); err != nil {
		fatal("invalid target: %v", err)
	}
	if *concurrency < 1 || *concurrency > 500 {
		fatal("workers must be 1-500")
	}
	if *timeout < 100*time.Millisecond || *timeout > 30*time.Second {
		fatal("timeout must be between 100ms and 30s")
	}
	if *gobusterThreads < 1 || *gobusterThreads > 30 {
		fatal("gobuster threads must be 1-30")
	}
	if *gobusterTimeout < 10*time.Second || *gobusterTimeout > 30*time.Minute {
		fatal("gobuster timeout must be 10s-30m")
	}
	if *gobusterExt != "" {
		for _, ext := range strings.Split(*gobusterExt, ",") {
			if ext == "" || strings.Trim(ext, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != "" {
				fatal("invalid gobuster extension list")
			}
		}
	}
	ports, err := parsePorts(*portSpec)
	if err != nil {
		fatal("invalid ports: %v", err)
	}
	out := printer{color: *color}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	// IPs remain literal. Hostnames are resolved by the Go dialer and checks.
	out.header("exec_me v%s | target %s | %d ports | %d workers", version, *target, len(ports), *concurrency)
	started := time.Now()
	if net.ParseIP(strings.Trim(*target, "[]")) == nil {
		showDNS(ctx, *target, out)
		if *subdomains {
			showSubdomains(ctx, *target, out)
		}
	} else if *subdomains {
		out.note("passive subdomains require a DNS name; skipped")
	}
	out.note("Scanning TCP ports (connect scan)...")
	openPorts := scanPorts(ctx, *target, ports, *concurrency, *timeout)
	if len(openPorts) == 0 {
		out.note("No open TCP ports detected in the selected range")
	}
	for _, port := range openPorts {
		out.open(port, portName(port))
	}
	if *enumerate || *gobuster {
		gopts := gobusterOptions{enabled: *gobuster, wordlist: *gobusterWordlist, threads: *gobusterThreads, timeout: *gobusterTimeout, extensions: *gobusterExt, insecure: *gobusterInsecure}
		for _, port := range openPorts {
			if *enumerate {
				enumeratePort(ctx, *target, port, out, *smbList)
			}
			if isWebPort(port) {
				runGobuster(ctx, *target, port, isSecureWebPort(port), out, gopts)
			}
		}
	}
	out.header("Done | %d/%d open | %s elapsed", len(openPorts), len(ports), time.Since(started).Round(time.Millisecond))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[-] "+format+"\n", args...)
	os.Exit(2)
}
