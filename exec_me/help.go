package main

import (
	"fmt"
	"io"
)

// printHelp is intentionally plain text so it also works without ANSI support,
// in SSH sessions, and when piped through less or grep.
func printHelp(w io.Writer) {
	fmt.Fprintf(w, `exec_me v%s  |  Reconnaissance & service enumeration

USAGE
  exec_me scan -t <target> [options]
  exec_me auth -t <target> -u <user> [options]
  exec_me services
  exec_me --version
  exec_me -help

SUPPORTED SERVICES
  PORT(S)                SERVICE                 AUTOMATED CHECKS
  21                     FTP                     Greeting, anonymous login, PWD, passive LIST
  22                     SSH                     Server banner
  23                     Telnet                  Server banner (if provided)
  25, 587                SMTP                    Server banner (if provided)
  110                    POP3                    Server banner (if provided)
  143                    IMAP                    Server banner (if provided)
  139, 445               SMB                     Unauthenticated share listing via smbclient
  80, 8000, 8080, 8888   HTTP                    Status, server headers, title, basic header checks
  5985, 9200             HTTP / API              Same HTTP metadata checks
  443, 8443              HTTPS                   HTTP checks + TLS certificate details
  5986                   WinRM / HTTPS           HTTP checks + TLS certificate details
  465, 636, 993, 995     TLS services            TLS details / certificate validation

  Other ports can still be TCP-scanned, including DNS (53), LDAP (389),
  RDP (3389), MySQL (3306), PostgreSQL (5432), Redis (6379), and more.
  These are currently PORT LABELS ONLY; no protocol-specific checks run.
  Port labels are educated guesses, not confirmed service fingerprints.

AUTHENTICATION
  exec_me auth -help     Single-credential checks on discovered FTP, SMB, HTTP Basic and WinRM NTLM endpoints
                         Cleartext FTP/HTTP requires -allow-cleartext.
                         WinRM needs python3 + pywinrm; HTTP requires -allow-winrm-http.
                         SSH, LDAP and other authentication protocols are not implemented.

OPTIONAL MODULES
  FTP anonymous check    Automatic with service enumeration (port 21)
  SMB share listing      Automatic on ports 139/445; needs smbclient installed
  SMB directory listing  Enable with -smb-list (read-only, up to 5 shares)
  Gobuster dir search    Enable with -gobuster on supported HTTP(S) ports;
                         needs gobuster and a wordlist installed
  DNS records            A/AAAA and MX lookup for DNS hostname targets
  Passive subdomains     Enable with -subdomains for crt.sh lookup

SCAN OPTIONS
  -t TARGET              IP address or DNS hostname (required; one host only)
  -p PORTS               "common", 1-1000, or 21,22,80,443 (default: common)
  -c WORKERS             Concurrent TCP connections (default: 100; max: 500)
  -timeout DURATION      TCP connection timeout (default: 1200ms)
  -enum                  Run service checks (default: true; -enum=false to disable)
  -smb-list              Try read-only listing of up to five SMB shares
  -subdomains            Passive certificate-transparency lookup (opt-in)
  -color                 Color output (default: true; -color=false to disable)

GOBUSTER OPTIONS (OPT-IN)
  -gobuster              Run directory discovery on detected web ports
  -gobuster-wordlist P   Custom wordlist path (otherwise checks Kali defaults)
  -gobuster-threads N    HTTP workers for Gobuster (default: 10; max: 30)
  -gobuster-timeout D    Time limit per web port (default: 3m)
  -gobuster-ext LIST     Extensions, e.g. php,txt,html
  -gobuster-insecure     Skip TLS certificate checks in Gobuster (labs only)

EXAMPLES
  exec_me scan -t 192.168.56.10
  exec_me scan -t 192.168.56.10 -p 1-1000 -c 150
  exec_me scan -t 192.168.56.10 -p 21,445 -smb-list
  exec_me scan -t 192.168.56.10 -p 80,443,8080 -gobuster
  exec_me scan -t lab.example.test -p 80,443 -subdomains
  exec_me scan -t 192.168.56.10 -enum=false
  exec_me scan -help

NOTES
  * All findings print in the terminal; no report files are generated.
  * Scan only systems you own or are explicitly authorized to test.
`, version)
}

func printServices(w io.Writer) {
	fmt.Fprintln(w, `exec_me: service checks

  FTP (21)               Anonymous login, PWD, passive LIST
  SSH (22)               Read server banner
  Telnet (23)            Read server banner
  SMTP (25,587)          Read server banner
  POP3 (110)             Read server banner
  IMAP (143)             Read server banner
  SMB (139,445)          List unauthenticated shares (smbclient required)
  HTTP (80,8000,8080,
        8888,5985,9200)  Status, headers, HTML title
  HTTPS (443,8443,5986)  HTTP checks plus TLS metadata
  TLS (465,636,993,995)  Certificate and version information
  DNS (hostname input)  Resolve IP and MX records

  Optional:
    -smb-list            Try read-only SMB directory listing
    -gobuster            Web directory enumeration (external tool)
    -subdomains          Passive crt.sh lookup

  Other TCP ports: open/closed status and best-effort name only.
  Run 'exec_me -help' for all flags and examples.`)
}
