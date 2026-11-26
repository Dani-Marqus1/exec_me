# exec_me

A small, **terminal-only reconnaissance and service-enumeration CLI** written in Go. Built for authorized penetration tests, personal labs, and learning how network services behave. No report files, databases, or vulnerability exploitation.

## Features

- Concurrent TCP **connect** scanning (1–65,535; one target per invocation)
- Common ports or custom comma-separated ports and ranges
- FTP greeting, **anonymous login test**, `PWD`, and a bounded passive `LIST`
- SMB **no-credentials share enumeration** through the optional `smbclient` binary
- Optional read-only `ls` test on up to five SMB disk shares
- HTTP(S) status, server headers, page title, missing basic security headers
- TLS version, certificate expiry, and certificate trust validation
- SSH, Telnet, SMTP, POP3, and IMAP banners when servers provide them
- DNS IP/MX records; optional *passive* certificate-transparency lookup via crt.sh
- **Optional Gobuster integration** for directory and file discovery on known HTTP(S) ports, with live terminal results
- Color terminal output; no output files

> A port-to-service mapping is a **guess**, not proof of the service. SMB shares visible without supplied credentials do **not** prove anonymous read or write permissions. A missing HTTP header is an observation, not automatically an exploitable vulnerability.

## Requirements

- Go **1.22+**
- Linux, macOS or Windows for most checks
- **Optional:** `smbclient` (Samba client) for SMB enumeration; on Kali: `sudo apt update && sudo apt install smbclient`
- **Optional:** `gobuster` for HTTP(S) directory discovery; on Kali: `sudo apt install gobuster dirb`. By default, the tool checks common Kali wordlist paths or you can specify your own.
- Internet access only for the **optional** `--subdomains` crt.sh query

## Build

```bash
unzip exec_me_source.zip
cd exec_me
go test ./...
go build -o exec_me .
./exec_me --help
```

On Windows:

```powershell
go test ./...
go build -o exec_me.exe .
.\exec_me.exe --help
```

## Command help and service catalog

Run `./exec_me -help` or `./exec_me scan -help` to see every option,
example commands, and a table showing the services with implemented
checks. Run `./exec_me services` for a shorter service-only summary.

The catalog distinguishes deep checks from port labels: for example,
RDP and LDAP ports can be discovered, but currently have no dedicated
protocol-specific enumeration module. Gobuster is opt-in and requires
its external executable and a wordlist.

## Examples

```bash
# Default list of common TCP ports (and service checks)
./exec_me scan -t 192.168.56.10

# Custom port range and more workers
./exec_me scan -t 192.168.56.10 -p 1-1000 -c 150

# Only connectivity scanning; no subsequent service checks
./exec_me scan -t 192.168.56.10 -p 21,22,80,443,445 -enum=false

# Enumerate SMB shares and optionally test read-only top-level listing
./exec_me scan -t 192.168.56.10 -p 445 -smb-list

# Passive subdomains from crt.sh (no scans of discovered subdomains)
./exec_me scan -t example.test -p 80,443 -subdomains

# Run Gobuster automatically against discovered known HTTP(S) ports
./exec_me scan -t 192.168.56.10 -p 80,443,8080 -gobuster

# Specify a wordlist and optional extension checks
./exec_me scan -t 192.168.56.10 -p 80,443 -gobuster -gobuster-wordlist /usr/share/wordlists/dirb/common.txt -gobuster-ext php,txt

# Use this only for self-signed HTTPS lab certificates
./exec_me scan -t 192.168.56.10 -p 443 -gobuster -gobuster-insecure

# Disable terminal colors
./exec_me scan -t 127.0.0.1 -p 1-1024 -color=false
```

## Limitations and safety design

- **One explicit target only**, no CIDR ranges, credential lists, spraying, or automatically scanning discovered hosts.
- Gobuster is **opt-in** (`-gobuster`) because directory discovery sends many additional requests. It runs only on known web ports (80, 443, 8000, 8080, 8443, 8888, 5985, 5986, 9200) when those ports are open; a service running on a nonstandard port may need separate testing. Gobuster runs with up to 30 threads and a bounded per-service timeout, and output is printed only to the terminal. `-gobuster-insecure` disables HTTPS certificate verification for the Gobuster subprocess only. No wordlist or Gobuster executable is bundled.
- TCP connect scans, not SYN/UDP scans. Not a substitute for Nmap or protocol-specific scanners.
- Target host is used for FTP passive data connections; PASV-advertised hosts are intentionally ignored.
- FTP anonymous access sends one standard anonymous credential pair, not a password brute force.
- SMB attempts use `smbclient -N -U %`, i.e. no supplied credentials. Servers may map these requests to guest; guest vs null session is **not reliably identified** by this check. `--smb-list` only tests `ls` against up to five shares; no file downloads or writes.
- HTTPS verification is enforced for HTTP requests. A **separate metadata-only TLS inspection** intentionally permits a handshake with an untrusted certificate so it can display certificate details and then independently validates the chain and hostname.
- HTTP requests do not follow redirects; this avoids scanning a different host outside the designated target. Page reads are capped at 64 KiB.
- The passive crt.sh lookup makes a request to a third-party service; opt-in only.
- Concurrency capped at 500. Timeouts and response sizes are bounded. No stealth/evasion features.
- For anything besides owned lab hosts, verify authorization and scope before testing. Network services may log every connection.

## Project layout

```
exec_me/
├── main.go        CLI and execution flow
├── scan.go        port parser, target validation and concurrent TCP scanner
├── enumerate.go   service dispatch and banners
├── ftp.go         anonymous FTP client and read-only listing
├── smb.go         smbclient-based unauthenticated share checks
├── http.go        HTTP metadata probe
├── gobuster.go    optional external Gobuster integration
├── tls.go         TLS metadata and trust checks
├── dns.go         DNS and passive certificate transparency lookup
├── output.go      terminal formatting and sanitization
├── scan_test.go   basic tests
└── go.mod
```

## Next practical improvements

Full protocol fingerprinting (instead of port guesses), integration tests with a disposable FTP/SMB test server, optional IPv4-only resolution, structured scan result types, connection retry and advanced logging.

Released for learning and authorized security testing. Do not target systems without authorization.

## Authentication (v0.5.0)

One host, one supplied username/password, sequential checks on discovered compatible ports. No password lists or retries. SMB uses only one endpoint (445 preferred). Account lockout can be shared across protocols; confirm the lockout policy first. SSH/LDAP authentication is not implemented. WinRM uses NTLM with a read-only WS-Management configuration Get; no remote shell or command execution. HTTPS (5986) is preferred and HTTP (5985) requires explicit opt-in. A successful Get proves access to the resource; insufficient permissions or transport errors may be UNVERIFIED even with valid credentials. HTTP Basic is checked only if the root endpoint advertises it. SMB success is marked UNVERIFIED because guest fallback is possible.

```bash
./exec_me auth -help
read -rsp 'Lab password: ' EXEC_ME_PASSWORD; echo; export EXEC_ME_PASSWORD
./exec_me auth -t 192.168.56.10 -u alice -domain LAB
unset EXEC_ME_PASSWORD
```

FTP and unencrypted HTTP require `-allow-cleartext` (isolated lab only). HTTPS requires trusted certificates. `-p` is accepted but can expose the password in shell history and process arguments; prefer the environment variable. SMB requires `smbclient`. No report files are generated.

### WinRM (optional)

On Kali, install `python3-winrm` using `sudo apt install python3-winrm`. The Go executable embeds the Python helper and does not require additional Go dependencies.

```bash
read -rsp 'Lab password: ' EXEC_ME_PASSWORD; echo; export EXEC_ME_PASSWORD
./exec_me auth -t 192.168.56.10 -u alice -domain LAB -allow-winrm-http
unset EXEC_ME_PASSWORD
```

Ports 5985 and 5986 are already in the common list. If both are open, only 5986 is tested; there is no fallback after failure. HTTPS certificate verification is enforced. HTTP uses pywinrm NTLM message encryption (auto); NTLM over HTTP does not authenticate the server, so only enable it in a trusted isolated lab. A Negotiate challenge is not proof that the server accepts NTLM. Kerberos-only servers are not supported. The helper is not a shell or command runner.

Go tests cover endpoint challenge handling; live Windows authentication and the optional pywinrm dependency have not been tested in the build environment.
