# exec_me

**Automated Network Reconnaissance & Service Enumeration**

## Overview

**exec_me** is a lightweight, terminal-based reconnaissance tool written in Go, designed to streamline the initial enumeration phase of penetration testing.

It combines concurrent port scanning, service enumeration, web directory discovery and credential validation into a single command-line interface, reducing the need to manually switch between multiple tools.

## Features

- Concurrent TCP port scanning with up to 500 workers.
- Full port range scanning (1–65535).
- Extended service identification, including Active Directory services.
- FTP anonymous access detection.
- SMB share enumeration.
- HTTP/HTTPS server and security header analysis.
- TLS certificate inspection.
- DNS resolution and passive subdomain discovery.
- Automated Gobuster integration.
- Single-credential validation across supported services.
- Colour-coded terminal output.

## Supported Services

| Service | Port | Functionality |
|---|---|---|
| FTP | 21 | Anonymous access, directory listing, authentication |
| SSH | 22 | Banner enumeration |
| Telnet | 23 | Banner enumeration |
| SMTP | 25, 587 | Banner enumeration |
| DNS | 53 | Port identification and hostname resolution |
| HTTP | 80, 8080 | Headers, title, Basic authentication |
| Kerberos | 88, 464 | Port identification |
| SMB | 139, 445 | Share enumeration and credential validation |
| LDAP | 389 | Port identification |
| HTTPS | 443, 8443 | HTTP and TLS inspection |
| LDAPS | 636 | TLS inspection |
| Global Catalog | 3268, 3269 | Port identification |
| RDP | 3389 | Port identification |
| WinRM | 5985, 5986 | NTLM authentication checks |
| ADWS | 9389 | Port identification |

Additional common services are included in the port identification database.

## Installation

### Prerequisites

- Go 1.22 or later
- Git
- Samba Client (optional)
- Gobuster (optional)
- Python 3 and pywinrm (optional)

### Kali Linux

```bash
sudo apt update
sudo apt install golang-go smbclient gobuster dirb python3-winrm
```

### Clone and build

```bash
git clone https://github.com/Dani-Marqus1/exec_me.git
cd exec_me/exec_me
go build -o exec_me .
```

Install globally:

```bash
sudo install -m 755 exec_me /usr/local/bin/exec_me
```

Verify installation:

```bash
exec_me --version
```

## Usage

### Basic reconnaissance

```bash
exec_me scan -t 192.168.56.10
```

### Full TCP port scan

```bash
exec_me scan -t 192.168.56.10 -p 1-65535 -c 200
```

### Specific ports

```bash
exec_me scan -t 192.168.56.10 -p 21,22,80,445
```

### Port scanning without enumeration

```bash
exec_me scan -t 192.168.56.10 -enum=false
```

### Credential validation

Validate a single supplied credential against supported services on an authorised host.

```bash
exec_me auth -t 192.168.56.10 -u labuser -p ''
```

Supported authentication protocols:

- FTP
- SMB
- HTTP Basic
- WinRM NTLM


## Example Output

```text
[*] exec_me v0.7.0
[*] Scanning TCP ports...

[+]    53/tcp  OPEN  DNS
[+]    80/tcp  OPEN  HTTP
[+]    88/tcp  OPEN  Kerberos
[+]   135/tcp  OPEN  MSRPC
[+]   389/tcp  OPEN  LDAP
[+]   445/tcp  OPEN  SMB
[+]  3268/tcp  OPEN  LDAP Global Catalog
[+]  3389/tcp  OPEN  RDP
[+]  5985/tcp  OPEN  WinRM/HTTP
[+]  9389/tcp  OPEN  AD Web Services

[*] Scan completed.
```

*Illustrative output from an Active Directory lab environment.*

## Command-Line Options

| Flag | Description |
|---|---|
| `-t` | Target IP address or hostname |
| `-p` | Port range or list |
| `-c` | Concurrent scan workers |
| `-timeout` | TCP connection timeout |
| `-enum` | Enable or disable service enumeration |
| `-smb-list` | Read-only SMB directory listing |
| `-gobuster` | Enable web directory discovery |
| `-gobuster-wordlist` | Specify a custom wordlist |
| `-subdomains` | Passive subdomain discovery |
| `-color` | Enable or disable terminal colours |

For the complete command reference:

```bash
exec_me -help
exec_me scan -help
exec_me auth -help
exec_me services
```

## Disclaimer

This tool is intended exclusively for educational purposes, authorised penetration testing and controlled laboratory environments.

Users are responsible for obtaining appropriate authorisation before testing any system.

---

