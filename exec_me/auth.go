package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func authCommand(args []string) {
	fs := flag.NewFlagSet("auth", flag.ContinueOnError)
	target := fs.String("t", "", "one authorized host or IP")
	user := fs.String("u", "", "one username")
	pass := fs.String("p", "", "password (prefer EXEC_ME_PASSWORD environment variable)")
	domain := fs.String("domain", "", "optional SMB/WinRM domain")
	spec := fs.String("ports", "common", "TCP ports or ranges to discover")
	timeout := fs.Duration("timeout", 5*time.Second, "timeout per operation")
	winrmHTTP := fs.Bool("allow-winrm-http", false, "allow NTLM WinRM over HTTP (message encryption required by pywinrm)")
	clear := fs.Bool("allow-cleartext", false, "allow credentials over unencrypted FTP/HTTP in an isolated lab")
	if err := fs.Parse(args); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		return
	}
	if err := validateTarget(*target); err != nil {
		fatal("%v", err)
	}
	if *pass == "" {
		*pass = os.Getenv("EXEC_ME_PASSWORD")
	}
	if *user == "" || *pass == "" {
		fatal("supply one username and password")
	}
	for _, v := range []string{*user, *pass, *domain} {
		if strings.ContainsAny(v, "\r\n\x00") {
			fatal("invalid credential field")
		}
	}
	if *timeout < time.Second || *timeout > 30*time.Second {
		fatal("timeout must be 1s–30s")
	}
	ports, err := parsePorts(*spec)
	if err != nil {
		fatal("%v", err)
	}
	ctx := context.Background()
	fmt.Printf("[*] Discovering TCP services on %s; one credential, no retries.\n", *target)
	fmt.Println("[*] Multiple services may share an account lockout counter. Check policy before running.")
	open := scanPorts(ctx, *target, ports, 40, *timeout)
	winrmPort := 5985
	for _, p := range open {
		if p == 5986 {
			winrmPort = 5986
		}
	}
	smbPort := 139
	for _, p := range open {
		if p == 445 {
			smbPort = 445
		}
	}
	for _, p := range open {
		status, detail := "SKIP", "no authentication adapter"
		switch {
		case p == 21:
			if *clear {
				status, detail = authFTP(ctx, *target, p, *user, *pass, *timeout)
			} else {
				detail = "cleartext FTP disabled"
			}
		case p == 139 || p == 445:
			if p == smbPort {
				status, detail = authSMB(ctx, *target, p, *user, *pass, *domain, *timeout)
			} else {
				detail = "duplicate SMB endpoint"
			}
		case p == 5985 || p == 5986:
			if p != winrmPort {
				detail = "duplicate WinRM endpoint; HTTPS preferred"
			} else if p == 5985 && !*winrmHTTP {
				detail = "WinRM HTTP disabled; use -allow-winrm-http in an authorized lab"
			} else {
				status, detail = authWinRM(ctx, *target, p, *user, *pass, *domain, *timeout)
			}
		case isWebPort(p):
			if isSecureWebPort(p) || *clear {
				status, detail = authHTTP(ctx, baseURL(*target, p, isSecureWebPort(p)), *user, *pass, *timeout)
			} else {
				detail = "cleartext HTTP disabled"
			}
		}
		fmt.Printf("[%-10s] %5d/tcp %-15s %s\n", status, p, portName(p), detail)
		if status == "LOCKED" {
			fmt.Println("[!] Account lockout reported; stopping.")
			break
		}
	}
	fmt.Println("[*] Finished.")
}

func authFTP(ctx context.Context, host string, port int, user, pass string, timeout time.Duration) (string, string) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", tcpAddress(host, port))
	if err != nil {
		return "ERROR", "FTP connection failed"
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	s := ftpSession{conn: c, r: bufio.NewReader(io.LimitReader(c, 32768)), w: bufio.NewWriter(c)}
	code, _, err := s.reply()
	if err != nil || code != 220 {
		return "UNVERIFIED", "FTP greeting not confirmed"
	}
	code, _, err = s.command("USER " + user)
	if err != nil {
		return "ERROR", "FTP USER failed"
	}
	if code == 230 {
		return "UNVERIFIED", "username accepted without testing password"
	}
	if code != 331 {
		return "UNVERIFIED", fmt.Sprintf("FTP USER returned %d", code)
	}
	code, _, err = s.command("PASS " + pass)
	if err != nil {
		return "ERROR", "FTP PASS response unavailable"
	}
	if code == 230 {
		return "VALID", "FTP login accepted"
	}
	if code == 530 {
		return "INVALID", "FTP login denied (credentials or policy)"
	}
	return "UNVERIFIED", fmt.Sprintf("FTP response %d", code)
}

func authHTTP(ctx context.Context, url, user, pass string, timeout time.Duration) (string, string) {
	// No proxy, redirects, insecure TLS or preemptive credentials.
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "ERROR", "invalid URL"
	}
	r, err := cl.Do(req)
	if err != nil {
		return "ERROR", "HTTP probe failed (connection or TLS trust)"
	}
	r.Body.Close()
	basic := false
	for _, h := range r.Header.Values("WWW-Authenticate") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(h)), "basic ") {
			basic = true
		}
	}
	if r.StatusCode != 401 || !basic {
		return "SKIP", "root endpoint did not advertise HTTP Basic authentication"
	}
	req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "ERROR", "invalid URL"
	}
	req.SetBasicAuth(user, pass)
	r, err = cl.Do(req)
	if err != nil {
		return "ERROR", "HTTP authentication response unavailable"
	}
	defer r.Body.Close()
	if r.StatusCode == 401 {
		return "INVALID", "HTTP Basic login denied"
	}
	if r.StatusCode >= 200 && r.StatusCode < 300 {
		return "VALID", "Basic challenge followed by successful response"
	}
	return "UNVERIFIED", fmt.Sprintf("HTTP status %d", r.StatusCode)
}

func authSMB(ctx context.Context, host string, port int, user, pass, domain string, timeout time.Duration) (string, string) {
	bin, err := exec.LookPath("smbclient")
	if err != nil {
		return "SKIP", "smbclient not installed"
	}
	if strings.Contains(user, "%") {
		return "SKIP", "SMB username contains unsupported delimiter"
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	args := []string{"-L", "//" + host, "-g", "-p", strconv.Itoa(port), "-U", user, "-t", strconv.Itoa(int(timeout.Seconds())), "--option=client min protocol=SMB2"}
	if domain != "" {
		args = append(args, "-W", domain)
	}
	cmd := exec.CommandContext(cctx, bin, args...)
	// Samba reads PASSWD from the environment. Never put password in subprocess arguments.
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "PASSWD=") && !strings.HasPrefix(e, "PASSWD_FD=") && !strings.HasPrefix(e, "PASSWD_FILE=") && !strings.HasPrefix(e, "EXEC_ME_PASSWORD=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, "PASSWD="+pass)
	data, err := cmd.CombinedOutput()
	s := strings.ToUpper(string(data))
	if strings.Contains(s, "NT_STATUS_ACCOUNT_LOCKED_OUT") {
		return "LOCKED", "SMB reported account lockout"
	}
	if strings.Contains(s, "NT_STATUS_LOGON_FAILURE") || strings.Contains(s, "NT_STATUS_WRONG_PASSWORD") {
		return "INVALID", "SMB login denied"
	}
	if err == nil {
		return "UNVERIFIED", "SMB session/share request succeeded; guest fallback not excluded"
	}
	if cctx.Err() != nil {
		return "ERROR", "SMB timed out"
	}
	return "UNVERIFIED", "SMB request unsuccessful; identity not confirmed"
}
