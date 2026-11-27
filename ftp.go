package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ftpSession struct {
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
}

func (s *ftpSession) command(command string) (int, string, error) {
	// Commands in this module are constants, not constructed from remote data.
	if _, err := fmt.Fprintf(s.w, "%s\r\n", command); err != nil {
		return 0, "", err
	}
	if err := s.w.Flush(); err != nil {
		return 0, "", err
	}
	return s.reply()
}
func (s *ftpSession) reply() (int, string, error) {
	line, err := s.r.ReadString('\n')
	if err != nil {
		return 0, "", err
	}
	if len(line) < 4 {
		return 0, "", errors.New("malformed FTP reply")
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0, "", errors.New("invalid FTP status")
	}
	if line[3] == '-' {
		for i := 0; i < 40; i++ { // bounded multiline response
			next, e := s.r.ReadString('\n')
			if e != nil {
				return 0, "", e
			}
			if strings.HasPrefix(next, fmt.Sprintf("%03d ", code)) {
				line = next
				break
			}
			if i == 39 {
				return 0, "", errors.New("FTP multiline reply too long")
			}
		}
	}
	return code, clean(strings.TrimSpace(line[4:])), nil
}
func checkFTP(ctx context.Context, target string, port int, out printer) {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", tcpAddress(target, port))
	if err != nil {
		out.warn(port, "FTP connect: "+err.Error())
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	session := ftpSession{conn: conn, r: bufio.NewReader(io.LimitReader(conn, 32*1024)), w: bufio.NewWriter(conn)}
	code, banner, err := session.reply()
	if err != nil {
		out.warn(port, "FTP greeting: "+err.Error())
		return
	}
	out.finding(port, "FTP greeting", fmt.Sprintf("%d %s", code, banner))
	if code != 220 {
		return
	}
	code, _, err = session.command("USER anonymous")
	if err != nil {
		out.warn(port, "Anonymous test: "+err.Error())
		return
	}
	switch code {
	case 230: // Logged in without PASS.
	case 331:
		code, _, err = session.command("PASS anonymous@example.invalid")
		if err != nil {
			out.warn(port, "Anonymous test: "+err.Error())
			return
		}
		if code != 230 {
			out.finding(port, "Anonymous login", fmt.Sprintf("not allowed (FTP %d)", code))
			return
		}
	default:
		out.finding(port, "Anonymous login", fmt.Sprintf("not allowed (FTP %d)", code))
		return
	}
	out.finding(port, "Anonymous login", "ALLOWED")
	if c, pwd, e := session.command("PWD"); e == nil && c == 257 {
		out.finding(port, "Working directory", pwd)
	}
	if listing, err := ftpList(ctx, &session, target); err == nil {
		if listing == "" {
			out.finding(port, "Directory listing", "allowed (empty)")
		} else {
			out.finding(port, "Directory listing", listing)
		}
	} else {
		out.finding(port, "Directory listing", "not available: "+err.Error())
	}
	_, _, _ = session.command("QUIT")
}

var pasvPortPattern = regexp.MustCompile(`\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)`)

func parseFTPDataPort(code int, message string) (int, error) {
	if code == 229 {
		start := strings.LastIndex(message, "(")
		end := strings.LastIndex(message, ")")
		if start < 0 || end <= start {
			return 0, errors.New("invalid EPSV reply")
		}
		payload := message[start+1 : end]
		if len(payload) < 5 {
			return 0, errors.New("invalid EPSV payload")
		}
		sep := string(payload[0])
		parts := strings.Split(payload, sep)
		if len(parts) < 5 {
			return 0, errors.New("invalid EPSV delimiter")
		}
		p, err := strconv.Atoi(parts[len(parts)-2])
		if err != nil || p < 1 || p > 65535 {
			return 0, errors.New("invalid EPSV port")
		}
		return p, nil
	}
	if code == 227 {
		match := pasvPortPattern.FindStringSubmatch(message)
		if len(match) != 7 {
			return 0, errors.New("invalid PASV reply")
		}
		hi, _ := strconv.Atoi(match[5])
		lo, _ := strconv.Atoi(match[6])
		p := hi*256 + lo
		if p < 1 || p > 65535 {
			return 0, errors.New("invalid PASV port")
		}
		return p, nil
	}
	return 0, fmt.Errorf("FTP passive mode rejected (%d)", code)
}
func ftpList(ctx context.Context, s *ftpSession, target string) (string, error) {
	code, msg, err := s.command("EPSV")
	if err != nil {
		return "", err
	}
	if code != 229 {
		code, msg, err = s.command("PASV")
		if err != nil {
			return "", err
		}
	}
	port, err := parseFTPDataPort(code, msg)
	if err != nil {
		return "", err
	}
	// Intentionally ignore a PASV-advertised IP; never pivot to a third-party host.
	d := net.Dialer{Timeout: 3 * time.Second}
	data, err := d.DialContext(ctx, "tcp", tcpAddress(target, port))
	if err != nil {
		return "", err
	}
	defer data.Close()
	_ = data.SetReadDeadline(time.Now().Add(4 * time.Second))
	code, _, err = s.command("LIST")
	if err != nil {
		return "", err
	}
	if code != 125 && code != 150 {
		return "", fmt.Errorf("LIST rejected (%d)", code)
	}
	buf, readErr := io.ReadAll(io.LimitReader(data, 8*1024))
	_ = data.Close()
	if readErr != nil {
		return "", readErr
	}
	code, _, err = s.reply()
	if err != nil {
		return "", err
	}
	if code != 226 && code != 250 {
		return "", fmt.Errorf("LIST incomplete (%d)", code)
	}
	lines := strings.Split(strings.TrimSpace(string(buf)), "\n")
	if len(lines) == 1 && strings.TrimSpace(lines[0]) == "" {
		return "", nil
	}
	if len(lines) > 5 {
		lines = append(lines[:5], "... (truncated)")
	}
	for i := range lines {
		lines[i] = clean(lines[i])
	}
	return strings.Join(lines, " | "), nil
}
