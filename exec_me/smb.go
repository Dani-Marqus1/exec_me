package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type smbShare struct{ name, kind string }

func parseSMBShares(output string) []smbShare {
	var shares []smbShare
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		// smbclient -g emits lines such as Disk|public|description
		parts := strings.SplitN(strings.TrimSpace(line), "|", 3)
		if len(parts) < 2 {
			continue
		}
		kind := strings.TrimSpace(parts[0])
		name := strings.TrimSpace(parts[1])
		if name == "" || (kind != "Disk" && kind != "IPC" && kind != "Printer") {
			continue
		}
		if !seen[name] {
			shares = append(shares, smbShare{name, kind})
			seen[name] = true
		}
	}
	return shares
}

func checkSMB(ctx context.Context, target string, port int, out printer, listShares bool) {
	if _, err := exec.LookPath("smbclient"); err != nil {
		out.finding(port, "SMB enumeration", "install smbclient (sudo apt install smbclient)")
		return
	}
	callCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	// Argument array; no shell expansion. -U % means empty username/password.
	// -N ensures an SMB password prompt is never shown.
	args := []string{"-L", "//" + target, "-g", "-N", "-U", "%", "-p", strconv.Itoa(port), "-t", "8"}
	data, err := exec.CommandContext(callCtx, "smbclient", args...).CombinedOutput()
	shares := parseSMBShares(string(data))
	if len(shares) == 0 {
		summary := "no shares returned"
		if err != nil {
			summary = "denied or unavailable"
		}
		out.finding(port, "Unauthenticated SMB", summary)
		if err != nil {
			out.finding(port, "SMB detail", briefSMBError(string(data), err))
		}
		return
	}
	out.finding(port, "Share enumeration", "ALLOWED without supplied credentials (guest/null-session identity unverified)")
	for i, share := range shares {
		if i == 12 {
			out.finding(port, "Shares", "... remaining shares omitted")
			break
		}
		out.finding(port, "Share", fmt.Sprintf("%s (%s)", share.name, share.kind))
	}
	if !listShares {
		return
	}
	checked := 0
	for _, share := range shares {
		if share.kind != "Disk" || strings.ContainsAny(share.name, "/\\\r\n") {
			continue
		}
		if checked >= 5 {
			out.finding(port, "Share checks", "limit of 5 reached")
			break
		}
		checked++
		checkSMBShare(ctx, target, port, share.name, out)
	}
}
func checkSMBShare(ctx context.Context, target string, port int, share string, out printer) {
	callCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	// Read-only top-level listing, no downloads, writes or recursion.
	args := []string{"//" + target + "/" + share, "-c", "ls", "-N", "-U", "%", "-p", strconv.Itoa(port), "-t", "6"}
	data, err := exec.CommandContext(callCtx, "smbclient", args...).CombinedOutput()
	if err != nil || strings.Contains(string(data), "NT_STATUS_") {
		out.finding(port, share+" listing", "denied or unavailable")
		return
	}
	out.finding(port, share+" listing", "ALLOWED without supplied credentials")
}
func briefSMBError(output string, err error) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "NT_STATUS_") || strings.Contains(strings.ToLower(line), "error") {
			return line
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed out"
	}
	return "SMB share listing unsuccessful"
}
