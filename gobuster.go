package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// gobusterOptions intentionally uses bounded concurrency and an opt-in scan.
type gobusterOptions struct {
	enabled    bool
	wordlist   string
	threads    int
	timeout    time.Duration // maximum run time per web service
	insecure   bool
	extensions string
}

var defaultWebWordlists = []string{
	"/usr/share/wordlists/dirb/common.txt",
	"/usr/share/seclists/Discovery/Web-Content/common.txt",
	"/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
}

func resolveWebWordlist(requested string) (string, error) {
	if requested != "" {
		info, err := os.Stat(requested)
		if err != nil {
			return "", fmt.Errorf("wordlist %q: %w", requested, err)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("wordlist %q is not a regular file", requested)
		}
		return requested, nil
	}
	for _, candidate := range defaultWebWordlists {
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}
	return "", errors.New("no web wordlist found; install dirb/seclists or supply -gobuster-wordlist PATH")
}

func gobusterArgs(url, wordlist string, opts gobusterOptions) []string {
	args := []string{"dir", "-u", url, "-w", wordlist, "-t", fmt.Sprint(opts.threads), "--no-progress", "-q"}
	if opts.insecure {
		args = append(args, "-k")
	}
	if opts.extensions != "" {
		args = append(args, "-x", opts.extensions)
	}
	return args
}

func runGobuster(ctx context.Context, target string, port int, secure bool, out printer, opts gobusterOptions) {
	if !opts.enabled {
		return
	}
	path, err := exec.LookPath("gobuster")
	if err != nil {
		out.warn(port, "Gobuster not installed: sudo apt install gobuster")
		return
	}
	wordlist, err := resolveWebWordlist(opts.wordlist)
	if err != nil {
		out.warn(port, "Gobuster skipped: "+err.Error())
		return
	}
	url := baseURL(target, port, secure)
	out.note("Gobuster directory discovery: %s (wordlist: %s, threads: %d)", url, filepath.Base(wordlist), opts.threads)

	runCtx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, path, gobusterArgs(url, wordlist, opts)...)
	// Using exec.CommandContext (not a shell) prevents any shell interpolation.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		out.warn(port, "Gobuster stdout: "+err.Error())
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		out.warn(port, "Gobuster stderr: "+err.Error())
		return
	}
	if err := cmd.Start(); err != nil {
		out.warn(port, "Gobuster start: "+err.Error())
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); streamGobuster(stdout, port, out, false) }()
	go func() { defer wg.Done(); streamGobuster(stderr, port, out, true) }()
	wg.Wait()
	err = cmd.Wait()
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		out.warn(port, fmt.Sprintf("Gobuster stopped after %s time limit", opts.timeout))
	} else if err != nil {
		out.warn(port, "Gobuster exited: "+err.Error())
	}
}

func streamGobuster(reader io.Reader, port int, out printer, isError bool) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if isError {
			out.warn(port, "Gobuster: "+line)
		} else {
			out.finding(port, "Gobuster", line)
		}
	}
	if err := scanner.Err(); err != nil {
		out.warn(port, "Gobuster output: "+err.Error())
	}
}
