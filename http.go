package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"time"
)

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)

func checkHTTP(ctx context.Context, target string, port int, secure bool, out printer) {
	transport := &http.Transport{
		Proxy:               nil, // do not route authorized target traffic through environment proxies
		DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		TLSHandshakeTimeout: 4 * time.Second,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives:   true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout: 6 * time.Second, Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	url := baseURL(target, port, secure)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		out.warn(port, "HTTP request: "+err.Error())
		return
	}
	request.Header.Set("User-Agent", "exec_me/0.1")
	response, err := client.Do(request)
	if err != nil {
		out.finding(port, "HTTP probe", "failed: "+err.Error())
		return
	}
	defer response.Body.Close()
	out.finding(port, "HTTP status", fmt.Sprintf("%d %s", response.StatusCode, http.StatusText(response.StatusCode)))
	if server := response.Header.Get("Server"); server != "" {
		out.finding(port, "Server", server)
	}
	if powered := response.Header.Get("X-Powered-By"); powered != "" {
		out.finding(port, "X-Powered-By", powered)
	}
	if location := response.Header.Get("Location"); location != "" {
		out.finding(port, "Redirect location", location)
	}
	if len(response.Header.Values("Content-Security-Policy")) == 0 {
		out.finding(port, "CSP header", "not present")
	}
	if response.Header.Get("X-Content-Type-Options") == "" {
		out.finding(port, "X-Content-Type-Options", "not present")
	}
	if secure && response.Header.Get("Strict-Transport-Security") == "" {
		out.finding(port, "HSTS header", "not present")
	}
	// Bound memory and bytes downloaded: retrieve only the start of the page.
	body, _ := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if match := titlePattern.FindSubmatch(body); len(match) == 2 {
		out.finding(port, "HTML title", string(match[1]))
	}
}
