package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func showDNS(ctx context.Context, domain string, out printer) {
	lookupCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(lookupCtx, domain)
	if err != nil {
		out.note("DNS resolution: %s", clean(err.Error()))
		return
	}
	if len(ips) > 8 {
		ips = ips[:8]
	}
	var records []string
	for _, ip := range ips {
		records = append(records, ip.IP.String())
	}
	out.note("Resolved IPs: %s", strings.Join(records, ", "))
	mxCtx, mxCancel := context.WithTimeout(ctx, 3*time.Second)
	defer mxCancel()
	mx, err := net.DefaultResolver.LookupMX(mxCtx, domain)
	if err == nil && len(mx) > 0 {
		if len(mx) > 5 {
			mx = mx[:5]
		}
		for _, record := range mx {
			out.note("MX: %s (priority %d)", record.Host, record.Pref)
		}
	}
}

type certTransparencyEntry struct {
	NameValue string `json:"name_value"`
}

func showSubdomains(ctx context.Context, domain string, out printer) {
	requestCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	endpoint := "https://crt.sh/?q=" + url.QueryEscape("%."+strings.TrimSuffix(domain, ".")) + "&output=json"
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		out.note("crt.sh request error: %s", err)
		return
	}
	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		out.note("crt.sh unavailable: %s", clean(err.Error()))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		out.note("crt.sh returned HTTP %d", resp.StatusCode)
		return
	}
	// Limit third-party API response size to 2 MiB.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		out.note("crt.sh response error: %s", err)
		return
	}
	var entries []certTransparencyEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		out.note("crt.sh response could not be parsed")
		return
	}
	suffix := "." + strings.ToLower(strings.TrimSuffix(domain, "."))
	unique := make(map[string]bool)
	for _, entry := range entries {
		for _, raw := range strings.Split(entry.NameValue, "\n") {
			host := strings.ToLower(strings.TrimSpace(raw))
			host = strings.TrimPrefix(host, "*.")
			if strings.HasSuffix(host, suffix) && validateTarget(host) == nil {
				unique[host] = true
			}
		}
	}
	hosts := make([]string, 0, len(unique))
	for host := range unique {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	out.note("Passive crt.sh subdomains: %d unique (displaying up to 25)", len(hosts))
	for i, host := range hosts {
		if i >= 25 {
			break
		}
		out.note("  %s", host)
	}
	if len(body) >= 2*1024*1024 {
		out.note("crt.sh response truncated: results may be incomplete")
	}
}
