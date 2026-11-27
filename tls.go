package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"
)

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

func checkTLS(ctx context.Context, target string, port int, out printer) {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target, strconv.Itoa(port)))
	if err != nil {
		out.finding(port, "TLS", "connection failed: "+err.Error())
		return
	}
	// Metadata-only TLS handshake: certificate validation happens separately below.
	// This permits printing details of expired/self-signed certificates in labs.
	tlsConn := tls.Client(raw, &tls.Config{ServerName: target, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) //nolint:gosec
	defer tlsConn.Close()
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		out.finding(port, "TLS", "handshake failed: "+err.Error())
		return
	}
	state := tlsConn.ConnectionState()
	out.finding(port, "TLS negotiated", tlsVersion(state.Version))
	if len(state.PeerCertificates) == 0 {
		out.finding(port, "Certificate", "none supplied")
		return
	}
	cert := state.PeerCertificates[0]
	out.finding(port, "Certificate CN", cert.Subject.CommonName)
	out.finding(port, "Certificate expiry", cert.NotAfter.Format(time.RFC3339))
	days := time.Until(cert.NotAfter).Hours() / 24
	if days < 0 {
		out.finding(port, "Certificate status", "EXPIRED")
	}
	if days >= 0 && days < 30 {
		out.finding(port, "Certificate status", fmt.Sprintf("expires in %.0f days", days))
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		out.finding(port, "Trust validation", "system root CAs unavailable")
		return
	}
	intermediates := x509.NewCertPool()
	for _, chainCert := range state.PeerCertificates[1:] {
		intermediates.AddCert(chainCert)
	}
	_, err = cert.Verify(x509.VerifyOptions{DNSName: target, Roots: pool, Intermediates: intermediates})
	if err != nil {
		out.finding(port, "Trust validation", "not trusted/valid for target: "+err.Error())
	} else {
		out.finding(port, "Trust validation", "valid for target")
	}
}
