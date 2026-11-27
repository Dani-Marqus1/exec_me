package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWinRMChallenge(t *testing.T) {
	for _, tc := range []struct {
		code            int
		challenge, want string
	}{
		{401, "Negotiate, Kerberos", "READY"}, {401, "NTLM", "READY"}, {401, "Basic realm=lab", "SKIP"}, {200, "", "SKIP"}, {302, "", "SKIP"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.URL.Path != "/wsman" || r.Header.Get("Authorization") != "" {
				t.Error("unexpected probe")
			}
			w.Header().Set("WWW-Authenticate", tc.challenge)
			w.WriteHeader(tc.code)
		}))
		endpoint := srv.URL + "/wsman"
		got, _ := winrmChallenge(context.Background(), endpoint, winrmEnvelope(endpoint), time.Second)
		srv.Close()
		if got != tc.want {
			t.Errorf("%d %s: got %s, want %s", tc.code, tc.challenge, got, tc.want)
		}
	}
}
func TestWinRMReadOnlyEnvelope(t *testing.T) {
	s := winrmEnvelope("http://127.0.0.1:5985/wsman")
	if !strings.Contains(s, "/transfer/Get") || !strings.Contains(s, "/1/config") {
		t.Fatal("expected read-only configuration request")
	}
}

func TestWinRMEndpoint(t *testing.T) {
	if got := winrmEndpoint("127.0.0.1", 5985); got != "http://127.0.0.1:5985/wsman" {
		t.Fatal(got)
	}
	if got := winrmEndpoint("::1", 5986); got != "https://[::1]:5986/wsman" {
		t.Fatal(got)
	}
}
