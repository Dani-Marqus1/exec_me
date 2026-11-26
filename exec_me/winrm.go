package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

//go:embed winrm_check.py
var winrmHelper string

// Use a read-only WS-Transfer Get, not Identify (which can be anonymous).
func winrmEnvelope(endpoint string) string {
	return fmt.Sprintf(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><s:Header><a:To>%s</a:To><a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo><a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action><a:MessageID>uuid:43d44db0-39be-4af9-b2f9-23042d09c001</a:MessageID><w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/config</w:ResourceURI><w:OperationTimeout>PT3S</w:OperationTimeout></s:Header><s:Body/></s:Envelope>`, endpoint)
}

func winrmChallenge(ctx context.Context, endpoint, envelope string, timeout time.Duration) (string, string) {
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(envelope))
	if err != nil {
		return "ERROR", "invalid WinRM endpoint"
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	r, err := cl.Do(req)
	if err != nil {
		return "ERROR", "WinRM probe failed (connection or TLS trust)"
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusUnauthorized {
		return "SKIP", fmt.Sprintf("/wsman did not require authentication (HTTP %d)", r.StatusCode)
	}
	for _, v := range r.Header.Values("WWW-Authenticate") {
		for _, part := range strings.Split(v, ",") {
			f := strings.Fields(part)
			if len(f) > 0 && (strings.EqualFold(f[0], "NTLM") || strings.EqualFold(f[0], "Negotiate")) {
				return "READY", "NTLM/Negotiate challenge"
			}
		}
	}
	return "SKIP", "/wsman did not advertise NTLM or Negotiate"
}

func winrmEndpoint(host string, port int) string {
	return strings.TrimRight(baseURL(host, port, port == 5986), "/") + "/wsman"
}

func authWinRM(ctx context.Context, host string, port int, user, pass, domain string, timeout time.Duration) (string, string) {
	endpoint := winrmEndpoint(host, port)
	envelope := winrmEnvelope(endpoint)
	status, detail := winrmChallenge(ctx, endpoint, envelope, timeout)
	if status != "READY" {
		return status, detail
	}
	bin, err := exec.LookPath("python3")
	if err != nil {
		return "SKIP", "WinRM requires python3 and pywinrm"
	}
	if domain != "" && !strings.ContainsAny(user, "\\@") {
		user = domain + "\\" + user
	}
	data, err := json.Marshal(map[string]any{"endpoint": endpoint, "username": user, "password": pass, "envelope": envelope, "timeout": int(timeout.Seconds())})
	if err != nil {
		return "ERROR", "WinRM input encoding failed"
	}
	cctx, cancel := context.WithTimeout(ctx, timeout+2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, "-c", winrmHelper)
	cmd.Stdin = strings.NewReader(string(data))
	for _, v := range os.Environ() {
		k, _, _ := strings.Cut(v, "=")
		switch strings.ToUpper(k) {
		case "EXEC_ME_PASSWORD", "PASSWD", "PASSWD_FD", "PASSWD_FILE", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
			continue
		}
		cmd.Env = append(cmd.Env, v)
	}
	out, err := cmd.Output()
	if cctx.Err() != nil {
		return "ERROR", "WinRM timed out"
	}
	if err != nil {
		return "ERROR", "WinRM helper failed"
	}
	switch strings.TrimSpace(string(out)) {
	case "MISSING":
		return "SKIP", "install python3-winrm (pywinrm)"
	case "VALID":
		return "VALID", "authenticated WinRM configuration read succeeded"
	case "DENIED":
		return "UNVERIFIED", "WinRM authentication denied (credentials, policy or lockout); stopping WinRM checks"
	case "LOCKED":
		return "LOCKED", "WinRM reported account lockout"
	case "UNVERIFIED":
		return "UNVERIFIED", "WinRM request unsuccessful; authentication or authorization not confirmed"
	default:
		return "ERROR", "WinRM helper returned an unexpected result"
	}
}
