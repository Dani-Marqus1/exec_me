package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSMBAuthOutput(t *testing.T) {
	data := "Disk|Public|Example\nIPC|IPC$|IPC Service\nDisk|Public|Duplicate\n"
	for _, err := range []error{nil, errors.New("workgroup lookup failed")} {
		status, detail := smbAuthResult(data, err, nil, "example-secret")
		if status != "UNVERIFIED" || !strings.Contains(detail, "Returned shares (2;") || !strings.Contains(detail, "Public") || !strings.Contains(detail, "IPC$") || !strings.Contains(detail, "guest fallback not excluded") {
			t.Fatalf("unexpected result: %s %s", status, detail)
		}
	}
}
func TestSMBAuthOutputRejection(t *testing.T) {
	for _, tc := range []struct{ data, want string }{{"NT_STATUS_LOGON_FAILURE", "INVALID"}, {"NT_STATUS_ACCOUNT_LOCKED_OUT", "LOCKED"}} {
		status, _ := smbAuthResult(tc.data, errors.New("denied"), nil, "secret")
		if status != tc.want {
			t.Fatalf("got %s, want %s", status, tc.want)
		}
	}
	status, _ := smbAuthResult("", errors.New("timeout"), context.DeadlineExceeded, "secret")
	if status != "ERROR" {
		t.Fatal(status)
	}
}
func TestSMBAuthOutputRedacts(t *testing.T) {
	_, detail := smbAuthResult("Disk|secret\x1b[31m|Example\n", nil, nil, "secret")
	if strings.Contains(detail, "secret") || strings.Contains(detail, "\x1b") {
		t.Fatal("unsafe output")
	}
}
