package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelpDocumentsImplementedServicesAndFlags(t *testing.T) {
	var out bytes.Buffer
	printHelp(&out)
	for _, s := range []string{"SUPPORTED SERVICES", "FTP", "SMB", "HTTP", "Gobuster", "-gobuster", "-gobuster-wordlist", "-smb-list", "-subdomains", "-enum=false", "exec_me scan -help", "PORT LABELS ONLY"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("help does not contain %q", s)
		}
	}
}

func TestServicesList(t *testing.T) {
	var out bytes.Buffer
	printServices(&out)
	if !strings.Contains(out.String(), "smbclient required") || !strings.Contains(out.String(), "-gobuster") {
		t.Fatal("services output missing optional tool details")
	}
}
