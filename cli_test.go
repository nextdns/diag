package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

func TestParseCLI(t *testing.T) {
	yes, email, err := parseCLI([]string{"-y", "-email", "ops@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !yes || email != "ops@example.com" {
		t.Fatalf("yes=%v email=%q", yes, email)
	}

	yes, email, err = parseCLI(nil)
	if err != nil {
		t.Fatal(err)
	}
	if yes || email != "" {
		t.Fatalf("defaults yes=%v email=%q", yes, email)
	}

	_, _, err = parseCLI([]string{"-unknown"})
	if err == nil {
		t.Fatal("expected an error for an unknown flag")
	}
	_, _, err = parseCLI([]string{"-h"})
	if err != flag.ErrHelp {
		t.Fatalf("help error = %v", err)
	}
}

func TestConfirmReport(t *testing.T) {
	var out bytes.Buffer
	send, contact := confirmReport(&out, panicReader{}, true, "ops@example.com")
	if !send || contact != "ops@example.com" {
		t.Fatalf("unattended send=%v contact=%q", send, contact)
	}
	if out.Len() != 0 {
		t.Fatalf("unattended prompt = %q", out.String())
	}

	cases := []struct {
		in      string
		email   string
		send    bool
		contact string
	}{
		{"n\n", "", false, ""},
		{"no\n", "", false, ""},
		{"\nops@example.com\n", "", true, "ops@example.com"},
		{"y\n\n", "", true, ""},
		{"Y\nignored@example.com\n", "preset@example.com", true, "preset@example.com"},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		send, contact := confirmReport(&buf, strings.NewReader(tc.in), false, tc.email)
		if send != tc.send || contact != tc.contact {
			t.Fatalf("input %q email %q: send=%v contact=%q, want send=%v contact=%q",
				tc.in, tc.email, send, contact, tc.send, tc.contact)
		}
	}
}

// panicReader fails the test if unattended mode reads stdin.
type panicReader struct{}

func (panicReader) Read([]byte) (int, error) {
	panic("unattended mode read from stdin")
}
