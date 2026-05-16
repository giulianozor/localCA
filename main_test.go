package main

import "testing"

func TestParseValidityYears(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{name: "default", input: "", want: 1},
		{name: "valid", input: "30", want: 30},
		{name: "too high", input: "31", wantErr: true},
		{name: "invalid", input: "abc", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseValidityYears(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseValidityYears() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("parseValidityYears() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSANs(t *testing.T) {
	t.Run("valid and deduplicated", func(t *testing.T) {
		got, err := parseSANs("Dev.Local, 127.0.0.1, dev.local, api.locsl")
		if err != nil {
			t.Fatalf("parseSANs() error = %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("parseSANs() len = %d, want 3", len(got))
		}
	})

	t.Run("missing", func(t *testing.T) {
		if _, err := parseSANs("   ,   "); err == nil {
			t.Fatal("parseSANs() expected error")
		}
	})
}
