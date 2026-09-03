package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func parseValidityYears(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultCertValidityYears, nil
	}
	years, err := strconv.Atoi(raw)
	if err != nil {
		return 0, errors.New("invalid validity value")
	}
	if years < 1 || years > maxCertValidityYear {
		return 0, fmt.Errorf("validity must be between 1 and %d years", maxCertValidityYear)
	}
	return years, nil
}

func parseSANs(input string) ([]string, error) {
	parts := strings.Split(input, ",")
	seen := map[string]struct{}{}
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(strings.ToLower(p))
		if v == "" {
			continue
		}
		if _, exists := seen[v]; exists {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	if len(result) == 0 {
		return nil, errors.New("enter at least one SAN (FQDN, IP, or hostname)")
	}
	return result, nil
}

// parseSANsOptional parses a comma-separated SAN list, returning an empty
// slice (not an error) when the input is blank. Used for client certificates,
// where the CommonName is the identity and SANs are not required.
func parseSANsOptional(input string) ([]string, error) {
	if strings.TrimSpace(input) == "" {
		return nil, nil
	}
	return parseSANs(input)
}

func splitSANs(sans []string) ([]string, []net.IP) {
	dnsNames := make([]string, 0, len(sans))
	ipAddresses := make([]net.IP, 0, len(sans))
	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			ipAddresses = append(ipAddresses, ip)
			continue
		}
		dnsNames = append(dnsNames, san)
	}
	return dnsNames, ipAddresses
}

func filterCertificates(certs []certMetadata, query string) []certMetadata {
	query = strings.TrimSpace(strings.ToLower(query))
	if query == "" {
		return certs
	}
	filtered := make([]certMetadata, 0, len(certs))
	for _, cert := range certs {
		if strings.Contains(strings.ToLower(cert.ID), query) ||
			strings.Contains(strings.ToLower(cert.CommonName), query) ||
			strings.Contains(strings.ToLower(strings.Join(cert.SANs, ",")), query) {
			filtered = append(filtered, cert)
		}
	}
	return filtered
}

// filterCertificatesByType keeps only certificates of the given type
// (server, client, dot1x or codeSigning).
func filterCertificatesByType(certs []certMetadata, certType string) []certMetadata {
	filtered := make([]certMetadata, 0, len(certs))
	for _, cert := range certs {
		if cert.CertType() == certType {
			filtered = append(filtered, cert)
		}
	}
	return filtered
}

func (a *app) resolveCertificateDir(id string) (string, string, error) {
	if id == "" {
		return "", "", errors.New("missing certificate ID")
	}
	entries, err := os.ReadDir(filepath.Join(a.dataDir, "certs"))
	if err != nil {
		return "", "", errors.New("certificate archive not available")
	}
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() == id {
			return filepath.Join(a.dataDir, "certs", entry.Name()), entry.Name(), nil
		}
	}
	return "", "", errors.New("invalid certificate ID")
}
