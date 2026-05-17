# localCA

Go web application (dark theme) to manage a local Certificate Authority and issue local server certificates.

## Run

```bash
go run . /path/to/data
```

```bash
go run . -port 9090 -lang ja /path/to/data
```

Required CLI argument:
- data directory path used to persist configuration and artifacts

Optional flags:
- `-port` (default `8080`) sets the web server port
- `-lang` (default `en`) sets the initial UI language (`en`, `it`, or `ja`)

The application listens on all network interfaces and exposes the UI at `http://<host-ip-or-hostname>:<port>`.

> ⚠️ **Security**: when bound on all interfaces, the CA management UI is reachable from the network. Use only in trusted networks or restrict access with firewall/network rules.

## Features

- Local CA creation with fixed **100-year** validity
- Server certificate creation with DNS/IP SANs (`FQDN`, IP, `.local`) and selectable validity from **1 to 30 years**
- Web export in common formats:
  - Certificates: CSR PEM, PEM, DER, chain PEM, per-certificate `tar.gz`
  - Private keys: PEM (PKCS#1), PEM (PKCS#8), DER
- UI language selector (English/Italian/Japanese) with preference persisted in `config.json`
- Issued certificate filtering by ID/CN/SAN with debounced updates (300 ms) and table-only refresh (no full page reload)

## Data layout

The provided data directory contains:

- `config.json`
- `ca-cert.pem`, `ca-cert.der`
- `ca-key.pem`, `ca-key-pkcs8.pem`, `ca-key.der`
- `certs/<id>/...` for each issued certificate, including CSR/certificate/key material and metadata
