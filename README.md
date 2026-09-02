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

- Local CA creation with fixed **100-year** validity (optional private-key passphrase)
- Optional intermediate CA creation with fixed **30-year** validity (used to sign newly issued certificates)
- Server certificate creation with DNS/IP SANs (`FQDN`, IP, `.local`) and selectable validity from **1 to 30 years** (default **2 years**)
- CA/intermediate/issued private-key passphrase set/change/remove support
- Certificate revoke and renew actions from the issued certificates list
- Per-certificate export as `tar.gz` only, with optional export passphrase
- Whole-CA export/import as a `tar.gz` backup (CA, intermediate, CRL and all issued certificates), with optional passphrase-based AES encryption
- UI language selector (English/Italian/Japanese) with preference persisted in `config.json`
- UI translations are embedded in the binary (no runtime `i18n/*.json` files required)
- Issued certificate filtering by ID/CN/SAN with debounced updates (300 ms) and table-only refresh (no full page reload)

## Data layout

The provided data directory contains:

- `config.json`
- `ca-cert.pem`, `ca-cert.der`
- `ca-key.pem`
- `intermediate-cert.pem`, `intermediate-key.pem`, `intermediate-chain.pem` (if created)
- `certs/<id>/...` for each issued certificate, including CSR (`csr.pem`), certificate (`cert.pem`), private key (`key.pem`) and metadata
