# localCA

Applicazione Go con interfaccia web (tema scuro) per gestire una Certificate Authority locale e certificati server locali.

## Avvio

```bash
go run . /percorso/dati
```

```bash
go run . -port 9090 /percorso/dati
```

L'unico parametro da riga di comando è il percorso dove salvare dati e configurazione.
È disponibile un flag opzionale `-port` (default `8080`) per impostare la porta web.
L'applicazione ascolta su tutte le interfacce di rete ed espone la UI su `http://<ip-host>:<porta>`.

> ⚠️ **Sicurezza**: esponendo la UI su tutte le interfacce, il pannello di gestione CA è raggiungibile dalla rete. Usare solo in rete fidata o limitare l'accesso con firewall/regole di rete.

## Funzionalità

- Creazione CA locale con validità fissa a **100 anni**
- Creazione certificati server con SAN DNS/IP (`FQDN`, IP, host `.local` o `.locsl`), validità selezionabile da **1 a 30 anni**
- Esportazione via web in formati diffusi:
  - Certificati: PEM, DER, chain PEM
  - Chiavi private: PEM (PKCS#1), PEM (PKCS#8), DER
- Configurazione (`config.json`) creata alla creazione della CA e salvata nella cartella dati

## Struttura dati

Nella cartella passata da CLI vengono creati:

- `config.json`
- `ca-cert.pem`, `ca-cert.der`
- `ca-key.pem`, `ca-key-pkcs8.pem`, `ca-key.der`
- `certs/<id>/...` per ogni certificato emesso
