zms-authhistory
===============

A utility to retrieve and report authorization history dependencies for services in a specified Athenz domain. It connects to the ZMS server using mTLS authentication and generates a report showing both **incoming** and **outgoing** dependencies for each service in the domain.

- **Outgoing dependencies**: Services in your domain that have accessed resources in other domains (which domains they call).
- **Incoming dependencies**: Principals from other domains that have accessed resources in your domain (who calls your domain).

## Usage

```
zms-authhistory -domain <domain> -zms <url> -svc-key-file <key-file> -svc-cert-file <cert-file> [-svc-cacert-file <ca-cert-file>] [-days <days>] [-domains-only]
```

### Required Options

| Option | Description |
|--------|-------------|
| `-domain` | Athenz domain name to report on |
| `-zms` | ZMS server URL (e.g. `https://athenz.io:4443/zms/v1`) |
| `-svc-key-file` | Service identity private key file (PEM) |
| `-svc-cert-file` | Service identity certificate file (PEM) |

### Optional Options

| Option | Description |
|--------|-------------|
| `-svc-cacert-file` | CA certificates file for verifying the ZMS server |
| `-days` | Number of days to look back; records older than this are ignored (0 = no filter) |
| `-domains-only` | For dependencies, show only the domain name (no service name) |
| `-version` | Print version and exit |

### Example

```bash
zms-authhistory -domain mydomain -zms https://athenz.example.com:4443/zms/v1 \
  -svc-key-file /path/to/key.pem -svc-cert-file /path/to/cert.pem \
  -svc-cacert-file /path/to/ca.pem -days 30
```

With `-domains-only` to get a compact list of domains only:

```bash
zms-authhistory -domain mydomain -zms https://athenz.example.com:4443/zms/v1 \
  -svc-key-file ./key.pem -svc-cert-file ./cert.pem -domains-only -days 7
```

## Output

The report is printed as CSV to stdout.

**Default format** (with service names):

- **Outgoing**: `Service,Target-Domain,Last-Access` — services in your domain and which external domains they accessed.
- **Incoming**: `Source-Domain,Source-Service,Last-Access` — external principals that accessed your domain.

**With `-domains-only`**:

- **Outgoing**: `Target-Domain,Last-Access`
- **Incoming**: `Source-Domain,Last-Access`

Example (default):

```
Service,Target-Domain,Last-Access
api,other.domain,2025-02-10T12:00:00Z
api,third.domain,2025-02-09T08:30:00Z
worker,other.domain,2025-02-08T14:00:00Z

Source-Domain,Source-Service,Last-Access
caller.domain,frontend,2025-02-10T11:00:00Z
caller.domain,ingest,2025-02-09T09:00:00Z
```

## Building

Prerequisites: Go 1.19 or newer.

```bash
# Build for current OS and run checks
make

# Build for specific platforms
make darwin   # target/darwin/zms-authhistory
make linux    # target/linux/zms-authhistory

# Clean build artifacts
make clean
```

## License

Copyright The Athenz Authors

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
