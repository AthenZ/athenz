# SIA for Spacelift

The SIA utility authenticates Spacelift runs with Athenz and obtains a service
identity X.509 certificate.

The OIDC token is automatically read from the `SPACELIFT_OIDC_TOKEN` environment
variable or from the `/mnt/workspace/spacelift.oidc` file.

## Dependencies

The script requires Python 3.10+ and the following packages:

- `cryptography>=43.0`
- `PyJWT>=2.9`
- `requests>=2.32`

When [uv](https://docs.astral.sh/uv/) is available, dependencies are resolved
automatically. Otherwise, install them with `pip install cryptography PyJWT requests`.

## Usage

```
./sia.py --zts <zts-server-url> --domain <athenz-domain> --service <athenz-service> \
         --dns-domain <dns-domain> --key-file <key-file> --cert-file <cert-file>
```

The utility will generate a unique RSA private key and obtain a service identity
X.509 certificate from Athenz and store the key and certificate in the specified files.

As part of its output, the agent shows the action and resource values that the domain
administrator must use to configure the Athenz services to allow the Spacelift run
to authorize:

```
2024/02/15 17:05:43 Action:                          spacelift.run
2024/02/15 17:05:43 Resource for specific run type:   sports:space:my-space:stack:my-stack:run_type:TRACKED:*
2024/02/15 17:05:43 Resource for all run types:        sports:space:my-space:stack:my-stack:*
```

## Testing

```
python3 -m pytest -v sia_test.py
```
