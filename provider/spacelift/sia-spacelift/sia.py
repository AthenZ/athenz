#!/bin/sh
''':'
if command -v uv >/dev/null 2>&1; then
  exec uv run --script "$0" "$@"
else
  exec python3 "$0" "$@"
fi
':'''
# /// script
# dependencies = [
#   "cryptography>=43.0",
#   "PyJWT>=2.9",
#   "requests>=2.32",
# ]
# ///
from __future__ import annotations
#
# Copyright The Athenz Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Service Identity Agent for Spacelift.

Obtains an Athenz X.509 service identity certificate using a Spacelift OIDC token.
The token is read from the SPACELIFT_OIDC_TOKEN environment variable or from
/mnt/workspace/spacelift.oidc.
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

VERSION = "development"

SPACELIFT_TOKEN_ENV_VAR = "SPACELIFT_OIDC_TOKEN"
SPACELIFT_TOKEN_FILE = "/mnt/workspace/spacelift.oidc"

JWT_ALGORITHMS = [
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
    "EdDSA",
]

log = logging.getLogger("sia-spacelift")


def get_oidc_token(
    env_var: str = SPACELIFT_TOKEN_ENV_VAR,
    token_file: str = SPACELIFT_TOKEN_FILE,
) -> tuple[str, dict[str, Any]]:
    """Read Spacelift OIDC token from environment or file and parse its claims.

    Returns:
        Tuple of (raw_token, claims_dict).

    Raises:
        RuntimeError: If the token cannot be obtained or parsed.
    """
    token = os.environ.get(env_var, "").strip()

    if not token:
        token_path = Path(token_file)
        if token_path.is_file():
            token = token_path.read_text().strip()

    if not token:
        raise RuntimeError(
            f"Unable to obtain Spacelift OIDC token: env var {env_var} not set "
            f"and file {token_file} not readable"
        )

    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=JWT_ALGORITHMS,
        )
    except jwt.exceptions.DecodeError as exc:
        raise RuntimeError(f"Unable to parse Spacelift OIDC token: {exc}") from exc

    return token, claims


def get_instance_id(claims: dict[str, Any]) -> str:
    """Construct instance ID from token claims.

    Format: <spaceId>:<callerId>:<runId>

    Raises:
        RuntimeError: If required claims are missing.
    """
    missing = [
        field for field in ("spaceId", "callerId", "runId")
        if not claims.get(field)
    ]
    if missing:
        raise RuntimeError(
            f"Unable to extract {', '.join(missing)} from OIDC token claims"
        )

    return f"{claims['spaceId']}:{claims['callerId']}:{claims['runId']}"


def generate_csr(
    private_key: rsa.RSAPrivateKey,
    domain: str,
    service: str,
    provider: str,
    instance_id: str,
    dns_domain: str,
    spiffe_trust_domain: str = "",
    subj_c: str = "US",
    subj_o: str = "",
    subj_ou: str = "Athenz",
) -> str:
    """Generate a PEM-encoded X.509 CSR with Athenz SAN entries.

    Returns:
        PEM-encoded CSR as a string.
    """
    # build subject name attributes
    name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, f"{domain}.{service}")]
    if subj_c:
        name_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, subj_c))
    if subj_o:
        name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, subj_o))
    if subj_ou:
        name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subj_ou))

    # build SAN entries
    san_entries: list[x509.GeneralName] = []

    # SAN DNS: <service>.<domain>.<dns_domain>
    san_entries.append(x509.DNSName(f"{service}.{domain}.{dns_domain}"))

    # SPIFFE URI must be first URI entry
    if spiffe_trust_domain:
        spiffe_uri = f"spiffe://{spiffe_trust_domain}/ns/default/sa/{domain}.{service}"
        san_entries.append(x509.UniformResourceIdentifier(spiffe_uri))

    # instance ID URI
    instance_uri = f"athenz://instanceid/{provider}/{instance_id}"
    san_entries.append(x509.UniformResourceIdentifier(instance_uri))

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name(name_attrs))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(private_key, hashes.SHA256())
    )

    return csr.public_bytes(serialization.Encoding.PEM).decode()


def register_instance(
    zts_url: str,
    provider: str,
    domain: str,
    service: str,
    attestation_data: str,
    csr: str,
    expiry_time: int,
    ca_cert: str | None = None,
) -> dict[str, Any]:
    """Register instance with ZTS and obtain X.509 certificate.

    Returns:
        Response dict with x509Certificate and x509CertificateSigner.

    Raises:
        RuntimeError: If the registration request fails.
    """
    url = f"{zts_url.rstrip('/')}/instance"
    payload = {
        "provider": provider,
        "domain": domain,
        "service": service,
        "attestationData": attestation_data,
        "csr": csr,
        "expiryTime": expiry_time,
    }

    verify: bool | str = ca_cert if ca_cert else True
    response = requests.post(
        url,
        json=payload,
        headers={"User-Agent": f"SIA-Spacelift {VERSION}"},
        verify=verify,
        timeout=30,
    )

    if response.status_code not in (200, 201):
        raise RuntimeError(
            f"Unable to register instance: {response.status_code} {response.text}"
        )

    return response.json()


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Spacelift Service Identity Agent for Athenz",
    )
    parser.add_argument("--key-file", required=True, help="output private key file")
    parser.add_argument("--cert-file", required=True, help="output certificate file")
    parser.add_argument("--signer-cert-file", default="", help="output signer certificate file (optional)")
    parser.add_argument("--domain", required=True, help="domain of service")
    parser.add_argument("--service", required=True, help="name of service")
    parser.add_argument("--zts", required=True, help="url of the ZTS Service")
    parser.add_argument("--dns-domain", required=True, help="dns domain suffix for sanDNS entries")
    parser.add_argument("--subj-c", default="US", help="Subject C/Country field (default: US)")
    parser.add_argument("--subj-o", default="", help="Subject O/Organization field (optional)")
    parser.add_argument("--subj-ou", default="Athenz", help="Subject OU/OrganizationalUnit field (default: Athenz)")
    parser.add_argument("--provider", default="sys.auth.spacelift", help="Athenz Provider (default: sys.auth.spacelift)")
    parser.add_argument("--cacert", default="", help="CA certificate file (optional)")
    parser.add_argument("--spiffe-trust-domain", default="", help="SPIFFE trust domain (optional)")
    parser.add_argument("--expiry-time", type=int, default=360, help="expiry time in minutes (default: 360)")
    parser.add_argument("--version", action="store_true", help="Show version")
    return parser.parse_args(args)


def main(args: list[str] | None = None) -> None:
    logging.basicConfig(format="%(asctime)s %(message)s", level=logging.INFO)

    opts = parse_args(args)

    if opts.version:
        log.info("SIA Spacelift version: %s", VERSION)
        sys.exit(0)

    # get the OIDC token for the Spacelift run
    token, claims = get_oidc_token()

    # construct the instance id from the claims
    instance_id = get_instance_id(claims)

    subject = claims.get("sub", "")
    if not subject:
        log.fatal("unable to extract subject from OIDC token claims")
        sys.exit(1)

    # display the action and resource for athenz policy configuration
    # subject format: space:<space_id>:(stack|module):<caller_id>:run_type:<run_type>:scope:<scope>
    subject_parts = subject.split(":")
    if len(subject_parts) < 4:
        log.fatal("invalid subject format: %s", subject)
        sys.exit(1)

    specific_resource = ":".join(subject_parts[:6]) + ":*"
    broad_resource = ":".join(subject_parts[:4]) + ":*"

    log.info("Action:                          %s", "spacelift.run")
    log.info("Resource for specific run type:  %s", f"{opts.domain}:{specific_resource}")
    log.info("Resource for all run types:      %s", f"{opts.domain}:{broad_resource}")

    # generate RSA private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # generate CSR
    csr = generate_csr(
        private_key,
        opts.domain,
        opts.service,
        opts.provider,
        instance_id,
        opts.dns_domain,
        opts.spiffe_trust_domain,
        opts.subj_c,
        opts.subj_o,
        opts.subj_ou,
    )

    # register with ZTS
    identity = register_instance(
        opts.zts,
        opts.provider,
        opts.domain,
        opts.service,
        token,
        csr,
        opts.expiry_time,
        opts.cacert or None,
    )

    # write private key
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = Path(opts.key_file)
    key_path.write_bytes(key_pem)
    key_path.chmod(0o400)

    # write certificate
    cert_path = Path(opts.cert_file)
    cert_path.write_text(identity["x509Certificate"])
    cert_path.chmod(0o444)

    # write signer certificate if requested
    if opts.signer_cert_file and identity.get("x509CertificateSigner"):
        signer_path = Path(opts.signer_cert_file)
        signer_path.write_text(identity["x509CertificateSigner"])
        signer_path.chmod(0o444)


if __name__ == "__main__":
    main()
