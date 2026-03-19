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

"""Tests for the Spacelift SIA agent."""

from __future__ import annotations

import json
import time
from unittest.mock import patch

import jwt as pyjwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import load_pem_x509_csr

from sia import generate_csr, get_instance_id, get_oidc_token, parse_args, register_instance


def _make_test_token(claims: dict | None = None) -> str:
    """Create a JWT token (unsigned) for testing purposes."""
    payload = {
        "iss": "https://demo.app.spacelift.io",
        "aud": "demo.app.spacelift.io",
        "sub": "space:my-space:stack:my-stack:run_type:TRACKED:scope:write",
        "spaceId": "my-space",
        "callerType": "stack",
        "callerId": "my-stack",
        "runType": "TRACKED",
        "runId": "run-uuid-123",
        "scope": "write",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    if claims:
        payload.update(claims)
    return pyjwt.encode(payload, "secret", algorithm="HS256")


# --- get_oidc_token ---


class TestGetOidcToken:
    def test_from_env(self, monkeypatch: pytest.MonkeyPatch, tmp_path):
        token = _make_test_token()
        monkeypatch.setenv("SPACELIFT_OIDC_TOKEN", token)

        raw, claims = get_oidc_token(token_file=str(tmp_path / "nonexistent"))
        assert raw == token
        assert claims["spaceId"] == "my-space"
        assert claims["callerId"] == "my-stack"
        assert claims["runId"] == "run-uuid-123"

    def test_from_file(self, monkeypatch: pytest.MonkeyPatch, tmp_path):
        token = _make_test_token()
        token_file = tmp_path / "spacelift.oidc"
        token_file.write_text(token)
        monkeypatch.delenv("SPACELIFT_OIDC_TOKEN", raising=False)

        raw, claims = get_oidc_token(
            env_var="SPACELIFT_OIDC_TOKEN",
            token_file=str(token_file),
        )
        assert raw == token
        assert claims["sub"] == "space:my-space:stack:my-stack:run_type:TRACKED:scope:write"

    def test_strips_whitespace(self, monkeypatch: pytest.MonkeyPatch, tmp_path):
        token = _make_test_token()
        monkeypatch.setenv("SPACELIFT_OIDC_TOKEN", f"  {token}  \n")

        raw, claims = get_oidc_token(token_file=str(tmp_path / "nonexistent"))
        assert raw == token
        assert claims["spaceId"] == "my-space"

    def test_missing_token(self, monkeypatch: pytest.MonkeyPatch, tmp_path):
        monkeypatch.delenv("SPACELIFT_OIDC_TOKEN", raising=False)

        with pytest.raises(RuntimeError, match="Unable to obtain Spacelift OIDC token"):
            get_oidc_token(
                env_var="SPACELIFT_OIDC_TOKEN",
                token_file=str(tmp_path / "nonexistent"),
            )

    def test_invalid_token(self, monkeypatch: pytest.MonkeyPatch, tmp_path):
        monkeypatch.setenv("SPACELIFT_OIDC_TOKEN", "not-a-jwt")

        with pytest.raises(RuntimeError, match="Unable to parse Spacelift OIDC token"):
            get_oidc_token(token_file=str(tmp_path / "nonexistent"))


# --- get_instance_id ---


class TestGetInstanceId:
    def test_valid_claims(self):
        claims = {"spaceId": "my-space", "callerId": "my-stack", "runId": "run-123"}
        assert get_instance_id(claims) == "my-space:my-stack:run-123"

    @pytest.mark.parametrize("missing_field", ["spaceId", "callerId", "runId"])
    def test_missing_field(self, missing_field: str):
        claims = {"spaceId": "s", "callerId": "c", "runId": "r"}
        del claims[missing_field]

        with pytest.raises(RuntimeError, match=missing_field):
            get_instance_id(claims)

    def test_empty_field(self):
        claims = {"spaceId": "", "callerId": "my-stack", "runId": "run-123"}
        with pytest.raises(RuntimeError, match="spaceId"):
            get_instance_id(claims)


# --- generate_csr ---


class TestGenerateCsr:
    @pytest.fixture()
    def private_key(self):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def test_basic_csr(self, private_key):
        csr_pem = generate_csr(
            private_key, "sports", "api", "sys.auth.spacelift",
            "my-space:my-stack:run-123", "athenz.io",
        )
        assert "BEGIN CERTIFICATE REQUEST" in csr_pem

        csr = load_pem_x509_csr(csr_pem.encode())
        assert csr.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )[0].value == "sports.api"

        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "api.sports.athenz.io" in dns_names

        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        assert "athenz://instanceid/sys.auth.spacelift/my-space:my-stack:run-123" in uris

    def test_csr_with_spiffe(self, private_key):
        csr_pem = generate_csr(
            private_key, "sports", "api", "sys.auth.spacelift",
            "my-space:my-stack:run-123", "athenz.io",
            spiffe_trust_domain="athenz",
        )

        csr = load_pem_x509_csr(csr_pem.encode())
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        assert "spiffe://athenz/ns/default/sa/sports.api" in uris
        assert "athenz://instanceid/sys.auth.spacelift/my-space:my-stack:run-123" in uris

    def test_csr_subject_fields(self, private_key):
        csr_pem = generate_csr(
            private_key, "sports", "api", "sys.auth.spacelift",
            "id", "athenz.io",
            subj_c="DE", subj_o="MyOrg", subj_ou="MyUnit",
        )

        csr = load_pem_x509_csr(csr_pem.encode())
        subject = csr.subject
        assert subject.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)[0].value == "DE"
        assert subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value == "MyOrg"
        assert subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "MyUnit"


# --- register_instance ---


class TestRegisterInstance:
    def test_successful_registration(self):
        response_data = {
            "x509Certificate": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            "x509CertificateSigner": "-----BEGIN CERTIFICATE-----\nsigner\n-----END CERTIFICATE-----",
        }

        with patch("sia.requests.post") as mock_post:
            mock_post.return_value.status_code = 201
            mock_post.return_value.json.return_value = response_data

            result = register_instance(
                "https://zts.athenz.io/zts/v1",
                "sys.auth.spacelift", "sports", "api",
                "oidc-token", "csr-pem", 360,
            )

        assert result["x509Certificate"] == response_data["x509Certificate"]
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert call_kwargs[0][0] == "https://zts.athenz.io/zts/v1/instance"
        assert call_kwargs[1]["json"]["provider"] == "sys.auth.spacelift"
        assert call_kwargs[1]["json"]["attestationData"] == "oidc-token"

    def test_failed_registration(self):
        with patch("sia.requests.post") as mock_post:
            mock_post.return_value.status_code = 403
            mock_post.return_value.text = "Forbidden"

            with pytest.raises(RuntimeError, match="Unable to register instance: 403"):
                register_instance(
                    "https://zts.athenz.io/zts/v1",
                    "sys.auth.spacelift", "sports", "api",
                    "oidc-token", "csr-pem", 360,
                )

    def test_with_ca_cert(self):
        with patch("sia.requests.post") as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = {"x509Certificate": "cert"}

            register_instance(
                "https://zts.athenz.io/zts/v1",
                "sys.auth.spacelift", "sports", "api",
                "token", "csr", 360, ca_cert="/path/to/ca.pem",
            )

        assert mock_post.call_args[1]["verify"] == "/path/to/ca.pem"

    def test_url_trailing_slash_stripped(self):
        with patch("sia.requests.post") as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = {"x509Certificate": "cert"}

            register_instance(
                "https://zts.athenz.io/zts/v1/",
                "sys.auth.spacelift", "sports", "api",
                "token", "csr", 360,
            )

        assert mock_post.call_args[0][0] == "https://zts.athenz.io/zts/v1/instance"


# --- parse_args ---


class TestParseArgs:
    def test_required_args(self):
        opts = parse_args([
            "--key-file", "/tmp/key", "--cert-file", "/tmp/cert",
            "--domain", "sports", "--service", "api",
            "--zts", "https://zts.athenz.io", "--dns-domain", "athenz.io",
        ])
        assert opts.domain == "sports"
        assert opts.provider == "sys.auth.spacelift"
        assert opts.expiry_time == 360

    def test_defaults(self):
        opts = parse_args([
            "--key-file", "k", "--cert-file", "c",
            "--domain", "d", "--service", "s",
            "--zts", "z", "--dns-domain", "dns",
        ])
        assert opts.subj_c == "US"
        assert opts.subj_ou == "Athenz"
        assert opts.provider == "sys.auth.spacelift"
        assert opts.cacert == ""
        assert opts.spiffe_trust_domain == ""
