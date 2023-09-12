/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yahoo.athenz.auth.oauth.validator;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessToken;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessTokenException;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;

/**
 * Validator interface for validating OAuth2 JWT access token
 */
public interface OAuthJwtAccessTokenValidator {

    /**
     * validate JWT
     * @param  jwt                          jwt object
     * @throws OAuthJwtAccessTokenException throws when the JWT is invalid
     */
    void validate(OAuthJwtAccessToken jwt) throws OAuthJwtAccessTokenException;

    /**
     * validate client ID claim
     * @param  jwt                          jwt object
     * @param  clientId                     expected client ID
     * @throws OAuthJwtAccessTokenException throws when the client ID in the JWT is invalid
     */
    void validateClientId(OAuthJwtAccessToken jwt, String clientId) throws OAuthJwtAccessTokenException;

    /**
     * validate certificate binding of the JWT
     * @param  jwt                          jwt object
     * @param  certificateThumbprint        expected certificate thumbprint
     * @throws OAuthJwtAccessTokenException throws when the certificate thumbprint in the JWT is invalid
     */
    void validateCertificateBinding(OAuthJwtAccessToken jwt, String certificateThumbprint) throws OAuthJwtAccessTokenException;

    /**
     * validate certificate binding of the JWT
     * @param  jwt                          jwt object
     * @param  x509Certificate              the bound certificate
     * @throws OAuthJwtAccessTokenException throws when the certificate thumbprint in the JWT is invalid
     */
    default void validateCertificateBinding(OAuthJwtAccessToken jwt, X509Certificate x509Certificate) throws OAuthJwtAccessTokenException {
        String certificateThumbprint;
        try {
            certificateThumbprint = this.getX509CertificateThumbprint(x509Certificate);
        } catch (CertificateEncodingException | CryptoException e) {
            throw new OAuthJwtAccessTokenException(e);
        }
        this.validateCertificateBinding(jwt, certificateThumbprint);
    }

    /**
     * return certificate's common name
     * @param x509Certificate x509Certificate
     * @return X.509 certificate common name
     * @throws NullPointerException on null
     */
    default String getX509CertificateCommonName(X509Certificate x509Certificate) {
        return Crypto.extractX509CertCommonName(x509Certificate);
    }

    /**
     * return certificate thumbprint
     * @param x509Certificate x509Certificate
     * @return SHA-256 hash of the DER encoding of the X.509 certificate in base64url-encoded without padding format
     * @throws CertificateEncodingException CertificateEncodingException
     * @throws CryptoException              CryptoException
     * @throws NullPointerException         on null
     * @see <a href="https://tools.ietf.org/html/draft-ietf-oauth-mtls-17#section-3.1" target="_top">draft-ietf-oauth-mtls-17</a>
     */
    default String getX509CertificateThumbprint(X509Certificate x509Certificate) throws CertificateEncodingException, CryptoException {
        byte[] encodedCert = Crypto.sha256(x509Certificate.getEncoded());
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encodedCert);
    }

}
