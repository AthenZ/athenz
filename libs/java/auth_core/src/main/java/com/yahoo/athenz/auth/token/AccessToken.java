/*
 * Copyright 2019 Oath Holdings Inc.
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
package com.yahoo.athenz.auth.token;

import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;

public class AccessToken extends OAuth2Token {

    public static final String HDR_TOKEN_TYPE = "typ";
    public static final String HDR_TOKEN_JWT = "at+jwt";

    public static final String CLAIM_SCOPE = "scp";
    public static final String CLAIM_UID = "uid";
    public static final String CLAIM_CLIENT_ID = "client_id";
    public static final String CLAIM_CONFIRM = "cnf";

    public static final String CLAIM_CONFIRM_X509_HASH = "x5t#S256";

    private static final Logger LOG = LoggerFactory.getLogger(AccessToken.class);

    private String clientId;
    private String userId;
    private List<String> scope;
    private LinkedHashMap<String, Object> confirm;

    public AccessToken() {
        super();
    }

    public AccessToken(final String token, JwtsSigningKeyResolver keyResolver) {

        super(token, keyResolver);
        setAccessTokenFields();
    }

    public AccessToken(final String token, PublicKey publicKey) {

        super(token, publicKey);
        setAccessTokenFields();
    }

    void setAccessTokenFields() {
        final Claims body = claims.getBody();
        setClientId(body.get(CLAIM_CLIENT_ID, String.class));
        setUserId(body.get(CLAIM_UID, String.class));
        setScope(body.get(CLAIM_SCOPE, List.class));
        setConfirm(body.get(CLAIM_CONFIRM, LinkedHashMap.class));
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public List<String> getScope() {
        return scope;
    }

    public void setScope(List<String> scope) {
        this.scope = scope;
    }

    public LinkedHashMap<String, Object> getConfirm() {
        return confirm;
    }

    public void setConfirm(LinkedHashMap<String, Object> confirm) {
        this.confirm = confirm;
    }

    public void setConfirmEntry(final String key, final Object value) {
        if (confirm == null) {
            confirm = new LinkedHashMap<>();
        }
        confirm.put(key, value);
    }

    public void setConfirmX509CertHash(X509Certificate cert) {
        setConfirmEntry(CLAIM_CONFIRM_X509_HASH, getX509CertificateHash(cert));
    }

    public boolean confirmX509CertHash(X509Certificate cert) {
        final String cnfHash = (String) getConfirmEntry(CLAIM_CONFIRM_X509_HASH);
        if (cnfHash == null) {
            return false;
        }
        final String certHash = getX509CertificateHash(cert);
        return cnfHash.equals(certHash);
    }

    String getX509CertificateHash(X509Certificate cert) {
        try {
            byte[] encCert = Crypto.sha256(cert.getEncoded());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(encCert);
        } catch (CryptoException | CertificateEncodingException ex) {
            LOG.error("Unable to get X.509 certificate hash", ex);
            return null;
        }
    }

    public Object getConfirmEntry(final String key) {
        return confirm == null ? null : confirm.get(key);
    }

    public String getSignedToken(final PrivateKey key, final String keyId,
            final SignatureAlgorithm keyAlg) {

        return Jwts.builder().setSubject(subject)
                .setIssuedAt(Date.from(Instant.ofEpochSecond(issueTime)))
                .setExpiration(Date.from(Instant.ofEpochSecond(expiryTime)))
                .setIssuer(issuer)
                .setAudience(audience)
                .claim(CLAIM_AUTH_TIME, authTime)
                .claim(CLAIM_VERSION, version)
                .claim(CLAIM_SCOPE, scope)
                .claim(CLAIM_UID, userId)
                .claim(CLAIM_CLIENT_ID, clientId)
                .claim(CLAIM_CONFIRM, confirm)
                .setHeaderParam(HDR_KEY_ID, keyId)
                .setHeaderParam(HDR_TOKEN_TYPE, HDR_TOKEN_JWT)
                .signWith(keyAlg, key)
                .compact();
    }
}
