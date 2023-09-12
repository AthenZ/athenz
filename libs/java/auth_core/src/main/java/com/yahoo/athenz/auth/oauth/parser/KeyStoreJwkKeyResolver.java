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
package com.yahoo.athenz.auth.oauth.parser;

import java.security.Key;
import javax.net.ssl.SSLContext;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.auth.util.Crypto;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * KeyResolver that get public key from key store or JWKS URL
 * @see <a href="https://tools.ietf.org/html/rfc7517" target="_top">RFC7517</a>
 */
public class KeyStoreJwkKeyResolver implements SigningKeyResolver {

    private static final Logger LOG = LoggerFactory.getLogger(KeyStoreJwkKeyResolver.class);

    private static final String SYS_AUTH_DOMAIN = "sys.auth";

    private final KeyStore keyStore;
    private final SigningKeyResolver jwksResolver;

    /**
     * @param  keyStore key store get the JWT public keys
     * @param  url JWKS URL to download the JWT public keys
     * @param sslContext ssl context if server requires tls connections
     * @throws IllegalStateException if url is null
     */
    public KeyStoreJwkKeyResolver(KeyStore keyStore, String url, SSLContext sslContext) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("KeyStoreJwkKeyResolver:JWK URL: {}", url);
        }

        this.keyStore = keyStore;
        this.jwksResolver = new JwtsSigningKeyResolver(url, sslContext, true);
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        String keyId = header.getKeyId();
        if (keyId == null || keyId.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("KeyStoreJwkKeyResolver:resolveSigningKey: invalid key ID: {}", keyId);
            }
            return null;
        }

        // 1. find in key store
        String issuer = claims.getIssuer();
        if (this.keyStore != null && issuer != null && !issuer.isEmpty()) {
            String[] ds = AthenzUtils.splitPrincipalName(issuer);
            if (ds == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("KeyStoreJwkKeyResolver:resolveSigningKey: skip using KeyStore, invalid issuer: {}", issuer);
                }
            } else {
                String domain = ds[0];
                String service = ds[1];

                if (!SYS_AUTH_DOMAIN.equals(domain)) {
                    LOG.debug("KeyStoreJwkKeyResolver:resolveSigningKey: skip using KeyStore, invalid domain: {}", domain);
                } else {
                    String publicKey = this.keyStore.getPublicKey(domain, service, keyId);
                    if (publicKey != null && !publicKey.isEmpty()) {
                        try {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("KeyStoreJwkKeyResolver:resolveSigningKey: will use public key from key store: ({}, {}, {})", domain, service, keyId);
                            }
                            return Crypto.loadPublicKey(publicKey);
                        } catch (Exception ex) {
                            LOG.warn("KeyStoreJwkKeyResolver:resolveSigningKey: invalid public key format", ex);
                        }
                    }
                }
            }
        }

        // 2. find in JWKS
        if (LOG.isDebugEnabled()) {
            LOG.debug("KeyStoreJwkKeyResolver:resolveSigningKey: will use public key from JWKS: ({})", keyId);
        }
        return this.jwksResolver.resolveSigningKey(header, claims);
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, String plaintext) {
        // JSON Web Encryption (JWE) not supported
        return null;
    }

}
