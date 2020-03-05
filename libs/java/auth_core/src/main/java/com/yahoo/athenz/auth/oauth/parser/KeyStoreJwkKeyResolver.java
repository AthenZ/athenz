/*
 * Copyright 2020 Yahoo Inc.
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

import java.net.URL;
import java.security.Key;
import java.util.concurrent.TimeUnit;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolver;

/**
 * KeyResolver that get public key from key store or JWKS URL
 * @see <a href="https://tools.ietf.org/html/rfc7517" target="_top">RFC7517</a>
 */
public class KeyStoreJwkKeyResolver implements SigningKeyResolver {

    private static final Logger LOG = LoggerFactory.getLogger(KeyStoreJwkKeyResolver.class);

    private KeyStore keyStore = null;
    private JwkProvider provider = null;

    /**
     * @param  keyStore key store get the JWT public keys
     * @param  url      JWKS URL to download the JWT public keys
     */
    public KeyStoreJwkKeyResolver(KeyStore keyStore, URL url) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("KeyStoreJwkKeyResolver:JWK URL: " + url.toString());
        }

        this.keyStore = keyStore;

        // TODO: adjust the default value and use system prop (current default same as GuavaCachedJwkProvider default)
        this.provider = new JwkProviderBuilder(url).cached(5, 10, TimeUnit.HOURS).rateLimited(false).build();
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        String keyId = header.getKeyId();
        if (keyId == null || keyId.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("KeyStoreJwkKeyResolver:resolveSigningKey: invalid key ID " + keyId);
            }
            return null;
        }

        // 1. find in key store
        String issuer = claims.getIssuer();
        if (issuer != null && !issuer.isEmpty()) {
            String[] ds = AthenzUtils.splitPrincipalName(issuer);
            if (ds == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("KeyStoreJwkKeyResolver:resolveSigningKey: invalid issuer " + issuer);
                }
            } else {
                String domain = ds[0];
                String service = ds[1];

                String publicKey = this.keyStore.getPublicKey(domain, service, keyId);
                if (publicKey != null && !publicKey.isEmpty()) {
                    try {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("KeyStoreJwkKeyResolver:resolveSigningKey: will use public key from key store: ({}, {}, {})", domain, service, keyId);
                        }
                        return Crypto.loadPublicKey(publicKey);
                    } catch (CryptoException e) {
                        LOG.warn("KeyStoreJwkKeyResolver:resolveSigningKey: invalid public key format", e);
                    }
                }
            }
        }

        // 2. find in JWKS
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("KeyStoreJwkKeyResolver:resolveSigningKey: will use public key from JWKS: ({})", keyId);
            }
            return this.provider.get(keyId).getPublicKey();
        } catch (JwkException e) {
            LOG.warn("KeyStoreJwkKeyResolver:resolveSigningKey: jwks error", e);
        }

        return null;
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Key resolveSigningKey(JwsHeader header, String plaintext) {
        // JSON Web Encryption (JWE) not supported
        return null;
    }

}
