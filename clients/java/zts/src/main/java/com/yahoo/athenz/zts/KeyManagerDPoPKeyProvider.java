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
package com.yahoo.athenz.zts;

import com.oath.auth.KeyRefresher;

import javax.net.ssl.X509KeyManager;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * DPoP key provider that signs proofs with the service identity key held by
 * an X.509 key manager, typically the KeyManagerProxy of the KeyRefresher
 * used for the client's mTLS connections. Every call returns the key manager's
 * current key, so when the KeyRefresher reloads a refreshed key and
 * certificate, DPoP proofs follow the new identity key without any additional
 * configuration. The proof key always matches the client certificate key, as
 * required when ZTS enables athenz.zts.dpop_require_cert_key_match.
 */
public final class KeyManagerDPoPKeyProvider implements DPoPKeyProvider {

    private static final String[] KEY_TYPES = { "EC", "RSA" };
    private static final int MAX_READ_ATTEMPTS = 3;

    private final X509KeyManager keyManager;
    private final String certAlias;

    /**
     * Sign proofs with the identity key managed by the given key refresher
     * @param keyRefresher key refresher used for the client's mTLS connections
     */
    public KeyManagerDPoPKeyProvider(KeyRefresher keyRefresher) {
        this(keyRefresher.getKeyManagerProxy(), null);
    }

    /**
     * Sign proofs with the client key held by the given key manager
     * @param keyManager key manager used for the client's mTLS connections
     */
    public KeyManagerDPoPKeyProvider(X509KeyManager keyManager) {
        this(keyManager, null);
    }

    /**
     * Sign proofs with the key stored under the given alias in the key manager
     * @param keyManager key manager used for the client's mTLS connections
     * @param certAlias alias of the key entry, or null to use the alias the
     *          key manager selects for client authentication
     */
    public KeyManagerDPoPKeyProvider(X509KeyManager keyManager, final String certAlias) {
        this.keyManager = Objects.requireNonNull(keyManager, "keyManager must not be null");
        this.certAlias = certAlias;
    }

    /**
     * @return the key manager's current private key with the public key of its certificate
     * @throws IllegalStateException if the key manager has no usable client key. Returning
     *          null instead would silently disable DPoP for the request.
     */
    @Override
    public KeyPair getKeyPair() {

        // the KeyRefresher can swap the key manager between our calls so we
        // only return a key and certificate that were read from the same one

        for (int attempt = 0; attempt < MAX_READ_ATTEMPTS; attempt++) {
            final String alias = certAlias != null ? certAlias : keyManager.chooseClientAlias(KEY_TYPES, null, null);
            if (alias == null) {
                throw new IllegalStateException("DPoP key provider: key manager has no EC or RSA client key");
            }
            final PrivateKey privateKey = keyManager.getPrivateKey(alias);
            final X509Certificate[] certChain = keyManager.getCertificateChain(alias);
            if (privateKey == null || certChain == null || certChain.length == 0) {
                throw new IllegalStateException("DPoP key provider: no private key or certificate for alias: " + alias);
            }
            final PublicKey publicKey = certChain[0].getPublicKey();
            final X509Certificate[] currentCertChain = keyManager.getCertificateChain(alias);
            if (privateKey.equals(keyManager.getPrivateKey(alias)) && currentCertChain != null
                    && currentCertChain.length != 0 && publicKey.equals(currentCertChain[0].getPublicKey())) {
                return new KeyPair(publicKey, privateKey);
            }
        }
        throw new IllegalStateException("DPoP key provider: key manager changed while reading the key");
    }
}
