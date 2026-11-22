/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.server.identity;

import com.yahoo.athenz.common.server.ServerResourceException;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Stores the X.509 identity that the server issues for itself with its
 * own cert signer so that other components can use it. The server
 * generates the key pair, issues and refreshes the certificate, and
 * calls the store with every newly issued identity.
 */
public interface SelfIdentityStore {

    /**
     * Store the newly issued identity. The method is called during server
     * startup for the initial identity and then for every refreshed one.
     * @param privateKey private key of the identity
     * @param certificateChain issued certificate as returned by the cert signer:
     *        the leaf certificate optionally followed by its intermediate certificates
     * @param caCertificates CA certificate bundle of the server's cert signer.
     *        The list may be empty.
     * @throws ServerResourceException if the identity cannot be stored. During
     *         startup the server fails to start, otherwise the refresh is retried.
     */
    void storeIdentity(PrivateKey privateKey, List<X509Certificate> certificateChain,
            List<X509Certificate> caCertificates) throws ServerResourceException;
}
