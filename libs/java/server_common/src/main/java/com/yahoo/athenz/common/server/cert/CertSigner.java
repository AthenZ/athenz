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
package com.yahoo.athenz.common.server.cert;

import com.yahoo.athenz.common.server.ServerResourceException;

public interface CertSigner {

    /**
     * Generate a signed X509 Certificate based on the given request. The
     * signer imposes how long the certificate is valid for. The result
     * must be the certificate in PEM format.
     * @param provider (optional) Athenz provider that validated certificate request
     * @param certIssuer (optional) Request to have cert signed by given issuer
     * @param csr Certificate request
     * @param keyUsage Requested key usage (null for both server and client,
     * otherwise specified usage type: server or client)
     * @param expiryTime Requested certificate expiration time in minutes.
     * CertSigner might override this value with a smaller value.
     * @param priority requested priority for processing the request signing service
     * @param signerKeyId requested signer key id if configured for the domain
     * @return X509 Certificate in PEM format
     */
    default String generateX509Certificate(String provider, String certIssuer, String csr,
            String keyUsage, int expiryTime, Priority priority, String signerKeyId)
            throws ServerResourceException {
        return null;
    }

    /**
     * Retrieve the CA certificate in PEM format. This will be returned
     * along with the x509 certificate back to the client. The function
     * should return all the CAs defined for the provider
     * @param provider (optional) CA certificate for given Athenz provider
     * @param signerKeyId requested signer key id if configured for the domain
     * @return the CA Certificate in PEM format
     */
    default String getCACertificate(String provider, String signerKeyId) throws ServerResourceException {
        return null;
    }

    /** Retrieve the certificate max expiry time supported
     * by the given signer
     * @return expiry time in minutes
     */
    default int getMaxCertExpiryTimeMins() {
        return 0;
    }
    
    /**
     * Close the certSigner signer object and release all
     * allocated resources (if any)
     */
    default void close() {
    }
}
