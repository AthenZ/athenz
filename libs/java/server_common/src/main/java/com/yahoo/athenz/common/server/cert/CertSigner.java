/*
 * Copyright 2016 Yahoo Inc.
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

public interface CertSigner {

    /**
     * Generate a signed X509 Certificate based on the given request. The
     * signer imposes how long the certificate is valid for. The result
     * must be the certificate in PEM format.
     * @param csr Certificate request
     * @param keyUsage Requested key usage (null for both server and client,
     * otherwise specified usage type: server or client)
     * @param expiryTime Requested certificate expiration time in minutes.
     * CertSigner might override this value with a smaller value.
     * @return X509 Certificate in PEM format
     */
    default String generateX509Certificate(String csr, String keyUsage, int expiryTime) {
        return null;
    }

    /**
     * Retrieve the CA certificate in PEM format. This will be returned
     * along with the x509 certificate back to the client.
     * @return the CA Certificate in PEM format
     */
    default String getCACertificate() {
        return null;
    }

    /**
     * Generate an SSH Certificate based on the given request
     * @param csr SSH Certificate Request
     * @return SSH Certificate
     */
    default String generateSSHCertificate(String csr) {
        return null;
    }

    /**
     * Retrieve the SSH Signer certificate for the given type
     * @param type signer type user or host
     * @return SSH Signer Certificate
     */
    default String getSSHCertificate(String type) {
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
