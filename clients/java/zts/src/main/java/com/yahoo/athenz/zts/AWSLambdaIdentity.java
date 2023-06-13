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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class AWSLambdaIdentity {

    private PrivateKey privateKey;
    private X509Certificate x509Certificate;
    private String caCertificates;

    /**
     * Get the private key for the lambda service identity
     * @return privateKey
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Set the private key for the labmda service identity
     * @param privateKey use the given private key
     */
    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Get the x.509 certificate for the lambda service identity
     * @return x509Certificate
     */
    public X509Certificate getX509Certificate() {
        return x509Certificate;
    }

    /**
     * Set the x.509 certificate for the lambda service idenitty
     * @param x509Certificate use the given x.509 certificate
     */
    public void setX509Certificate(X509Certificate x509Certificate) {
        this.x509Certificate = x509Certificate;
    }

    /**
     * Get the Athenz CA certificates in pem format
     * @return certificates in pem format
     */
    public String getCACertificates() {
        return caCertificates;
    }

    /**
     * Set the Athenz CA certificates in pem format
     * @param caCertificates use the given set of ca certificates
     */
    public void setCaCertificates(String caCertificates) {
        this.caCertificates = caCertificates;
    }
}
