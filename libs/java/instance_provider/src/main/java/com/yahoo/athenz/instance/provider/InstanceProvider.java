/*
 * Copyright 2017 Yahoo Holdings, Inc.
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
package com.yahoo.athenz.instance.provider;

import com.yahoo.athenz.auth.KeyStore;
import javax.net.ssl.SSLContext;

public interface InstanceProvider {

    enum Scheme {
        HTTP,
        CLASS,
        UNKNOWN
    }

    /**
     * Get Provider scheme. Currently supported schemes are HTTP
     * or CLASS. By default we'll return UNKNOWN.
     */

    default Scheme getProviderScheme() {
        return Scheme.UNKNOWN;
    }

    /**
     * Set provider details and initialize the provider object
     * @param provider name of the provider (service identity name)
     * @param endpoint endpoint for the provider
     * @param sslContext SSL Context for TLS communication
     * @param keyStore Athenz Keystore provider in case
     * it needs to retrieve public key for a service to validate
     * attestation data.
     */
    void initialize(String provider, String endpoint, SSLContext sslContext, KeyStore keyStore);
    
    /**
     * Contact the Instance provider and confirm that the requested
     * instance details are valid in order for ZTS to issue a
     * service identity certificate for the instance
     * @param confirmation instance confirmation details (including instance
     * identity document, its signature and other details)
     * @return InstanceConfirmation object if the confirmation is successful
     * @throws ResourceException in case of any errors
     */
    InstanceConfirmation confirmInstance(InstanceConfirmation confirmation);
    
    /**
     * Contact the Instance provider and confirm that the requested
     * instance details are valid in order for ZTS to refresh a
     * service identity certificate for the instance
     * @param confirmation refresh confirmation details (including instance
     * identity document, its signature and other details)
     * @return InstanceConfirmation object if the confirmation is successful
     * @throws ResourceException in case of any errors
     */
    InstanceConfirmation refreshInstance(InstanceConfirmation confirmation);
    
    /**
     * Close the client and, if necessary, release any allocated resources
     */
    default void close() {
    }
}
