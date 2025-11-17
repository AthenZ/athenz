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
package com.yahoo.athenz.auth;

/**
 * The interface for a service identity provider. The container of the service defines the actual
 * implementation.
 */
public interface ServiceIdentityProvider {

    /**
     * Return the corresponding principal object for the service identity
     *
     * @param domainName the name of the domain
     * @param serviceName the name of the service
     * @return the identity of the service in the form of a Principal.
     */
    Principal getIdentity(String domainName, String serviceName);

    /**
     * Return the client assertion type if the identity provider
     * returns the assertion details for the token request
     * @return the assertion type
     */
    default String getClientAssertionType() {
        return null;
    }

    /**
     * Return the client assertion credentials if the identity provider
     * returns the assertion details for the token request
     * @return the assertion credentials
     */
    default String getClientAssertionValue() {
        return null;
    }
}
