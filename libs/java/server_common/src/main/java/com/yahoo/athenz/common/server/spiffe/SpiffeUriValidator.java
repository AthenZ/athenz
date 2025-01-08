/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.common.server.spiffe;

/**
 * An interface that allows system administrators to validate SPIFFE URIs
 * based on their own requirements.
 */
public interface SpiffeUriValidator {

    /**
     * Validate the SPIFFE URI for service identity certificates based on the system requirements.
     * @param spiffeUri the SPIFFE URI to be validated (e.g. spiffe://athenz.domain/sa/service)
     * @param domainName the domain name of the service
     * @param serviceName the service name
     * @param namespace the namespace of the service (typically a Kubernetes namespace)
     * @return true if the SPIFFE URI is valid, false otherwise
     */
    boolean validateServiceCertUri(final String spiffeUri, final String domainName, final String serviceName, final String namespace);

    /**
     * Validate the SPIFFE URI for rike certificates based on the system requirements.
     * @param spiffeUri the SPIFFE URI to be validated (e.g. spiffe://athenz.domain/ra/writers)
     * @param domainName the domain name of the service
     * @param roleName the role name
     * @return true if the SPIFFE URI is valid, false otherwise
     */
    boolean validateRoleCertUri(final String spiffeUri, final String domainName, final String roleName);
}
