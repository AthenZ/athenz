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

package com.yahoo.athenz.common.server.spiffe.impl;

import com.yahoo.athenz.common.server.spiffe.SpiffeUriValidator;

/**
 * Basic implementation of SpiffeUriValidator interface. This class validates the SPIFFE URI
 * with the following formats:
 * Service Cert URI: spiffe://<domainName>/sa/<serviceName>
 *     Example: spiffe://athenz/sa/api
 * Role Cert URI: spiffe://<domainName>/ra/<roleName>
 *     Example: spiffe://athenz/ra/readers
 */
public class SpiffeUriBasic implements SpiffeUriValidator {

    /**
     * Supported Service Cert URI: spiffe://<domainName>/sa/<serviceName>
     *     Example: spiffe://athenz/sa/api
     */
    @Override
    public boolean validateServiceCertUri(String spiffeUri, String domainName, String serviceName, String namespace) {
        final String reqUri = String.format("spiffe://%s/sa/%s", domainName, serviceName);
        return reqUri.equalsIgnoreCase(spiffeUri);
    }

    /**
     * Supported Role Cert URI: spiffe://<domainName>/ra/<roleName>
     *     Example: spiffe://athenz/ra/readers
     */
    @Override
    public boolean validateRoleCertUri(String spiffeUri, String domainName, String roleName) {
        final String reqUri = String.format("spiffe://%s/ra/%s", domainName, roleName);
        return reqUri.equalsIgnoreCase(spiffeUri);
    }
}
