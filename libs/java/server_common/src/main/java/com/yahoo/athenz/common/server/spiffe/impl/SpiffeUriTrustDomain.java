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
import org.eclipse.jetty.util.StringUtil;

/**
 * Trust Domain implementation of SpiffeUriValidator interface. This class validates the SPIFFE URI
 * with the following formats:
 * Service Cert URI: spiffe://<trustDomain>/ns/<namespace>/sa/<domainName>.<serviceName>
 *     Example: spiffe://athenz.io/ns/prod/sa/athenz.api
 * Role Cert URI: spiffe://<trustDomain>/ns/<domainName>/ra/<roleName>
 *     Example: spiffe://athenz.io/ns/athenz/ra/readers
 */
public class SpiffeUriTrustDomain implements SpiffeUriValidator {

    private static final String SPIFFE_DEFAULT_NAMESPACE = "default";

    private static final String SPIFFE_PROP_TRUST_DOMAIN = "athenz.zts.spiffe_trust_domain";
    private static final String SPIFFE_TRUST_DOMAIN = System.getProperty(SPIFFE_PROP_TRUST_DOMAIN, "athenz.io");

    /**
     * Service Cert URI: spiffe://<trustDomain>/ns/<namespace>/sa/<domainName>.<serviceName>
     *     Example: spiffe://athenz.io/ns/prod/sa/athenz.api
     */
    @Override
    public boolean validateServiceCertUri(String spiffeUri, String domainName, String serviceName, String namespace) {
        final String ns = StringUtil.isEmpty(namespace) ? SPIFFE_DEFAULT_NAMESPACE : namespace;
        final String reqUri = String.format("spiffe://%s/ns/%s/sa/%s.%s", SPIFFE_TRUST_DOMAIN,
                ns, domainName, serviceName);
        return reqUri.equalsIgnoreCase(spiffeUri);
    }

    /**
     * Role Cert URI: spiffe://<trustDomain>/ns/<domainName>/ra/<roleName>
     *     Example: spiffe://athenz.io/ns/athenz/ra/readers
     */
    @Override
    public boolean validateRoleCertUri(String spiffeUri, String domainName, String roleName) {
        final String reqUri = String.format("spiffe://%s/ns/%s/ra/%s", SPIFFE_TRUST_DOMAIN,
                domainName, roleName);
        return reqUri.equalsIgnoreCase(spiffeUri);
    }
}
