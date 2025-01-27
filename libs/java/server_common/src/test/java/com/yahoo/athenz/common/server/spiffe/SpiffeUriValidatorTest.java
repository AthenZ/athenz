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

package com.yahoo.athenz.common.server.spiffe;

import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class SpiffeUriValidatorTest {

    @Test
    public void testValidate() {

        final String trustDomain = "athenz.io";

        SpiffeUriValidator validator = new SpiffeUriValidator() {
            @Override
            public boolean validateServiceCertUri(String spiffeUri, String domainName, String serviceName, String namespace) {
                final String expectedUri = String.format("spiffe://%s/ns/%s/sa/%s.%s", trustDomain, namespace,
                        domainName, serviceName);
                return spiffeUri.equals(expectedUri);
            }

            @Override
            public boolean validateRoleCertUri(String spiffeUri, String domainName, String roleName) {
                final String expectedUri = String.format("spiffe://%s/ns/%s/ra/%s", trustDomain,
                        domainName, roleName);
                return spiffeUri.equals(expectedUri);
            }
        };

        assertTrue(validator.validateServiceCertUri("spiffe://athenz.io/ns/prod/sa/athenz.api", "athenz", "api", "prod"));
        assertFalse(validator.validateServiceCertUri("spiffe://athenz.io/ns/prod/sa/athenz.api", "athenz", "api", "dev"));

        assertTrue(validator.validateRoleCertUri("spiffe://athenz.io/ns/athenz/ra/readers", "athenz", "readers"));
        assertFalse(validator.validateRoleCertUri("spiffe://athenz.io/ns/athenz/ra/readers", "athenz", "writers"));
    }
}
