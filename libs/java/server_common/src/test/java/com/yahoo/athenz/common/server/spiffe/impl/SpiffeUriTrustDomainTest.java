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

package com.yahoo.athenz.common.server.spiffe.impl;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class SpiffeUriTrustDomainTest {

    @BeforeClass
    public void setup() {
        System.setProperty("athenz.zts.spiffe_trust_domain", "spiffe.athenz.io");
    }

    @Test
    public void testValidateServiceCertUri() {

        SpiffeUriTrustDomain validator = new SpiffeUriTrustDomain();
        assertTrue(validator.validateServiceCertUri("spiffe://spiffe.athenz.io/ns/default/sa/athenz.api", "athenz", "api", null));
        assertTrue(validator.validateServiceCertUri("spiffe://spiffe.athenz.io/ns/default/sa/athenz.api", "athenz", "api", "default"));
        assertTrue(validator.validateServiceCertUri("spiffe://spiffe.athenz.io/ns/prod/sa/athenz.api", "athenz", "api", "prod"));

        assertFalse(validator.validateServiceCertUri("spiffe://spiffe.athenz.io/ns/default/sa/athenz.api", "athenz", "api", "prod"));
        assertFalse(validator.validateServiceCertUri("spiffe://spiffe.athenz.io/ns/default/sa/athenz.backend", "athenz", "api", "default"));
        assertFalse(validator.validateServiceCertUri("spiffe://spiffe.athenz.io/ns/prod/sa/athenz.api", "athenz.prod", "api", "prod"));

        assertFalse(validator.validateServiceCertUri("spiffe://athenz.io/ns/prod/sa/athenz.api", "athenz", "api", "prod"));
    }

    @Test
    public void testValidateRoleCertUri() {

        SpiffeUriTrustDomain validator = new SpiffeUriTrustDomain();
        assertTrue(validator.validateRoleCertUri("spiffe://spiffe.athenz.io/ns/athenz/ra/readers", "athenz", "readers"));

        assertFalse(validator.validateRoleCertUri("spiffe://spiffe.athenz.io/ns/athenz/ra/readers", "athenz", "writers"));
        assertFalse(validator.validateRoleCertUri("spiffe://spiffe.athenz.io/ns/athenz/ra/readers", "athenz.prod", "readers"));

        assertFalse(validator.validateRoleCertUri("spiffe://athenz.io/ns/athenz/ra/readers", "athenz", "readers"));
    }
}
