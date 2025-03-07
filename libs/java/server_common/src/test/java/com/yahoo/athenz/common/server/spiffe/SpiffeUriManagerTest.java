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

import com.yahoo.athenz.common.server.spiffe.impl.SpiffeUriTrustDomain;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class SpiffeUriManagerTest {

    @BeforeClass
    public void setup() {
        System.setProperty("athenz.zts.spiffe_trust_domain", "spiffe.athenz.io");
    }

    @Test
    public void testValidateServiceCertUriDefaultClasses() {

        System.clearProperty("athenz.zts.spiffe_uri_validator_classes");
        SpiffeUriManager manager = new SpiffeUriManager();

        assertTrue(manager.validateServiceCertUri("spiffe://athenz/sa/api", "athenz", "api", null));
        assertTrue(manager.validateServiceCertUri("spiffe://athenz/sa/api", "athenz", "api", "default"));

        assertFalse(manager.validateServiceCertUri("spiffe://athenz/sa/api", "athenz.prod", "api", "default"));
        assertFalse(manager.validateServiceCertUri("spiffe://athenz/sa/api", "athenz", "backend", "default"));

        assertTrue(manager.validateServiceCertUri("spiffe://spiffe.athenz.io/ns/default/sa/athenz.api", "athenz", "api", null));
        assertTrue(manager.validateServiceCertUri("spiffe://spiffe.athenz.io/ns/default/sa/athenz.api", "athenz", "api", "default"));
        assertTrue(manager.validateServiceCertUri("spiffe://spiffe.athenz.io/ns/prod/sa/athenz.api", "athenz", "api", "prod"));

        assertFalse(manager.validateServiceCertUri("spiffe://spiffe.athenz.io/ns/default/sa/athenz.api", "athenz", "api", "prod"));
        assertFalse(manager.validateServiceCertUri("spiffe://spiffe.athenz.io/ns/default/sa/athenz.backend", "athenz", "api", "default"));
        assertFalse(manager.validateServiceCertUri("spiffe://spiffe.athenz.io/ns/prod/sa/athenz.api", "athenz.prod", "api", "prod"));

        assertFalse(manager.validateServiceCertUri("spiffe://athenz.io/ns/prod/sa/athenz.api", "athenz", "api", "prod"));
    }

    @Test
    public void testValidateRoleCertUriDefaultClasses() {

        System.clearProperty("athenz.zts.spiffe_uri_validator_classes");
        SpiffeUriManager manager = new SpiffeUriManager();

        assertTrue(manager.validateRoleCertUri("spiffe://athenz/ra/readers", "athenz", "readers"));
        assertTrue(manager.validateRoleCertUri("spiffe://athenz/ra/writers", "athenz", "writers"));

        assertFalse(manager.validateRoleCertUri("spiffe://athenz/ra/readers", "athenz.prod", "readers"));
        assertFalse(manager.validateRoleCertUri("spiffe://athenz/ra/readers", "athenz", "writers"));

        assertTrue(manager.validateRoleCertUri("spiffe://spiffe.athenz.io/ns/athenz/ra/readers", "athenz", "readers"));

        assertFalse(manager.validateRoleCertUri("spiffe://spiffe.athenz.io/ns/athenz/ra/readers", "athenz", "writers"));
        assertFalse(manager.validateRoleCertUri("spiffe://spiffe.athenz.io/ns/athenz/ra/readers", "athenz.prod", "readers"));

        assertFalse(manager.validateRoleCertUri("spiffe://athenz.io/ns/athenz/ra/readers", "athenz", "readers"));
    }

    @Test
    public void testValidateInvalidClass() {

        System.setProperty("athenz.zts.spiffe_uri_validator_classes", "com.yahoo.athenz.common.server.spiffe.impl.InvalidClass");
        try {
            new SpiffeUriManager();
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Invalid spiffe uri validator: com.yahoo.athenz.common.server.spiffe.impl.InvalidClass"));
        }
        System.clearProperty("athenz.zts.spiffe_uri_validator_classes");
    }
}
