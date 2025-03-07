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

import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class SpiffeUriBasicTest {

    @Test
    public void testValidateServiceCertUri() {
        SpiffeUriBasic validator = new SpiffeUriBasic();

        assertTrue(validator.validateServiceCertUri("spiffe://athenz/sa/api", "athenz", "api", null));
        assertTrue(validator.validateServiceCertUri("spiffe://athenz/sa/api", "athenz", "api", "default"));

        assertFalse(validator.validateServiceCertUri("spiffe://athenz/sa/api", "athenz.prod", "api", "default"));
        assertFalse(validator.validateServiceCertUri("spiffe://athenz/sa/api", "athenz", "backend", "default"));
    }

    @Test
    public void testValidateRoleCertUri() {
        SpiffeUriBasic validator = new SpiffeUriBasic();

        assertTrue(validator.validateRoleCertUri("spiffe://athenz/ra/readers", "athenz", "readers"));
        assertTrue(validator.validateRoleCertUri("spiffe://athenz/ra/writers", "athenz", "writers"));

        assertFalse(validator.validateRoleCertUri("spiffe://athenz/ra/readers", "athenz.prod", "readers"));
        assertFalse(validator.validateRoleCertUri("spiffe://athenz/ra/readers", "athenz", "writers"));
    }
}
