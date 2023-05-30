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

package com.yahoo.athenz.zms;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class DomainOptionsTest {

    @Test
    public void testDomainOptions() {

        DomainOptions opts1 = new DomainOptions();
        opts1.setEnforceUniqueAWSAccounts(true);
        opts1.setEnforceUniqueGCPProjects(true);
        opts1.setEnforceUniqueAzureSubscriptions(true);
        opts1.setEnforceUniqueProductIds(true);

        DomainOptions opts2 = new DomainOptions();
        opts2.setEnforceUniqueAWSAccounts(true);
        opts2.setEnforceUniqueGCPProjects(true);
        opts2.setEnforceUniqueAzureSubscriptions(true);
        opts2.setEnforceUniqueProductIds(true);

        assertEquals(opts1, opts1);
        assertEquals(opts1, opts2);
        assertNotEquals("data", opts2);

        // verify getters

        assertTrue(opts1.getEnforceUniqueAWSAccounts());
        assertTrue(opts1.getEnforceUniqueGCPProjects());
        assertTrue(opts1.getEnforceUniqueAzureSubscriptions());
        assertTrue(opts1.getEnforceUniqueProductIds());

        opts1.setEnforceUniqueAWSAccounts(false);
        assertNotEquals(opts1, opts2);
        opts1.setEnforceUniqueAWSAccounts(true);
        assertEquals(opts1, opts2);

        opts1.setEnforceUniqueGCPProjects(false);
        assertNotEquals(opts1, opts2);
        opts1.setEnforceUniqueGCPProjects(true);
        assertEquals(opts1, opts2);

        opts1.setEnforceUniqueAzureSubscriptions(false);
        assertNotEquals(opts1, opts2);
        opts1.setEnforceUniqueAzureSubscriptions(true);
        assertEquals(opts1, opts2);

        opts1.setEnforceUniqueProductIds(false);
        assertNotEquals(opts1, opts2);
        opts1.setEnforceUniqueProductIds(true);
        assertEquals(opts1, opts2);
    }
}
