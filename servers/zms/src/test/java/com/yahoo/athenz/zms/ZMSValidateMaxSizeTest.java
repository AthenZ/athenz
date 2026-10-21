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

import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

/**
 * Verifies that over-long values passed through the ZMS API are rejected with a
 * proper 400 error based on the maxSize constraints added to the RDL name types.
 * Without a maxSize, the underlying regex matcher throws a StackOverflowError on
 * very long values (the recursive compound-name patterns), which would surface as
 * an unhandled 500. These tests drive the real ZMS API methods end to end.
 */
public class ZMSValidateMaxSizeTest {

    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();

    @BeforeClass
    public void startMemoryMySQL() {
        zmsTestInitializer.startMemoryMySQL();
    }

    @AfterClass
    public void stopMemoryMySQL() {
        zmsTestInitializer.stopMemoryMySQL();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        zmsTestInitializer.setUp();
    }

    @AfterMethod
    public void shutDown() throws Exception {
        zmsTestInitializer.shutDown();
    }

    // a value well over any name maxSize - large enough that, without a maxSize
    // constraint, the recursive compound-name regex would overflow the stack
    private String longName(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append('a');
        }
        return sb.toString();
    }

    @Test
    public void testGetDomainDomainNameTooLong() {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String longDomain = longName(9000);
        try {
            zmsImpl.getDomain(ctx, longDomain);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Invalid DomainName value: "), ex.getMessage());
            assertTrue(ex.getMessage().contains("String larger than maxSize of 512 for type DomainName"),
                    ex.getMessage());
            // the reported value must be truncated and not contain the full input
            assertTrue(ex.getMessage().contains("..."), ex.getMessage());
        }
    }

    @Test
    public void testGetRoleRoleNameTooLong() {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String longRole = longName(9000);
        try {
            zmsImpl.getRole(ctx, "coretech", longRole, false, false, false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("String larger than maxSize of 512 for type EntityName"),
                    ex.getMessage());
        }
    }

    @Test
    public void testGetPolicyPolicyNameTooLong() {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String longPolicy = longName(9000);
        try {
            zmsImpl.getPolicy(ctx, "coretech", longPolicy);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("String larger than maxSize of 512 for type EntityName"),
                    ex.getMessage());
        }
    }

    @Test
    public void testGetServiceIdentityServiceNameTooLong() {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String longService = longName(9000);
        try {
            zmsImpl.getServiceIdentity(ctx, "coretech", longService);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("String larger than maxSize of 512 for type SimpleName"),
                    ex.getMessage());
        }
    }

    @Test
    public void testGetEntityEntityNameTooLong() {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String longEntity = longName(9000);
        try {
            zmsImpl.getEntity(ctx, "coretech", longEntity);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("String larger than maxSize of 512 for type EntityName"),
                    ex.getMessage());
        }
    }
}
