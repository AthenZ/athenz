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

package com.yahoo.athenz.zms;

import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigInteger;
import org.testng.annotations.*;

import java.util.List;

import static org.testng.Assert.*;

public class ZMSServiceIdentityTest {

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
    public void clearConnections() {
        zmsTestInitializer.clearConnections();
    }

    @Test
    public void testSearchServiceIdentities() {

        ZMSImplTest.TestAuditLogger alogger = new ZMSImplTest.TestAuditLogger();
        ZMSImpl zmsImpl = zmsTestInitializer.getZmsImpl(alogger);
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String dom1Name = "tech";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(dom1Name,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject(dom1Name,
                "api", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zmsImpl.putServiceIdentity(ctx, dom1Name, "api", auditRef, false, null, service1);

        final String dom2Name = "tech-subdomain";
        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(dom2Name,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        ServiceIdentity service2 = zmsTestInitializer.createServiceObject(dom2Name,
                "api", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zmsImpl.putServiceIdentity(ctx, dom2Name, "api", auditRef, false, null, service2);

        final String dom3Name = "domain-tech";
        TopLevelDomain dom3 = zmsTestInitializer.createTopLevelDomainObject(dom3Name,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom3);

        ServiceIdentity service3 = zmsTestInitializer.createServiceObject(dom3Name,
                "client-api", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zmsImpl.putServiceIdentity(ctx, dom3Name, "client-api", auditRef, false, null, service3);

        final String dom4Name = "plain-domain";
        TopLevelDomain dom4 = zmsTestInitializer.createTopLevelDomainObject(dom4Name,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom4);

        ServiceIdentity service4 = zmsTestInitializer.createServiceObject(dom4Name,
                "api", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zmsImpl.putServiceIdentity(ctx, dom4Name, "api", auditRef, false, null, service4);

        // search for all services with the name api - we should get back 3 results
        // from domains tech, tech-subdomain, and plain-domain

        ServiceIdentities serviceIdentities = zmsImpl.searchServiceIdentities(ctx, "api", null, null);
        assertEquals(serviceIdentities.getList().size(), 3);
        assertTrue(serviceIdentityPresent(serviceIdentities.getList(), "tech.api"));
        assertTrue(serviceIdentityPresent(serviceIdentities.getList(), "tech-subdomain.api"));
        assertTrue(serviceIdentityPresent(serviceIdentities.getList(), "plain-domain.api"));
        assertEquals(serviceIdentities.getServiceMatchCount(), 0);

        // we're going to limit the results to 2 entries only. we should get back
        // the service match count with value 3

        DynamicConfigInteger savedConfig = zmsImpl.dbService.defaultSearchIdentityLimit;
        zmsImpl.dbService.defaultSearchIdentityLimit = new DynamicConfigInteger(2);

        serviceIdentities = zmsImpl.searchServiceIdentities(ctx, "api", null, null);
        assertEquals(serviceIdentities.getList().size(), 2);
        assertEquals(serviceIdentities.getServiceMatchCount(), 3);

        // restore the original value and verify we get back our 3 entries

        zmsImpl.dbService.defaultSearchIdentityLimit = savedConfig;
        serviceIdentities = zmsImpl.searchServiceIdentities(ctx, "api", null, null);
        assertEquals(serviceIdentities.getList().size(), 3);
        assertEquals(serviceIdentities.getServiceMatchCount(), 0);

        // now search for all services with substring api - we should get back 4 results

        serviceIdentities = zmsImpl.searchServiceIdentities(ctx, "api", Boolean.TRUE, null);
        assertEquals(serviceIdentities.getList().size(), 4);
        assertTrue(serviceIdentityPresent(serviceIdentities.getList(), "tech.api"));
        assertTrue(serviceIdentityPresent(serviceIdentities.getList(), "tech-subdomain.api"));
        assertTrue(serviceIdentityPresent(serviceIdentities.getList(), "domain-tech.client-api"));
        assertTrue(serviceIdentityPresent(serviceIdentities.getList(), "plain-domain.api"));
        assertEquals(serviceIdentities.getServiceMatchCount(), 0);

        // now search for all services with substring api and domain containing tech - we should
        // get back 3 results

        serviceIdentities = zmsImpl.searchServiceIdentities(ctx, "api", Boolean.TRUE, "tech");
        assertEquals(serviceIdentities.getList().size(), 3);
        assertTrue(serviceIdentityPresent(serviceIdentities.getList(), "tech.api"));
        assertTrue(serviceIdentityPresent(serviceIdentities.getList(), "tech-subdomain.api"));
        assertTrue(serviceIdentityPresent(serviceIdentities.getList(), "domain-tech.client-api"));
        assertEquals(serviceIdentities.getServiceMatchCount(), 0);

        // now search for all services with name api (no substring) and domain containing tech - we should
        // get back 2 results

        serviceIdentities = zmsImpl.searchServiceIdentities(ctx, "api", Boolean.FALSE, "tech");
        assertEquals(serviceIdentities.getList().size(), 2);
        assertTrue(serviceIdentityPresent(serviceIdentities.getList(), "tech.api"));
        assertTrue(serviceIdentityPresent(serviceIdentities.getList(), "tech-subdomain.api"));
        assertEquals(serviceIdentities.getServiceMatchCount(), 0);

        zmsImpl.deleteTopLevelDomain(ctx, dom1Name, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, dom2Name, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, dom3Name, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, dom4Name, auditRef, null);
    }

    boolean serviceIdentityPresent(List<ServiceIdentity> services, String name) {
        for (ServiceIdentity service : services) {
            if (service.getName().equals(name)) {
                return true;
            }
        }
        return false;
    }
}
