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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.yahoo.athenz.common.server.store.AthenzDomain;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigInteger;
import jakarta.ws.rs.core.Response;
import org.testng.annotations.*;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
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

    @Test
    public void testGetServiceIdentities() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "get-services";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject(domainName,
                "service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zmsImpl.putServiceIdentity(ctx,
                domainName, "service1", auditRef, true, null, service1);

        ServiceIdentity service2 = zmsTestInitializer.createServiceObject(domainName,
                "service2", "http://localhost", "/usr/bin/java", "yahoo",
                "users", "host2");

        zmsImpl.putServiceIdentity(ctx, domainName, "service2",
                auditRef, false, null, service2);

        ServiceIdentities serviceList = zmsImpl.getServiceIdentities(ctx,
                domainName, Boolean.TRUE, Boolean.TRUE, null, null);
        List<ServiceIdentity> services = serviceList.getList();
        assertEquals(services.size(), 2);

        boolean service1Check = false;
        boolean service2Check = false;

        for (ServiceIdentity service : services) {
            switch (service.getName()) {
                case "get-services.service1":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "root");
                    assertEquals(service.getPublicKeys().size(), 2);
                    assertEquals(service.getHosts().size(), 1);
                    assertEquals(service.getHosts().get(0), "host1");
                    service1Check = true;
                    break;
                case "get-services.service2":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "yahoo");
                    assertEquals(service.getPublicKeys().size(), 2);
                    assertEquals(service.getHosts().size(), 1);
                    assertEquals(service.getHosts().get(0), "host2");
                    assertEquals(service.getDescription(), "test");
                    service2Check = true;
                    break;
            }
        }

        assertTrue(service1Check);
        assertTrue(service2Check);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testGetServiceIdentitiesInvalidDomain() {

        String domainName = "get-services-invalid-domain";
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        try {
            zmsImpl.getServiceIdentities(ctx, domainName,
                    Boolean.TRUE, Boolean.TRUE, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testSetupServiceListWithKeysHosts() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "setup-service-keys-hosts";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject(domainName,
                "service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zmsImpl.putServiceIdentity(ctx, domainName, "service1", auditRef, false, null, service1);

        ServiceIdentity service2 = zmsTestInitializer.createServiceObject(domainName,
                "service2", "http://localhost", "/usr/bin/java", "yahoo",
                "users", "host2");
        zmsImpl.putServiceIdentity(ctx, domainName, "service2", auditRef, false, null, service2);

        AthenzDomain domain = zmsImpl.getAthenzDomain(domainName, false);
        List<ServiceIdentity> services = zmsImpl.setupServiceIdentityList(domain,
                Boolean.TRUE, Boolean.TRUE, null, null, zmsImpl.serviceCredsEncryptionKey != null);
        assertEquals(services.size(), 2);

        boolean service1Check = false;
        boolean service2Check = false;

        for (ServiceIdentity service : services) {
            switch (service.getName()) {
                case "setup-service-keys-hosts.service1":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "root");
                    assertEquals(service.getPublicKeys().size(), 2);
                    assertEquals(service.getHosts().size(), 1);
                    assertEquals(service.getHosts().get(0), "host1");
                    service1Check = true;
                    break;
                case "setup-service-keys-hosts.service2":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "yahoo");
                    assertEquals(service.getPublicKeys().size(), 2);
                    assertEquals(service.getHosts().size(), 1);
                    assertEquals(service.getHosts().get(0), "host2");
                    service2Check = true;
                    break;
            }
        }

        assertTrue(service1Check);
        assertTrue(service2Check);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testSetupServiceListWithOutKeysHosts() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "setup-service-without-keys-hosts";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject(domainName,
                "service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        service1.setCreds("athenz-credentials-for-testing-not-saved");
        zmsImpl.putServiceIdentity(ctx, domainName, "service1", auditRef, false, null, service1);

        ServiceIdentity service2 = zmsTestInitializer.createServiceObject(domainName,
                "service2", "http://localhost", "/usr/bin/java", "yahoo",
                "users", "host2");
        zmsImpl.putServiceIdentity(ctx, domainName, "service2", auditRef, false, null, service2);

        AthenzDomain domain = zmsImpl.getAthenzDomain(domainName, false);
        List<ServiceIdentity> services = zmsImpl.setupServiceIdentityList(domain,
                Boolean.FALSE, Boolean.FALSE, null, null, zmsImpl.serviceCredsEncryptionKey != null);
        assertEquals(services.size(), 2);

        boolean service1Check = false;
        boolean service2Check = false;

        for (ServiceIdentity service : services) {
            switch (service.getName()) {
                case "setup-service-without-keys-hosts.service1":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "root");
                    assertNull(service.getPublicKeys());
                    assertNull(service.getHosts());
                    assertNull(service.getCreds());
                    service1Check = true;
                    break;
                case "setup-service-without-keys-hosts.service2":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "yahoo");
                    assertNull(service.getPublicKeys());
                    assertNull(service.getHosts());
                    assertNull(service.getCreds());
                    service2Check = true;
                    break;
            }
        }

        assertTrue(service1Check);
        assertTrue(service2Check);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testSetupServiceListWithKeysOnly() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "setup-service-keys-only";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject(domainName,
                "service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zmsImpl.putServiceIdentity(ctx, domainName, "service1", auditRef, false, null, service1);

        ServiceIdentity service2 = zmsTestInitializer.createServiceObject(domainName,
                "service2", "http://localhost", "/usr/bin/java", "yahoo",
                "users", "host2");
        zmsImpl.putServiceIdentity(ctx, domainName, "service2", auditRef, false, null, service2);

        AthenzDomain domain = zmsImpl.getAthenzDomain(domainName, false);
        List<ServiceIdentity> services = zmsImpl.setupServiceIdentityList(domain,
                Boolean.TRUE, Boolean.FALSE, null, null, zmsImpl.serviceCredsEncryptionKey != null);
        assertEquals(services.size(), 2);

        boolean service1Check = false;
        boolean service2Check = false;

        for (ServiceIdentity service : services) {
            switch (service.getName()) {
                case "setup-service-keys-only.service1":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "root");
                    assertEquals(service.getPublicKeys().size(), 2);
                    assertNull(service.getHosts());
                    service1Check = true;
                    break;
                case "setup-service-keys-only.service2":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "yahoo");
                    assertEquals(service.getPublicKeys().size(), 2);
                    assertNull(service.getHosts());
                    service2Check = true;
                    break;
            }
        }

        assertTrue(service1Check);
        assertTrue(service2Check);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testSetupServiceListWithHostsOnly() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "setup-service-hosts-only";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject(domainName,
                "service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zmsImpl.putServiceIdentity(ctx, domainName, "service1", auditRef, false, null, service1);

        ServiceIdentity service2 = zmsTestInitializer.createServiceObject(domainName,
                "service2", "http://localhost", "/usr/bin/java", "yahoo",
                "users", "host2");
        zmsImpl.putServiceIdentity(ctx, domainName, "service2", auditRef, false, null, service2);

        AthenzDomain domain = zmsImpl.getAthenzDomain(domainName, false);
        List<ServiceIdentity> services = zmsImpl.setupServiceIdentityList(domain,
                Boolean.FALSE, Boolean.TRUE, null, null, zmsImpl.serviceCredsEncryptionKey != null);
        assertEquals(services.size(), 2);

        boolean service1Check = false;
        boolean service2Check = false;

        for (ServiceIdentity service : services) {
            switch (service.getName()) {
                case "setup-service-hosts-only.service1":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "root");
                    assertNull(service.getPublicKeys());
                    assertEquals(service.getHosts().size(), 1);
                    assertEquals(service.getHosts().get(0), "host1");
                    service1Check = true;
                    break;
                case "setup-service-hosts-only.service2":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "yahoo");
                    assertNull(service.getPublicKeys());
                    assertEquals(service.getHosts().size(), 1);
                    assertEquals(service.getHosts().get(0), "host2");
                    service2Check = true;
                    break;
            }
        }

        assertTrue(service1Check);
        assertTrue(service2Check);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }


    @Test
    public void testCreateServiceIdentity() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServiceAddDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServiceAddDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServiceAddDom1", "Service1", auditRef, false, null, service);

        ServiceIdentity serviceRes2 = zmsImpl.getServiceIdentity(ctx, "ServiceAddDom1",
                "Service1");
        assertNotNull(serviceRes2);
        assertEquals(serviceRes2.getName(), "ServiceAddDom1.Service1".toLowerCase());

        zmsImpl.deleteTopLevelDomain(ctx, "ServiceAddDom1", auditRef, null);
    }

    @Test
    public void testCreateServiceIdentityNotSimpleName() {

        ZMSImplTest.TestAuditLogger alogger = new ZMSImplTest.TestAuditLogger();
        ZMSImpl zmsImpl = zmsTestInitializer.getZmsImpl(alogger);
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServiceAddDom1NotSimpleName",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServiceAddDom1NotSimpleName",
                "Service1.Test", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        try {
            zmsImpl.putServiceIdentity(ctx, "ServiceAddDom1NotSimpleName", "Service1.Test", auditRef, false, null, service);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServiceAddDom1NotSimpleName", auditRef, null);
    }

    @Test
    public void testCreateServiceIdentityMissingAuditRef() {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domain = "testCreateServiceIdentityMissingAuditRef";
        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        dom.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        ServiceIdentity service = zmsTestInitializer.createServiceObject(
                domain,
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        try {
            zmsImpl.putServiceIdentity(ctx, domain, "Service1", null, false, null, service);
            fail("requesterror not thrown by putServiceIdentity.");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zmsImpl.deleteTopLevelDomain(ctx, domain, auditRef, null);
        }
    }

    @Test
    public void testCreateServiceIdentityMismatchName() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServiceAddMismatchNameDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServiceAddMismatchNameDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        try {
            zmsImpl.putServiceIdentity(ctx, "ServiceAddMismatchNameDom1",
                    "ServiceAddMismatchNameDom1.Service1", auditRef, false, null, service);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServiceAddMismatchNameDom1", auditRef, null);
    }

    @Test
    public void testCreateServiceIdentityInvalidName() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServiceAddInvalidNameDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = new ServiceIdentity();
        service.setName("Service1");

        try {
            zmsImpl.putServiceIdentity(ctx, "ServiceAddInvalidNameDom1", "Service1", auditRef, false, null, service);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServiceAddInvalidNameDom1", auditRef, null);
    }

    @Test
    public void testCreateServiceIdentityInvalidCert() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServiceAddInvalidCertDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = new ServiceIdentity();
        service.setName(ResourceUtils.serviceResourceName("ServiceAddInvalidCertDom1", "Service1"));
        List<PublicKeyEntry> pubKeys = new ArrayList<>();
        pubKeys.add(new PublicKeyEntry().setId("0").setKey("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTk"));
        service.setPublicKeys(pubKeys);

        try {
            zmsImpl.putServiceIdentity(ctx, "ServiceAddInvalidCertDom1", "Service1", auditRef, false, null, service);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServiceAddInvalidCertDom1", auditRef, null);
    }

    @Test
    public void testCreateServiceIdentityInvalidStruct() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServiceAddInvalidStructDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = new ServiceIdentity();

        try {
            zmsImpl.putServiceIdentity(ctx, "ServiceAddInvalidStructDom1", "Service1", auditRef, false, null, service);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServiceAddInvalidStructDom1", auditRef, null);
    }

    @Test
    public void testPutServiceIdentityWithoutPubKey() {
        String domainName = "ServicePutDom1";
        String serviceName = "Service1";
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = new ServiceIdentity();
        service.setName(ResourceUtils.serviceResourceName(domainName, serviceName));

        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service);

        ServiceIdentity serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertNotNull(serviceRes);
        assertEquals(serviceRes.getName(), "ServicePutDom1.Service1".toLowerCase());

        zmsImpl.deleteTopLevelDomain(ctx,  domainName, auditRef, null);
    }

    @Test
    public void testPutServiceIdentitySamePubKeyIdDifferentValue() {
        String domainName = "ServicePutDom1";
        String serviceName = "Service1";
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        List<PublicKeyEntry> publicKeyOldList = new ArrayList<>();
        PublicKeyEntry publicKeyEntryOld = new PublicKeyEntry();
        publicKeyEntryOld.setKey(zmsTestInitializer.getPubKeyK1());
        publicKeyEntryOld.setId("1");
        publicKeyOldList.add(publicKeyEntryOld);

        List<PublicKeyEntry> publicKeyNewList = new ArrayList<>();
        PublicKeyEntry publicKeyEntryNew = new PublicKeyEntry();
        publicKeyEntryNew.setKey(zmsTestInitializer.getPubKeyK2());
        publicKeyEntryNew.setId("1");
        publicKeyNewList.add(publicKeyEntryNew);

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, "Test Domain1", "testOrg",
                zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = new ServiceIdentity();
        service.setName(ResourceUtils.serviceResourceName(domainName, serviceName));
        service.setPublicKeys(publicKeyOldList);
        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service);

        ServiceIdentity serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertNotNull(serviceRes);
        assertEquals(serviceRes.getName(), "ServicePutDom1.Service1".toLowerCase());
        assertEquals(serviceRes.getPublicKeys().size(), 1);
        assertEquals(serviceRes.getPublicKeys().get(0), publicKeyEntryOld);

        service.setPublicKeys(publicKeyNewList);
        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertNotNull(serviceRes);
        assertEquals(serviceRes.getName(), "ServicePutDom1.Service1".toLowerCase());
        assertEquals(serviceRes.getPublicKeys().size(), 1);
        assertEquals(serviceRes.getPublicKeys().get(0).getId(), "1");
        assertEquals(serviceRes.getPublicKeys().get(0).getKey(), zmsTestInitializer.getPubKeyK2());

        zmsImpl.deleteTopLevelDomain(ctx,  domainName, auditRef, null);
    }

    @Test
    public void testPutServiceIdentityInvalidServiceName() {
        String domainName = "ServicePutDom1";
        String serviceName = "cloud";
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, "Test Domain1", "testOrg",
                zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = new ServiceIdentity();
        service.setName(ResourceUtils.serviceResourceName(domainName, serviceName));

        try {
            zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("reserved service name"));
        }

        zmsImpl.deleteTopLevelDomain(ctx,  domainName, auditRef, null);
    }

    @Test
    public void testPutServiceIdentityInvalidEndPoint() {
        String domainName = "ServicePutDom1";
        String serviceName = "Service1";
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, "Test Domain1", "testOrg",
                zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = new ServiceIdentity();
        service.setName(ResourceUtils.serviceResourceName(domainName, serviceName));
        service.setProviderEndpoint("https://sometestcompany.com");

        try {
            zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid endpoint"));
        }

        zmsImpl.deleteTopLevelDomain(ctx,  domainName, auditRef, null);
    }

    @Test
    public void testPutServiceIdentityThrowException() {
        String domainName = "DomainName";
        String serviceName = "ServiceName";
        String wrongServiceName = "WrongServiceName";
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        // Tests the putServiceIdentity() condition: if (!serviceResourceName(domainName, serviceName).equals(detail.getName()))...
        try {
            ServiceIdentity detail = zmsTestInitializer.createServiceObject(domainName,
                    wrongServiceName, "http://localhost", "/usr/bin/java", "root",
                    "users", "host1");

            // serviceName should not render to be the same as domainName:service.wrongServiceName
            zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, detail);
            fail("requesterror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 400);
        }

        // Tests the putServiceIdentity() condition: if (domain == null)...
        try {
            ServiceIdentity detail = zmsTestInitializer.createServiceObject(domainName,
                    serviceName, "http://localhost", "/usr/bin/java", "root",
                    "users", "host1");

            // should fail b/c we never created a top level domain.
            zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, detail);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
    }

    @Test
    public void testGetServiceIdentity() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServiceGetDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServiceGetDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        service.setCreds("athenz-authorization-secret-for-testing");

        zmsImpl.putServiceIdentity(ctx, "ServiceGetDom1", "Service1", auditRef, false, null, service);

        ServiceIdentity serviceRes = zmsImpl.getServiceIdentity(ctx, "ServiceGetDom1",
                "Service1");
        assertNotNull(serviceRes);
        assertEquals(serviceRes.getName(), "ServiceGetDom1.Service1".toLowerCase());
        assertEquals(serviceRes.getExecutable(), "/usr/bin/java");
        assertEquals(serviceRes.getGroup(), "users");
        assertEquals(serviceRes.getUser(), "root");
        assertNull(serviceRes.getCreds());

        // provider endpoint is a system meta attribute, so we shouldn't save it
        assertNull(serviceRes.getProviderEndpoint());

        List<String> hosts = serviceRes.getHosts();
        assertNotNull(hosts);
        assertEquals(hosts.size(), 1);
        assertEquals(hosts.get(0), "host1");

        // this should throw a not found exception
        try {
            zmsImpl.getServiceIdentity(ctx, "ServiceGetDom1", "Service2");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        // this should throw a request error exception
        try {
            zmsImpl.getServiceIdentity(ctx, "ServiceGetDom1", "Service2.Service3");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServiceGetDom1", auditRef, null);
    }

    @Test
    public void testPutServiceIdentitySystemMeta() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "service-system-meta";
        final String serviceName = "service1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        service.setX509CertSignerKeyId("x509-keyid");
        service.setSshCertSignerKeyId("ssh-keyid");

        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service);

        ServiceIdentity serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertNotNull(serviceRes);
        assertEquals(serviceRes.getName(), domainName + "." + serviceName);
        assertEquals(serviceRes.getExecutable(), "/usr/bin/java");
        assertEquals(serviceRes.getGroup(), "users");
        assertEquals(serviceRes.getUser(), "root");

        // provider endpoint and key ids are system meta attributes, so we shouldn't save it

        assertNull(serviceRes.getProviderEndpoint());
        assertNull(serviceRes.getSshCertSignerKeyId());
        assertNull(serviceRes.getX509CertSignerKeyId());

        // now let's set the meta attribute

        ServiceIdentitySystemMeta meta = new ServiceIdentitySystemMeta();
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "providerendpoint", auditRef, meta);

        // we expect no changes

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getName(), domainName + "." + serviceName);
        assertEquals(serviceRes.getExecutable(), "/usr/bin/java");
        assertEquals(serviceRes.getGroup(), "users");
        assertEquals(serviceRes.getUser(), "root");
        assertNull(serviceRes.getProviderEndpoint());
        assertNull(serviceRes.getSshCertSignerKeyId());
        assertNull(serviceRes.getX509CertSignerKeyId());

        // now let's change the endpoint

        meta.setProviderEndpoint("https://localhost");
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "providerendpoint", auditRef, meta);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getName(), domainName + "." + serviceName);
        assertEquals(serviceRes.getExecutable(), "/usr/bin/java");
        assertEquals(serviceRes.getGroup(), "users");
        assertEquals(serviceRes.getUser(), "root");
        assertEquals(serviceRes.getProviderEndpoint(), "https://localhost");
        assertNull(serviceRes.getSshCertSignerKeyId());
        assertNull(serviceRes.getX509CertSignerKeyId());

        // now let's set the x509 cert key id

        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "x509certsignerkeyid", auditRef, meta);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getProviderEndpoint(), "https://localhost");
        assertNull(serviceRes.getSshCertSignerKeyId());
        assertNull(serviceRes.getX509CertSignerKeyId());

        meta.setX509CertSignerKeyId("x509-keyid");
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "x509certsignerkeyid", auditRef, meta);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getProviderEndpoint(), "https://localhost");
        assertEquals(serviceRes.getX509CertSignerKeyId(), "x509-keyid");
        assertNull(serviceRes.getSshCertSignerKeyId());

        meta.setX509CertSignerKeyId("x509-keyid2");
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "x509certsignerkeyid", auditRef, meta);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getProviderEndpoint(), "https://localhost");
        assertEquals(serviceRes.getX509CertSignerKeyId(), "x509-keyid2");
        assertNull(serviceRes.getSshCertSignerKeyId());

        // now let's set the ssh key id

        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "sshcertsignerkeyid", auditRef, meta);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getProviderEndpoint(), "https://localhost");
        assertEquals(serviceRes.getX509CertSignerKeyId(), "x509-keyid2");
        assertNull(serviceRes.getSshCertSignerKeyId());

        meta.setSshCertSignerKeyId("ssh-keyid");
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "sshcertsignerkeyid", auditRef, meta);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getProviderEndpoint(), "https://localhost");
        assertEquals(serviceRes.getX509CertSignerKeyId(), "x509-keyid2");
        assertEquals(serviceRes.getSshCertSignerKeyId(), "ssh-keyid");

        meta.setSshCertSignerKeyId("ssh-keyid2");
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "sshcertsignerkeyid", auditRef, meta);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getProviderEndpoint(), "https://localhost");
        assertEquals(serviceRes.getX509CertSignerKeyId(), "x509-keyid2");
        assertEquals(serviceRes.getSshCertSignerKeyId(), "ssh-keyid2");

        // reset all values

        meta = new ServiceIdentitySystemMeta();
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "providerendpoint", auditRef, meta);
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "x509certsignerkeyid", auditRef, meta);
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "sshcertsignerkeyid", auditRef, meta);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getName(), domainName + "." + serviceName);
        assertNull(serviceRes.getProviderEndpoint());
        assertNull(serviceRes.getSshCertSignerKeyId());
        assertNull(serviceRes.getX509CertSignerKeyId());

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testGetServiceIdentityThrowException() {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domainName = "ServiceGetDom1";
        String serviceName = "Service1";

        // Tests the getServiceIdentity() condition : if (domain == null)...
        try {
            // Should fail because we never created this domain.
            zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // Tests the getServiceIdentity() condition : if (collection == null)...
        try {
            // Should fail because we never added a service identity to this domain.
            zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }

        // Tests the getServiceIdentity() condition : if (service == null)...
        try {
            String wrongServiceName = "Service2";

            ServiceIdentity service = zmsTestInitializer.createServiceObject(domainName,
                    serviceName, "http://localhost", "/usr/bin/java", "root",
                    "users", "host1");
            zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service);

            // Should fail because trying to find a non-existent service identity.
            zmsImpl.getServiceIdentity(ctx, domainName, wrongServiceName);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testDeleteServiceIdentity() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServiceDelDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject("ServiceDelDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServiceDelDom1", "Service1", auditRef, false, null, service1);

        ServiceIdentity service2 = zmsTestInitializer.createServiceObject("ServiceDelDom1",
                "Service2", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServiceDelDom1", "Service2", auditRef, false, null, service2);

        ServiceIdentity serviceRes1 = zmsImpl.getServiceIdentity(ctx, "ServiceDelDom1",
                "Service1");
        assertNotNull(serviceRes1);

        ServiceIdentity serviceRes2 = zmsImpl.getServiceIdentity(ctx, "ServiceDelDom1",
                "Service2");
        assertNotNull(serviceRes2);

        zmsImpl.deleteServiceIdentity(ctx, "ServiceDelDom1", "Service1", auditRef, null);

        // this should throw a not found exception
        try {
            zmsImpl.getServiceIdentity(ctx, "ServiceDelDom1", "Service1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        serviceRes2 = zmsImpl.getServiceIdentity(ctx, "ServiceDelDom1", "Service2");
        assertNotNull(serviceRes2);

        zmsImpl.deleteServiceIdentity(ctx, "ServiceDelDom1", "Service2", auditRef, null);

        // this should throw a not found exception
        try {
            zmsImpl.getServiceIdentity(ctx, "ServiceDelDom1", "Service1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        // this should throw a not found exception
        try {
            zmsImpl.getServiceIdentity(ctx, "ServiceDelDom1", "Service2");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        // this should throw an invalid exception
        try {
            zmsImpl.getServiceIdentity(ctx, "ServiceDelDom1", "Service2.Service3");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServiceDelDom1", auditRef, null);
    }

    @Test
    public void testDeleteServiceIdentityMissingAuditRef() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domain = "testDeleteServiceIdentityMissingAuditRef";
        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        dom.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        ServiceIdentity service = zmsTestInitializer.createServiceObject(
                domain,
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zmsImpl.putServiceIdentity(ctx, domain, "Service1", auditRef, false, null, service);
        ServiceIdentity serviceRes =
                zmsImpl.getServiceIdentity(ctx, domain, "Service1");
        assertNotNull(serviceRes);
        try {
            zmsImpl.deleteServiceIdentity(ctx, domain, "Service1", null, null);
            fail("requesterror not thrown by deleteServiceIdentity.");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zmsImpl.deleteTopLevelDomain(ctx, domain, auditRef, null);
        }
    }

    @Test
    public void testDeleteServiceIdentityThrowException() {

        ZMSImplTest.TestAuditLogger alogger = new ZMSImplTest.TestAuditLogger();
        ZMSImpl zmsImpl = zmsTestInitializer.getZmsImpl(alogger);
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domainName = "WrongDomainName";
        String serviceName = "WrongServiceName";
        try {
            zmsImpl.deleteServiceIdentity(ctx, domainName, serviceName, auditRef, null);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
    }

    @Test
    public void testGetServiceIdentityList() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServiceListDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject("ServiceListDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServiceListDom1", "Service1", auditRef, false, null, service1);

        ServiceIdentity service2 = zmsTestInitializer.createServiceObject("ServiceListDom1",
                "Service2", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServiceListDom1", "Service2", auditRef, false, null, service2);

        ServiceIdentityList serviceList = zmsImpl.getServiceIdentityList(
                ctx, "ServiceListDom1", null, null);
        assertNotNull(serviceList);
        assertEquals(serviceList.getNames().size(), 2);

        assertTrue(serviceList.getNames().contains("Service1".toLowerCase()));
        assertTrue(serviceList.getNames().contains("Service2".toLowerCase()));

        zmsImpl.deleteTopLevelDomain(ctx, "ServiceListDom1", auditRef, null);
    }

    @Test
    public void testGetServiceIdentityListParams() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(
                "ServiceListParamsDom1", "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service1 = zmsTestInitializer.createServiceObject("ServiceListParamsDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServiceListParamsDom1", "Service1", auditRef, false, null, service1);

        ServiceIdentity service2 = zmsTestInitializer.createServiceObject("ServiceListParamsDom1",
                "Service2", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServiceListParamsDom1", "Service2", auditRef, false, null, service2);

        ServiceIdentityList serviceList = zmsImpl.getServiceIdentityList(
                ctx, "ServiceListParamsDom1", 1, null);
        assertNotNull(serviceList);
        assertEquals(serviceList.getNames().size(), 1);

        serviceList = zmsImpl.getServiceIdentityList(ctx, "ServiceListParamsDom1", null,
                "Service1");
        assertNotNull(serviceList);
        assertEquals(serviceList.getNames().size(), 1);

        assertFalse(serviceList.getNames().contains("Service1".toLowerCase()));
        assertTrue(serviceList.getNames().contains("Service2".toLowerCase()));

        zmsImpl.deleteTopLevelDomain(ctx, "ServiceListParamsDom1", auditRef, null);
    }

    @Test
    public void testGetServiceIdentityListThrowException() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        String domainName = "WrongDomainName";
        try {
            zmsImpl.getServiceIdentityList(ctx, domainName, null, null);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
    }

    @Test
    public void testGetServiceIdentityCreds() throws ParseException, JOSEException, JsonProcessingException {

        final String domainName = "service-identity-creds";
        final String serviceName = "service1";
        final String svcCreds1 = "athenz-authorization-unit-test-secret-first";
        final String svcCreds2 = "athenz-authorization-unit-test-secret-second";

        // set our encryption secret for services

        System.setProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_GROUP, "unit-test");
        System.setProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_NAME, "svc-encryption-key");

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        service.setCreds(svcCreds1);

        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service);

        ServiceIdentity serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertNotNull(serviceRes);
        assertEquals(serviceRes.getName(), domainName + "." + serviceName);
        assertEquals(serviceRes.getExecutable(), "/usr/bin/java");
        assertEquals(serviceRes.getGroup(), "users");
        assertEquals(serviceRes.getUser(), "root");
        assertNull(serviceRes.getCreds());

        // set the credentials using the correct api

        CredsEntry creds = new CredsEntry().setValue(svcCreds1);
        zmsImpl.putServiceCredsEntry(ctx, domainName, serviceName, auditRef, null, creds);

        // we still should not see the creds value

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertNull(serviceRes.getCreds());

        // now let's retrieve the creds using the get creds api

        byte[] svcCredsResp = zmsImpl.getServiceSecret(domainName, serviceName);
        assertEquals(svcCredsResp, svcCreds1.getBytes(StandardCharsets.UTF_8));

        // let's get the jws domain data and verify that the creds are not included
        // because our principal is not authorized for it

        Response response = zmsImpl.getJWSDomain(ctx, domainName, null, null);
        JWSDomain jwsDomain = (JWSDomain) response.getEntity();
        DomainData domainData = zmsTestInitializer.getDomainData(jwsDomain);

        assertEquals(domainData.getServices().size(), 1);
        ServiceIdentity serviceIdentity = domainData.getServices().get(0);
        assertNull(serviceIdentity.getCreds());

        // now let's authorize our principal to get the creds

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName(ctx.principal().getFullName()));
        Role role = new Role().setName("sys.auth:role.creds-admin").setRoleMembers(roleMembers);
        zmsImpl.putRole(ctx, "sys.auth", "creds-admin", auditRef, false, null, role);

        List<Assertion> assertions = new ArrayList<>();
        assertions.add(new Assertion().setRole("sys.auth:role.creds-admin").setResource("sys.auth:attribute.creds")
                .setAction("access"));
        Policy policy = new Policy().setName("sys.auth:policy.creds-admin").setAssertions(assertions);
        zmsImpl.putPolicy(ctx, "sys.auth", "creds-admin", auditRef, false, null, policy);

        response = zmsImpl.getJWSDomain(ctx, domainName, null, null);
        jwsDomain = (JWSDomain) response.getEntity();
        domainData = zmsTestInitializer.getDomainData(jwsDomain);

        assertEquals(domainData.getServices().size(), 1);
        serviceIdentity = domainData.getServices().get(0);
        assertNotNull(serviceIdentity.getCreds());

        // now let's update our credentials

        creds = new CredsEntry().setValue(svcCreds2);
        zmsImpl.putServiceCredsEntry(ctx, domainName, serviceName, auditRef, null, creds);

        // we still should not see the creds value

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertNull(serviceRes.getCreds());

        // now let's retrieve the creds using the get creds api

        svcCredsResp = zmsImpl.getServiceSecret(domainName, serviceName);
        assertEquals(svcCredsResp, svcCreds2.getBytes(StandardCharsets.UTF_8));

        response = zmsImpl.getJWSDomain(ctx, domainName, null, null);
        jwsDomain = (JWSDomain) response.getEntity();
        domainData = zmsTestInitializer.getDomainData(jwsDomain);

        assertEquals(domainData.getServices().size(), 1);
        serviceIdentity = domainData.getServices().get(0);
        assertNotNull(serviceIdentity.getCreds());

        // now let's reset our creds

        creds = new CredsEntry().setValue("");
        zmsImpl.putServiceCredsEntry(ctx, domainName, serviceName, auditRef, null, creds);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertNull(serviceRes.getCreds());

        svcCredsResp = zmsImpl.getServiceSecret(domainName, serviceName);
        assertNull(svcCredsResp);

        response = zmsImpl.getJWSDomain(ctx, domainName, null, null);
        jwsDomain = (JWSDomain) response.getEntity();
        domainData = zmsTestInitializer.getDomainData(jwsDomain);

        assertEquals(domainData.getServices().size(), 1);
        serviceIdentity = domainData.getServices().get(0);
        assertNull(serviceIdentity.getCreds());

        // clean up

        zmsImpl.deletePolicy(ctx, "sys.auth", "creds-admin", auditRef, null);
        zmsImpl.deleteRole(ctx, "sys.auth", "creds-admin", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);

        System.clearProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_GROUP);
        System.clearProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_NAME);
    }

    @Test
    public void testGetServiceIdentityCredsNotEnabled() {

        final String domainName = "service-identity-creds-not-enabled";
        final String serviceName = "service1";
        final String svcCreds = "athenz-authorization-unit-test-secret";

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // set the credentials using the correct api will fail
        // because the service identity creds is not enabled

        try {
            CredsEntry creds = new CredsEntry().setValue(svcCreds);
            zmsImpl.putServiceCredsEntry(ctx, domainName, serviceName, auditRef, null, creds);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Service Credentials are not supported"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testGetServiceIdentityCredsErrors() {

        final String domainName = "service-identity-creds-errors";
        final String serviceName = "service1";
        final String svcCreds = "athenz-authorization-unit-test-secret";

        // set our encryption secret for services

        System.setProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_GROUP, "unit-test");
        System.setProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_NAME, "svc-encryption-key");
        System.setProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_ENCRYPTION_ALGORITHM, "AES/UnknownAlgorithm");

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // set the credentials using the correct api will fail
        // because the service identity does not exist

        try {
            CredsEntry creds = new CredsEntry().setValue(svcCreds);
            zmsImpl.putServiceCredsEntry(ctx, domainName, serviceName, auditRef, null, creds);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        // any value less than 32 characters should fail

        try {
            CredsEntry creds = new CredsEntry().setValue("short");
            zmsImpl.putServiceCredsEntry(ctx, domainName, serviceName, auditRef, null, creds);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Invalid creds value. Must be at least 32 and at most 64 bytes long"));
        }

        // any value greater than 64 characters should fail

        try {
            CredsEntry creds = new CredsEntry().setValue("this-is-a-very-long-creds-value-that-is-more-than-64-characters-test");
            zmsImpl.putServiceCredsEntry(ctx, domainName, serviceName, auditRef, null, creds);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Invalid creds value. Must be at least 32 and at most 64 bytes long"));
        }

        // let's create the service so we can test the invalid algorithm case

        ServiceIdentity service = zmsTestInitializer.createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service);

        try {
            CredsEntry creds = new CredsEntry().setValue(svcCreds);
            zmsImpl.putServiceCredsEntry(ctx, domainName, serviceName, auditRef, null, creds);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
            assertTrue(ex.getMessage().contains("Unable to encrypt credentials"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);

        System.clearProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_GROUP);
        System.clearProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_NAME);
        System.clearProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_ENCRYPTION_ALGORITHM);
    }

    @Test
    public void testGetServiceSecretErrorsWithKeyEnabled() {
        final String domainName = "service-identity-creds-errors";
        final String serviceName = "service1";

        // set our encryption secret for services

        System.setProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_GROUP, "unit-test");
        System.setProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_NAME, "svc-encryption-key");

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // for invalid null domain/service values we should get back null

        assertNull(zmsImpl.getServiceSecret(null, null));
        assertNull(zmsImpl.getServiceSecret(domainName, null));
        assertNull(zmsImpl.getServiceSecret(null, serviceName));

        // for unknown service we should get back null

        assertNull(zmsImpl.getServiceSecret(domainName, "service2"));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);

        System.clearProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_GROUP);
        System.clearProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_NAME);
    }

    @Test
    public void testGetServiceSecretErrorsWithKeyDisabled() {
        final String domainName = "service-identity-creds-errors";
        final String serviceName = "service1";

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service);

        // for invalid null domain/service values we should get back null

        assertNull(zmsImpl.getServiceSecret(null, null));
        assertNull(zmsImpl.getServiceSecret(domainName, null));
        assertNull(zmsImpl.getServiceSecret(null, serviceName));

        // since secrets are disabled, we should get back null
        // for a valid case as well

        assertNull(zmsImpl.getServiceSecret(domainName, serviceName));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testGetSecretKeyWithInvalidAlgorithm() {

        final String domainName = "service-identity-creds-invalid-key-algo";
        final String serviceName = "service1";
        final String svcCreds = "athenz-authorization-unit-test-secret";

        // with the invalid key algorithm we should get an exception,
        // and thus we won't have secrets enabled

        System.setProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_GROUP, "unit-test");
        System.setProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_NAME, "svc-encryption-key");
        System.setProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_SECRET_KEY_ALGORITHM, "AES/UnknownAlgorithm");

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // set the credentials using the correct api will fail
        // because the service identity creds is not enabled

        try {
            CredsEntry creds = new CredsEntry().setValue(svcCreds);
            zmsImpl.putServiceCredsEntry(ctx, domainName, serviceName, auditRef, null, creds);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Service Credentials are not supported"));
        }

        System.clearProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_GROUP);
        System.clearProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_NAME);
        System.clearProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_SECRET_KEY_ALGORITHM);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }
}
