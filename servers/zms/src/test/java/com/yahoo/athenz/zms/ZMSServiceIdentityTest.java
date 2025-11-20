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
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.common.server.store.AthenzDomain;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigInteger;
import jakarta.ws.rs.core.Response;
import org.mockito.Mockito;
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
        zmsImpl.putServiceIdentity(ctx, domainName, "service2", auditRef, false, "TF", service2);

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
                    assertNull(service.getResourceOwnership());
                    service1Check = true;
                    break;
                case "setup-service-keys-hosts.service2":
                    assertEquals(service.getExecutable(), "/usr/bin/java");
                    assertEquals(service.getUser(), "yahoo");
                    assertEquals(service.getPublicKeys().size(), 2);
                    assertEquals(service.getHosts().size(), 1);
                    assertEquals(service.getHosts().get(0), "host2");
                    assertEquals(service.getResourceOwnership().getObjectOwner(), "TF");
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

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, "Test Domain1", "testOrg",
                zmsTestInitializer.getAdminUser());
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

        final String domainName = "service-get-domain-test";
        final String serviceName = "service1";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        service.setCreds("athenz-authorization-secret-for-testing");
        service.setClientId("client-id");

        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service);

        ServiceIdentity serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertNotNull(serviceRes);
        assertEquals(serviceRes.getName(), domainName + "." + serviceName);
        assertEquals(serviceRes.getExecutable(), "/usr/bin/java");
        assertEquals(serviceRes.getGroup(), "users");
        assertEquals(serviceRes.getUser(), "root");
        assertNull(serviceRes.getCreds());
        assertNull(serviceRes.getClientId());

        // provider endpoint is a system meta attribute, so we shouldn't save it
        assertNull(serviceRes.getProviderEndpoint());

        List<String> hosts = serviceRes.getHosts();
        assertNotNull(hosts);
        assertEquals(hosts.size(), 1);
        assertEquals(hosts.get(0), "host1");

        // now let's update some of the fields in our service identity

        service.setExecutable("/usr/bin/python");
        service.setUser("athenz");
        service.setGroup("admins");
        service.setClientId("client-id2");
        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertNotNull(serviceRes);
        assertEquals(serviceRes.getName(), domainName + "." + serviceName);
        assertEquals(serviceRes.getExecutable(), "/usr/bin/python");
        assertEquals(serviceRes.getGroup(), "admins");
        assertEquals(serviceRes.getUser(), "athenz");
        assertNull(serviceRes.getCreds());
        assertNull(serviceRes.getClientId());

        // now let's remove some of the attributes by setting them to null

        service.setUser(null);
        service.setClientId(null);
        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertNotNull(serviceRes);
        assertEquals(serviceRes.getName(), domainName + "." + serviceName);
        assertEquals(serviceRes.getExecutable(), "/usr/bin/python");
        assertEquals(serviceRes.getGroup(), "admins");
        assertNull(serviceRes.getUser());
        assertNull(serviceRes.getCreds());
        assertNull(serviceRes.getClientId());

        // this should throw a not found exception
        try {
            zmsImpl.getServiceIdentity(ctx, domainName, "Service2");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        // this should throw a request error exception
        try {
            zmsImpl.getServiceIdentity(ctx, domainName, "Service2.Service3");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
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
        service.setClientId("client-id");

        zmsImpl.putServiceIdentity(ctx, domainName, serviceName, auditRef, false, null, service);

        ServiceIdentity serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertNotNull(serviceRes);
        assertEquals(serviceRes.getName(), domainName + "." + serviceName);
        assertEquals(serviceRes.getExecutable(), "/usr/bin/java");
        assertEquals(serviceRes.getGroup(), "users");
        assertEquals(serviceRes.getUser(), "root");

        // provider endpoint, key ids and client-id are system meta attributes, so we shouldn't save it

        assertNull(serviceRes.getProviderEndpoint());
        assertNull(serviceRes.getSshCertSignerKeyId());
        assertNull(serviceRes.getX509CertSignerKeyId());
        assertNull(serviceRes.getClientId());

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
        assertNull(serviceRes.getClientId());

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
        assertNull(serviceRes.getClientId());

        // now let's set the x509 cert key id

        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "x509certsignerkeyid", auditRef, meta);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getProviderEndpoint(), "https://localhost");
        assertNull(serviceRes.getSshCertSignerKeyId());
        assertNull(serviceRes.getX509CertSignerKeyId());
        assertNull(serviceRes.getClientId());

        meta.setX509CertSignerKeyId("x509-keyid");
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "x509certsignerkeyid", auditRef, meta);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getProviderEndpoint(), "https://localhost");
        assertEquals(serviceRes.getX509CertSignerKeyId(), "x509-keyid");
        assertNull(serviceRes.getSshCertSignerKeyId());
        assertNull(serviceRes.getClientId());

        meta.setX509CertSignerKeyId("x509-keyid2");
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "x509certsignerkeyid", auditRef, meta);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getProviderEndpoint(), "https://localhost");
        assertEquals(serviceRes.getX509CertSignerKeyId(), "x509-keyid2");
        assertNull(serviceRes.getSshCertSignerKeyId());
        assertNull(serviceRes.getClientId());

        // now let's set the ssh key id

        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "sshcertsignerkeyid", auditRef, meta);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getProviderEndpoint(), "https://localhost");
        assertEquals(serviceRes.getX509CertSignerKeyId(), "x509-keyid2");
        assertNull(serviceRes.getSshCertSignerKeyId());
        assertNull(serviceRes.getClientId());

        meta.setSshCertSignerKeyId("ssh-keyid");
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "sshcertsignerkeyid", auditRef, meta);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getProviderEndpoint(), "https://localhost");
        assertEquals(serviceRes.getX509CertSignerKeyId(), "x509-keyid2");
        assertEquals(serviceRes.getSshCertSignerKeyId(), "ssh-keyid");
        assertNull(serviceRes.getClientId());

        meta.setSshCertSignerKeyId("ssh-keyid2");
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "sshcertsignerkeyid", auditRef, meta);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getProviderEndpoint(), "https://localhost");
        assertEquals(serviceRes.getX509CertSignerKeyId(), "x509-keyid2");
        assertEquals(serviceRes.getSshCertSignerKeyId(), "ssh-keyid2");
        assertNull(serviceRes.getClientId());

        // now let's set the client id

        meta.setClientId("client-id");
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "clientid", auditRef, meta);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getProviderEndpoint(), "https://localhost");
        assertEquals(serviceRes.getX509CertSignerKeyId(), "x509-keyid2");
        assertEquals(serviceRes.getSshCertSignerKeyId(), "ssh-keyid2");
        assertEquals(serviceRes.getClientId(), "client-id");

        meta.setClientId("client-id2");
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "clientid", auditRef, meta);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getProviderEndpoint(), "https://localhost");
        assertEquals(serviceRes.getX509CertSignerKeyId(), "x509-keyid2");
        assertEquals(serviceRes.getSshCertSignerKeyId(), "ssh-keyid2");
        assertEquals(serviceRes.getClientId(), "client-id2");

        // reset all values

        meta = new ServiceIdentitySystemMeta();
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "providerendpoint", auditRef, meta);
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "x509certsignerkeyid", auditRef, meta);
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "sshcertsignerkeyid", auditRef, meta);
        zmsImpl.putServiceIdentitySystemMeta(ctx, domainName, serviceName, "clientid", auditRef, meta);

        serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertEquals(serviceRes.getName(), domainName + "." + serviceName);
        assertNull(serviceRes.getProviderEndpoint());
        assertNull(serviceRes.getSshCertSignerKeyId());
        assertNull(serviceRes.getX509CertSignerKeyId());
        assertNull(serviceRes.getClientId());

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
        System.setProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_NAME, "svc-encryption-key-must-be-longer-than-32-bytes");

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
        System.setProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_NAME, "svc-encryption-key-must-be-longer-than-32-bytes");
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
        System.setProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_NAME, "svc-encryption-key-must-be-longer-than-32-bytes");

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
    public void testGetSecretKeyWithInvalidEncryptionKey() {

        final String domainName = "service-identity-creds-invalid-key-algo";
        final String serviceName = "service1";
        final String svcCreds = "athenz-authorization-unit-test-secret";

        // with the invalid key algorithm we should get an exception,
        // and thus we won't have secrets enabled

        System.setProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_GROUP, "unit-test");
        System.setProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_NAME, "svc-encryption-key");

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

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testLoadServiceEncryptionKey() {

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        assertNull(zmsImpl.serviceCredsEncryptionKey);

        // now let's set the settings but with a small key size
        // and we still should not have a key

        System.setProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_NAME, "svc-encryption-key");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        Mockito.when(keyStore.getSecret("zms", "", "svc-encryption-key"))
                .thenThrow(new CryptoException("mock exception"));
        zmsImpl.keyStore = keyStore;
        zmsImpl.serviceCredsEncryptionKey = null;
        zmsImpl.loadServiceEncryptionKey();
        assertNull(zmsImpl.serviceCredsEncryptionKey);

        System.clearProperty(ZMSConsts.ZMS_PROP_SVC_CREDS_KEY_NAME);
    }

    @Test
    public void testDeletePublicKeyEntry() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServiceDelPubKeyDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServiceDelPubKeyDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServiceDelPubKeyDom1", "Service1", auditRef, false, null, service);

        zmsImpl.deletePublicKeyEntry(ctx, "ServiceDelPubKeyDom1", "Service1", "1", auditRef, null);
        ServiceIdentity serviceRes = zmsImpl.getServiceIdentity(ctx, "ServiceDelPubKeyDom1", "Service1");
        List<PublicKeyEntry> keyList = serviceRes.getPublicKeys();
        boolean found = false;
        for (PublicKeyEntry entry : keyList) {
            if (entry.getId().equals("1")) {
                found = true;
                break;
            }
        }
        assertFalse(found);

        zmsImpl.deleteTopLevelDomain(ctx, "ServiceDelPubKeyDom1", auditRef, null);
    }

    @Test
    public void testDeletePublicKeyEntryMissingAuditRef() {
        String domain = "testDeletePublicKeyEntryMissingAuditRef";
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        dom.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        ServiceIdentity service = zmsTestInitializer.createServiceObject(
                domain,
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zmsImpl.putServiceIdentity(ctx, domain, "Service1", auditRef, false, null, service);

        PublicKeyEntry keyEntry = new PublicKeyEntry();
        keyEntry.setId("zone1");
        keyEntry.setKey(zmsTestInitializer.getPubKeyK2());
        zmsImpl.putPublicKeyEntry(ctx, domain, "Service1", "zone1", auditRef, null, keyEntry);
        try {
            zmsImpl.deletePublicKeyEntry(ctx, domain, "Service1", "1", null, null);
            fail("requesterror not thrown by deletePublicKeyEntry.");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zmsImpl.deleteTopLevelDomain(ctx, domain, auditRef, null);
        }
    }

    @Test
    public void testDeletePublicKeyEntryDomainNotFound() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServiceDelPubKeyDom2",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServiceDelPubKeyDom2",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServiceDelPubKeyDom2", "Service1", auditRef, false, null, service);

        // this should throw a not found exception
        try {
            zmsImpl.deletePublicKeyEntry(ctx, "UnknownPublicKeyDomain", "Service1", "1", auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServiceDelPubKeyDom2", auditRef, null);
    }

    @Test
    public void testDeletePublicKeyEntryInvalidService() {

        ZMSImplTest.TestAuditLogger alogger = new ZMSImplTest.TestAuditLogger();
        ZMSImpl zmsImpl = zmsTestInitializer.getZmsImpl(alogger);
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServiceDelPubKeyDom2InvalidService",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServiceDelPubKeyDom2InvalidService",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServiceDelPubKeyDom2InvalidService",
                "Service1", auditRef, false, null, service);

        // this should throw an invalid request exception
        try {
            zmsImpl.deletePublicKeyEntry(ctx, "ServiceDelPubKeyDom2InvalidService",
                    "Service1.Service2", "1", auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServiceDelPubKeyDom2InvalidService", auditRef, null);
    }

    @Test
    public void testDeletePublicKeyEntryServiceNotFound() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServiceDelPubKeyDom3",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServiceDelPubKeyDom3",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServiceDelPubKeyDom3", "Service1", auditRef, false, null, service);

        // this should throw a not found exception
        try {
            zmsImpl.deletePublicKeyEntry(ctx, "ServiceDelPubKeyDom3", "ServiceNotFound", "1", auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServiceDelPubKeyDom3", auditRef, null);
    }

    @Test
    public void testDeletePublicKeyEntryIdNotFound() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServiceDelPubKeyDom4",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServiceDelPubKeyDom4",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServiceDelPubKeyDom4", "Service1", auditRef, false, null, service);

        // process invalid keys

        try {
            zmsImpl.deletePublicKeyEntry(ctx, "ServiceDelPubKeyDom4", "Service1", "zone", auditRef, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        // make sure both 1 and 2 keys are still valid

        ServiceIdentity serviceRes = zmsImpl.getServiceIdentity(ctx, "ServiceDelPubKeyDom4", "Service1");
        List<PublicKeyEntry> keyList = serviceRes.getPublicKeys();
        boolean foundKey1 = false;
        boolean foundKey2 = false;
        for (PublicKeyEntry entry : keyList) {
            if (entry.getId().equals("1")) {
                foundKey1 = true;
            } else if (entry.getId().equals("2")) {
                foundKey2 = true;
            }
        }
        assertTrue(foundKey1);
        assertTrue(foundKey2);

        zmsImpl.deleteTopLevelDomain(ctx, "ServiceDelPubKeyDom4", auditRef, null);
    }

    @Test
    public void testGetPublicKeyEntry() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServicePubKeyDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServicePubKeyDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServicePubKeyDom1", "Service1", auditRef, false, null, service);

        PublicKeyEntry entry = zmsImpl.getPublicKeyEntry(ctx, "ServicePubKeyDom1", "Service1", "1");
        assertNotNull(entry);
        assertEquals(entry.getId(), "1");
        assertEquals(entry.getKey(), zmsTestInitializer.getPubKeyK1());

        zmsImpl.deleteTopLevelDomain(ctx, "ServicePubKeyDom1", auditRef, null);
    }

    @Test
    public void testGetPublicKeyEntryInvalidService() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServicePubKeyDom2Invalid",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServicePubKeyDom2Invalid",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServicePubKeyDom2Invalid", "Service1", auditRef, false, null, service);

        // this should throw an invalid request exception
        try {
            zmsImpl.getPublicKeyEntry(ctx, "ServicePubKeyDom2Invalid", "Service1.Service2", "1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServicePubKeyDom2Invalid", auditRef, null);
    }

    @Test
    public void testGetPublicKeyEntryDomainNotFound() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServicePubKeyDom2",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServicePubKeyDom2",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServicePubKeyDom2", "Service1", auditRef, false, null, service);

        // this should throw a not found exception
        try {
            zmsImpl.getPublicKeyEntry(ctx, "UnknownPublicKeyDomain", "Service1", "1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServicePubKeyDom2", auditRef, null);
    }

    @Test
    public void testGetPublicKeyEntryServiceNotFound() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServicePubKeyDom3",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServicePubKeyDom3",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServicePubKeyDom3", "Service1", auditRef, false, null, service);

        // this should throw a not found exception
        try {
            zmsImpl.getPublicKeyEntry(ctx, "ServicePubKeyDom3", "ServiceNotFound", "1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServicePubKeyDom3", auditRef, null);
    }

    @Test
    public void testGetPublicKeyEntryIdNotFound() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServicePubKeyDom4",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServicePubKeyDom4",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServicePubKeyDom4", "Service1", auditRef, false, null, service);

        // this should throw a not found exception
        try {
            zmsImpl.getPublicKeyEntry(ctx, "ServicePubKeyDom4", "Service1", "zone");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServicePubKeyDom4", auditRef, null);
    }

    @Test
    public void testPutPublicKeyEntryNew() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServicePutPubKeyDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServicePutPubKeyDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServicePutPubKeyDom1", "Service1", auditRef, false, null, service);

        PublicKeyEntry keyEntry = new PublicKeyEntry();
        keyEntry.setId("zone1");
        keyEntry.setKey(zmsTestInitializer.getPubKeyK2());

        zmsImpl.putPublicKeyEntry(ctx, "ServicePutPubKeyDom1", "Service1", "zone1", auditRef, null, keyEntry);

        ServiceIdentity serviceRes = zmsImpl.getServiceIdentity(ctx, "ServicePutPubKeyDom1", "Service1");
        List<PublicKeyEntry> keyList = serviceRes.getPublicKeys();
        boolean foundKey1 = false;
        boolean foundKey2 = false;
        boolean foundKeyZONE1 = false;
        for (PublicKeyEntry entry : keyList) {
            switch (entry.getId()) {
                case "1":
                    foundKey1 = true;
                    break;
                case "2":
                    foundKey2 = true;
                    break;
                case "zone1":
                    foundKeyZONE1 = true;
                    break;
            }
        }
        assertTrue(foundKey1);
        assertTrue(foundKey2);
        assertTrue(foundKeyZONE1);

        PublicKeyEntry entry = zmsImpl.getPublicKeyEntry(ctx, "ServicePutPubKeyDom1", "Service1", "zone1");
        assertNotNull(entry);
        assertEquals(entry.getId(), "zone1");
        assertEquals(entry.getKey(), zmsTestInitializer.getPubKeyK2());

        zmsImpl.deleteTopLevelDomain(ctx, "ServicePutPubKeyDom1", auditRef, null);
    }

    @Test
    public void testPutPublicKeyEntryInvalidKey() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServicePutPubKeyDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServicePutPubKeyDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServicePutPubKeyDom1", "Service1", auditRef, false, null, service);

        PublicKeyEntry keyEntry = new PublicKeyEntry();
        keyEntry.setId("zone1");
        keyEntry.setKey("some-invalid-key");

        try {
            zmsImpl.putPublicKeyEntry(ctx, "ServicePutPubKeyDom1", "Service1", "zone1", auditRef, null, keyEntry);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid public key"));
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServicePutPubKeyDom1", auditRef, null);
    }

    @Test
    public void testPutPublicKeyEntryMissingAuditRef() {

        ZMSImplTest.TestAuditLogger alogger = new ZMSImplTest.TestAuditLogger();
        ZMSImpl zmsImpl = zmsTestInitializer.getZmsImpl(alogger);
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domain = "testPutPublicKeyEntryMissingAuditRef";
        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        dom.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        ServiceIdentity service = zmsTestInitializer.createServiceObject(
                domain,
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zmsImpl.putServiceIdentity(ctx, domain, "Service1", auditRef, false, null, service);

        PublicKeyEntry keyEntry = new PublicKeyEntry();
        keyEntry.setId("zone1");
        keyEntry.setKey(zmsTestInitializer.getPubKeyK2());

        try {
            zmsImpl.putPublicKeyEntry(ctx, domain, "Service1", "zone1", null, null, keyEntry);
            fail("requesterror not thrown by putPublicKeyEntry.");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zmsImpl.deleteTopLevelDomain(ctx, domain, auditRef, null);
        }
    }

    @Test
    public void testPutPublicKeyEntryInvalidService() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domain = "testPutPublicKeyEntryInvalidService";
        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(
                domain, "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        ServiceIdentity service = zmsTestInitializer.createServiceObject(
                domain,
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zmsImpl.putServiceIdentity(ctx, domain, "Service1", auditRef, false, null, service);

        PublicKeyEntry keyEntry = new PublicKeyEntry();
        keyEntry.setId("zone1");
        keyEntry.setKey(zmsTestInitializer.getPubKeyK2());

        try {
            zmsImpl.putPublicKeyEntry(ctx, domain, "Service1.Service2", "zone1", null, null, keyEntry);
            fail("requesterror not thrown by putPublicKeyEntry.");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        } finally {
            zmsImpl.deleteTopLevelDomain(ctx, domain, auditRef, null);
        }
    }

    @Test
    public void testPutPublicKeyEntryUpdate() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServicePutPubKeyDom1A",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServicePutPubKeyDom1A",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServicePutPubKeyDom1A", "Service1", auditRef, false, null, service);

        PublicKeyEntry keyEntry = new PublicKeyEntry();
        keyEntry.setId("1");
        keyEntry.setKey(zmsTestInitializer.getPubKeyK2());

        zmsImpl.putPublicKeyEntry(ctx, "ServicePutPubKeyDom1A", "Service1", "1", auditRef, null, keyEntry);

        ServiceIdentity serviceRes = zmsImpl.getServiceIdentity(ctx, "ServicePutPubKeyDom1A", "Service1");
        List<PublicKeyEntry> keyList = serviceRes.getPublicKeys();
        assertEquals(keyList.size(), 2);

        boolean foundKey1 = false;
        boolean foundKey2 = false;
        for (PublicKeyEntry entry : keyList) {
            if (entry.getId().equals("1")) {
                foundKey1 = true;
            } else if (entry.getId().equals("2")) {
                foundKey2 = true;
            }
        }

        assertTrue(foundKey1);
        assertTrue(foundKey2);

        PublicKeyEntry entry = zmsImpl.getPublicKeyEntry(ctx, "ServicePutPubKeyDom1A", "Service1", "1");
        assertNotNull(entry);
        assertEquals(entry.getId(), "1");
        assertEquals(entry.getKey(), zmsTestInitializer.getPubKeyK2());

        zmsImpl.deleteTopLevelDomain(ctx, "ServicePutPubKeyDom1A", auditRef, null);
    }

    @Test
    public void testPutPublicKeyEntryDomainNotFound() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServicePutPubKeyDom2",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServicePutPubKeyDom2",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServicePutPubKeyDom2", "Service1", auditRef, false, null, service);

        // this should throw a not found exception
        try {
            PublicKeyEntry keyEntry = new PublicKeyEntry();
            keyEntry.setId("zone1");
            keyEntry.setKey(zmsTestInitializer.getPubKeyK2());

            zmsImpl.putPublicKeyEntry(ctx, "UnknownPublicKeyDomain", "Service1", "zone1", auditRef, null, keyEntry);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServicePutPubKeyDom2", auditRef, null);
    }

    @Test
    public void testPutPublicKeyEntryServiceNotFound() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServicePutPubKeyDom3",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServicePutPubKeyDom3",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServicePutPubKeyDom3", "Service1", auditRef, false, null, service);

        // this should throw a not found exception
        try {
            PublicKeyEntry keyEntry = new PublicKeyEntry();
            keyEntry.setId("zone1");
            keyEntry.setKey(zmsTestInitializer.getPubKeyK2());

            zmsImpl.putPublicKeyEntry(ctx, "ServicePutPubKeyDom3", "ServiceNotFound", "zone1", auditRef, null, keyEntry);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServicePutPubKeyDom3", auditRef, null);
    }

    @Test
    public void testDeletePublicKeyEntryIdNoMatch() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServicePutPubKeyDom4",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServicePutPubKeyDom4",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServicePutPubKeyDom4", "Service1", auditRef, false, null, service);

        // this should throw invalid request exception

        try {
            PublicKeyEntry keyEntry = new PublicKeyEntry();
            keyEntry.setId("zone1");
            keyEntry.setKey(zmsTestInitializer.getPubKeyK2());

            zmsImpl.putPublicKeyEntry(ctx, "ServicePutPubKeyDom4", "Service1", "zone2", auditRef, null, keyEntry);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServicePutPubKeyDom4", auditRef, null);
    }

    @Test
    public void testGetPublicKeyService() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("GetPublicKeyDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("GetPublicKeyDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "GetPublicKeyDom1", "Service1", auditRef, false, null, service);

        String publicKey = zmsImpl.getPublicKey("GetPublicKeyDom1", "Service1", "0");
        assertNull(publicKey);

        assertNull(zmsImpl.getPublicKey("GetPublicKeyDom1", null, "0"));
        assertNull(zmsImpl.getPublicKey("GetPublicKeyDom1", "Service1", null));

        publicKey = zmsImpl.getPublicKey("GetPublicKeyDom1", "Service1", "1");
        assertNotNull(publicKey);
        assertEquals(publicKey, Crypto.ybase64DecodeString(zmsTestInitializer.getPubKeyK1()));

        publicKey = zmsImpl.getPublicKey("GetPublicKeyDom1", "Service1", "2");
        assertNotNull(publicKey);
        assertEquals(publicKey, Crypto.ybase64DecodeString(zmsTestInitializer.getPubKeyK2()));

        zmsImpl.deleteTopLevelDomain(ctx, "GetPublicKeyDom1", auditRef, null);
    }

    @Test
    public void testRetrieveServiceIdentityInvalidServiceName() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject("ServiceRetrieveDom1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject("ServiceRetrieveDom1",
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, "ServiceRetrieveDom1", "Service1", auditRef, false, null, service);

        try {
            zmsImpl.getServiceIdentity(ctx, "ServiceRetrieveDom1", "Service");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
        try {
            zmsImpl.getServiceIdentity(ctx, "ServiceRetrieveDom1", "Service2");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
        try {
            zmsImpl.getServiceIdentity(ctx, "ServiceRetrieveDom1", "Service11");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        zmsImpl.deleteTopLevelDomain(ctx, "ServiceRetrieveDom1", auditRef, null);
    }

    @Test
    public void testRetrieveServiceIdentityValid() {

        String domainName = "serviceretrievedom2";
        String serviceName = "service1";
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        ServiceIdentity service = zmsTestInitializer.createServiceObject(domainName,
                serviceName, "http://localhost", "/usr/bin/java", "root",
                "users", "host1");

        zmsImpl.putServiceIdentity(ctx, domainName, "Service1", auditRef, false, null, service);

        ServiceIdentity serviceRes = zmsImpl.getServiceIdentity(ctx, domainName, serviceName);
        assertNotNull(serviceRes);
        assertEquals(serviceRes.getName(), domainName + "." + serviceName);
        assertEquals(serviceRes.getExecutable(), "/usr/bin/java");
        assertEquals(serviceRes.getGroup(), "users");
        assertEquals(serviceRes.getUser(), "root");

        // provider endpoint is a system meta attribute so we shouldn't saved it
        assertNull(serviceRes.getProviderEndpoint());

        List<String> hosts = serviceRes.getHosts();
        assertNotNull(hosts);
        assertEquals(hosts.size(), 1);
        assertEquals(hosts.get(0), "host1");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testValidateServiceName() {

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        StringBuilder errorMessage = new StringBuilder(64);

        // reserved names
        assertFalse(zmsImpl.isValidServiceName("athenz", "com", errorMessage));
        assertEquals(errorMessage.toString(), "reserved service name");
        assertFalse(zmsImpl.isValidServiceName("athenz", "gov", errorMessage));
        assertFalse(zmsImpl.isValidServiceName("athenz", "info", errorMessage));
        assertFalse(zmsImpl.isValidServiceName("athenz", "org", errorMessage));

        assertTrue(zmsImpl.isValidServiceName("athenz", "svc", errorMessage));
        assertTrue(zmsImpl.isValidServiceName("athenz", "acom", errorMessage));
        assertTrue(zmsImpl.isValidServiceName("athenz", "coms", errorMessage));
        assertTrue(zmsImpl.isValidServiceName("athenz", "borg", errorMessage));

        // service names with 1 or 2 chars

        errorMessage.setLength(0);
        assertFalse(zmsImpl.isValidServiceName("athenz", "u", errorMessage));
        assertEquals(errorMessage.toString(), "service name length too short");

        assertFalse(zmsImpl.isValidServiceName("athenz", "k", errorMessage));
        assertFalse(zmsImpl.isValidServiceName("athenz", "r", errorMessage));

        assertFalse(zmsImpl.isValidServiceName("athenz", "us", errorMessage));
        assertFalse(zmsImpl.isValidServiceName("athenz", "uk", errorMessage));
        assertFalse(zmsImpl.isValidServiceName("athenz", "fr", errorMessage));

        // set the min length to 0 and verify all pass

        zmsImpl.serviceNameMinLength = 0;
        assertTrue(zmsImpl.isValidServiceName("athenz", "r", errorMessage));
        assertTrue(zmsImpl.isValidServiceName("athenz", "us", errorMessage));
        assertTrue(zmsImpl.isValidServiceName("athenz", "svc", errorMessage));

        // set map to null and verify all pass

        zmsImpl.reservedServiceNames = null;
        assertTrue(zmsImpl.isValidServiceName("athenz", "com", errorMessage));
        assertTrue(zmsImpl.isValidServiceName("athenz", "gov", errorMessage));

        // create new impl objects with new settings

        System.setProperty(ZMSConsts.ZMS_PROP_RESERVED_SERVICE_NAMES, "one,two");
        System.setProperty(ZMSConsts.ZMS_PROP_SERVICE_NAME_MIN_LENGTH, "0");
        ZMSImpl zmsImpl2 = zmsTestInitializer.zmsInit();

        assertTrue(zmsImpl2.isValidServiceName("athenz", "com", errorMessage));
        assertTrue(zmsImpl2.isValidServiceName("athenz", "gov", errorMessage));
        assertTrue(zmsImpl2.isValidServiceName("athenz", "info", errorMessage));

        assertFalse(zmsImpl2.isValidServiceName("athenz", "one", errorMessage));
        assertFalse(zmsImpl2.isValidServiceName("athenz", "two", errorMessage));

        assertTrue(zmsImpl2.isValidServiceName("athenz", "u", errorMessage));
        assertTrue(zmsImpl2.isValidServiceName("athenz", "k", errorMessage));
        assertTrue(zmsImpl2.isValidServiceName("athenz", "r", errorMessage));
        System.clearProperty(ZMSConsts.ZMS_PROP_RESERVED_SERVICE_NAMES);
        System.clearProperty(ZMSConsts.ZMS_PROP_SERVICE_NAME_MIN_LENGTH);

        // validate service names with underscores set to allow

        zmsImpl2.allowUnderscoreInServiceNames = new DynamicConfigBoolean(Boolean.TRUE);
        assertTrue(zmsImpl2.isValidServiceName("athenz", "service-name", errorMessage));
        assertTrue(zmsImpl2.isValidServiceName("athenz", "service_name", errorMessage));

        // while to allow option is enabled, let's create a service with underscore

        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain testDomain = zmsTestInitializer.createTopLevelDomainObject("athenz",
                "Athenz Domain", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, testDomain);

        ServiceIdentity service = new ServiceIdentity();
        service.setName(ResourceUtils.serviceResourceName("athenz", "service_name"));
        zmsImpl2.putServiceIdentity(ctx, "athenz", "service_name", auditRef, false, null, service);

        // now let's disable the option. with the existing service, it should
        // be allowed but non-existent service name with be rejected

        zmsImpl2.allowUnderscoreInServiceNames = new DynamicConfigBoolean(Boolean.FALSE);
        assertTrue(zmsImpl2.isValidServiceName("athenz", "service-name", errorMessage));
        assertTrue(zmsImpl2.isValidServiceName("athenz", "service_name", errorMessage));
        errorMessage.setLength(0);
        assertFalse(zmsImpl2.isValidServiceName("athenz", "service_name2", errorMessage));
        assertEquals(errorMessage.toString(), "service name with underscore not allowed");

        // by default the feature flag is not enabled for the domain

        assertFalse(zmsImpl2.isDomainFeatureFlagEnabled("athenz", 1));
        assertFalse(zmsImpl2.isDomainFeatureFlagEnabled("athenz", 2));

        // enable the domain to have the underscore feature flag enabled
        // services should now be allowed

        DomainMeta meta = new DomainMeta().setFeatureFlags(1);
        zmsImpl2.putDomainSystemMeta(ctx, "athenz", "featureflags", auditRef, meta);

        assertTrue(zmsImpl2.isDomainFeatureFlagEnabled("athenz", 1));
        assertFalse(zmsImpl2.isDomainFeatureFlagEnabled("athenz", 2));

        assertTrue(zmsImpl2.isValidServiceName("athenz", "service-name", errorMessage));
        assertTrue(zmsImpl2.isValidServiceName("athenz", "service_name", errorMessage));
        assertTrue(zmsImpl2.isValidServiceName("athenz", "service_name2", errorMessage));
        assertTrue(zmsImpl2.isValidServiceName("athenz", "service_name3", errorMessage));

        zmsImpl2.deleteDomain(ctx, auditRef, "athenz", null, "unit-test");

        zmsImpl.objectStore.clearConnections();
        zmsImpl2.objectStore.clearConnections();
    }

}
