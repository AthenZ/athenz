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

import com.yahoo.athenz.common.server.metastore.DomainMetaStore;
import com.yahoo.athenz.common.server.ServerResourceException;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class ZMSMetaAttributeTest {

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
        MockitoAnnotations.openMocks(this);
        zmsTestInitializer.setUp();
    }

    @Test
    public void testPutDomainMetaBusinessService() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "athenz-domain-with-business-service";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertNull(domain.getBusinessService());

        // set the business service

        DomainMeta dm = new DomainMeta().setBusinessService("service1");
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, dm);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getBusinessService(), "service1");

        // update the business service

        dm.setBusinessService("service2");
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, dm);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getBusinessService(), "service2");

        // update different meta attribute

        dm = new DomainMeta().setDescription("new description");
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, dm);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getBusinessService(), "service2");
        assertEquals(domain.getDescription(), "new description");

        // remove the business service

        dm = new DomainMeta().setBusinessService("").setDescription("new description");
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, dm);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertNull(domain.getBusinessService());
        assertEquals(domain.getDescription(), "new description");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainMetaEnvironment() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "athenz-domain-with-environment";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertNull(domain.getEnvironment());

        // set the environment

        DomainMeta dm = new DomainMeta().setEnvironment("production");
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, dm);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getEnvironment(), "production");

        // update the environment

        dm.setEnvironment("staging");
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, dm);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getEnvironment(), "staging");

        // set an invalid value and verify failure

        dm = new DomainMeta().setEnvironment("unknown");
        try {
            zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, dm);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid environment for domain"));
        }

        // remove the environment

        dm = new DomainMeta().setEnvironment("");
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, dm);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertNull(domain.getEnvironment());

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPostDomainInvalidDomainMetaStoreValues() {

        final String domainName = "athenz-domain-with-invalid-details";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        DomainMetaStore savedMetaStore = zmsImpl.domainMetaStore;
        zmsImpl.domainMetaStore = new TestDomainMetaStore();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());

        try {
            dom1.setBusinessService("invalid-business-service");
            zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid business service name"));
        }

        try {
            dom1.setBusinessService("valid-business-service");
            dom1.setAccount("invalid-aws-account");
            zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid aws account"));
        }

        try {
            dom1.setAccount("valid-aws-account");
            dom1.setAzureSubscription("invalid-azure-subscription");
            dom1.setAzureTenant("tenant");
            dom1.setAzureClient("client");
            zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid azure subscription"));
        }

        try {
            dom1.setAzureSubscription("valid-azure-subscription");
            dom1.setGcpProject("invalid-gcp-project");
            dom1.setGcpProjectNumber("1200");
            zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid gcp project"));
        }

        zmsImpl.productIdSupport = true;
        try {
            dom1.setGcpProject("valid-gcp-project");
            dom1.setGcpProjectNumber("1200");
            dom1.setYpmId(100);
            zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid product id"));
        }

        try {
            dom1.setYpmId(101);
            dom1.setProductId("invalid-product-id");
            zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid product id"));
        }

        // specify azure subscription but no tenant

        try {
            dom1.setProductId("valid-product-id");
            dom1.setAzureTenant(null);
            zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid azure details"));
        }

        // specify azure tenant but no client

        try {
            dom1.setAzureTenant("tenant");
            dom1.setAzureClient(null);
            zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid azure details"));
        }

        // specify gcp project but no project number

        try {
            dom1.setAzureClient("client");
            dom1.setGcpProjectNumber(null);
            zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid gcp project"));
        }

        dom1.setGcpProjectNumber("1200");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getBusinessService(), "valid-business-service");
        assertEquals(domain.getAccount(), "valid-aws-account");
        assertEquals(domain.getAzureSubscription(), "valid-azure-subscription");
        assertEquals(domain.getAzureTenant(), "tenant");
        assertEquals(domain.getAzureClient(), "client");
        assertEquals(domain.getGcpProject(), "valid-gcp-project");
        assertEquals(domain.getGcpProjectNumber(), "1200");
        assertEquals(domain.getYpmId().intValue(), 101);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        zmsImpl.domainMetaStore = savedMetaStore;
        zmsImpl.productIdSupport = false;
    }

    @Test
    public void testPutDomainMetaInvalidDomainMetaStoreValues() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "athenz-domain-meta-with-invalid-details";
        DomainMetaStore savedMetaStore = zmsImpl.domainMetaStore;
        zmsImpl.domainMetaStore = new TestDomainMetaStore();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        DomainMeta meta = new DomainMeta().setBusinessService("invalid-business-service");
        try {
            zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid business service name"));
        }

        meta.setBusinessService("valid-business-service");
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);

        // second time no-op since value not changed

        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getBusinessService(), "valid-business-service");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        zmsImpl.domainMetaStore = savedMetaStore;
    }

    @Test
    public void testPutDomainSystemMetaInvalidDomainMetaStoreValues() {

        final String domainName = "athenz-domain-system-meta-with-invalid-details";
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        DomainMetaStore savedMetaStore = zmsImpl.domainMetaStore;
        zmsImpl.domainMetaStore = new TestDomainMetaStore();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // first aws account

        DomainMeta meta = new DomainMeta().setAccount("invalid-aws-account");
        try {
            zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_ACCOUNT, auditRef, meta);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid aws account"));
        }

        meta.setAccount("valid-aws-account");
        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_ACCOUNT, auditRef, meta);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getAccount(), "valid-aws-account");

        // second time no-op since nothing has changed

        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_ACCOUNT, auditRef, meta);

        // next invalid azure subscription

        try {
            meta.setAzureSubscription("invalid-azure-subscription");
            zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_AZURE_SUBSCRIPTION, auditRef, meta);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid azure details"));
        }

        // next azure subscription without azure tenant

        try {
            meta.setAzureSubscription("valid-azure-subscription");
            meta.setAzureTenant(null);
            zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_AZURE_SUBSCRIPTION, auditRef, meta);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid azure details"));
        }

        // next azure subscription and tenant without client

        try {
            meta.setAzureTenant("tenant");
            meta.setAzureClient(null);
            zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_AZURE_SUBSCRIPTION, auditRef, meta);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid azure details"));
        }

        meta.setAzureClient("client");
        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_AZURE_SUBSCRIPTION, auditRef, meta);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getAzureSubscription(), "valid-azure-subscription");
        assertEquals(domain.getAzureTenant(), "tenant");
        assertEquals(domain.getAzureClient(), "client");

        // now keep the azure subscription but update the azure tenant
        meta.setAzureTenant("tenant2");
        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_AZURE_SUBSCRIPTION, auditRef, meta);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getAzureSubscription(), "valid-azure-subscription");
        assertEquals(domain.getAzureTenant(), "tenant2");
        assertEquals(domain.getAzureClient(), "client");

        // second time no-op since nothing has changed

        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_AZURE_SUBSCRIPTION, auditRef, meta);

        // now keep the azure tenant but update the azure client
        meta.setAzureClient("client2");
        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_AZURE_SUBSCRIPTION, auditRef, meta);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getAzureSubscription(), "valid-azure-subscription");
        assertEquals(domain.getAzureTenant(), "tenant2");
        assertEquals(domain.getAzureClient(), "client2");

        // second time no-op since nothing has changed

        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_AZURE_SUBSCRIPTION, auditRef, meta);

        // next gcp project

        try {
            meta.setGcpProject("invalid-gcp-project");
            meta.setGcpProjectNumber("1200");
            zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_GCP_PROJECT, auditRef, meta);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid gcp project"));
        }

        // next gcp project without project number

        try {
            meta.setGcpProject("valid-gcp-project");
            meta.setGcpProjectNumber(null);
            zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_GCP_PROJECT, auditRef, meta);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid gcp project"));
        }

        meta.setGcpProject("valid-gcp-project");
        meta.setGcpProjectNumber("1200");
        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_GCP_PROJECT, auditRef, meta);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getGcpProject(), "valid-gcp-project");
        assertEquals(domain.getGcpProjectNumber(), "1200");

        // now keep the gcp project but update the project number

        meta.setGcpProject("valid-gcp-project");
        meta.setGcpProjectNumber("1201");
        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_GCP_PROJECT, auditRef, meta);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getGcpProject(), "valid-gcp-project");
        assertEquals(domain.getGcpProjectNumber(), "1201");

        // second time no-op since nothing has changed

        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_GCP_PROJECT, auditRef, meta);

        // next product id

        zmsImpl.productIdSupport = true;
        try {
            meta.setYpmId(100);
            zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_PRODUCT_ID, auditRef, meta);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid product id"));
        }

        meta.setYpmId(101);
        try {
            meta.setProductId("invalid-product-id");
            zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_PRODUCT_ID, auditRef, meta);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid product id"));
        }

        meta.setProductId("valid-product-id");
        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_PRODUCT_ID, auditRef, meta);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getYpmId().intValue(), 101);

        // final business service

        try {
            meta.setBusinessService("invalid-business-service");
            zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_BUSINESS_SERVICE, auditRef, meta);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("invalid business service"));
        }

        meta.setBusinessService("valid-business-service");
        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_BUSINESS_SERVICE, auditRef, meta);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getBusinessService(), "valid-business-service");

        // second time no-op since nothing has changed

        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_BUSINESS_SERVICE, auditRef, meta);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        zmsImpl.domainMetaStore = savedMetaStore;
        zmsImpl.productIdSupport = false;
    }

    @Test
    public void testPutDomainMetaIDomainMetaStoreException() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "athenz-domain-meta-with-exception";
        DomainMetaStore savedMetaStore = zmsImpl.domainMetaStore;
        zmsImpl.domainMetaStore = new TestDomainMetaStore();

        // value with exc- will throw an exception but we should
        // not reject the request

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        dom1.setBusinessService("exc-business-service");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getBusinessService(), "exc-business-service");

        // try with system attribute now as well

        DomainMeta meta = new DomainMeta().setAccount("exc-aws-account");
        zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_ACCOUNT, auditRef, meta);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getAccount(), "exc-aws-account");
        assertEquals(domain.getBusinessService(), "exc-business-service");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        zmsImpl.domainMetaStore = savedMetaStore;
    }

    @Test
    public void testPutDomainSystemMetaInvalidDomain() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "athenz-domain-system-meta-not-found";

        DomainMeta meta = new DomainMeta().setAccount("aws-account");
        try {
            zmsImpl.putDomainSystemMeta(ctx, domainName, ZMSConsts.SYSTEM_META_ACCOUNT, auditRef, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
    }

    @Test
    public void testGetDomainMetaStoreValidValuesList() throws ServerResourceException {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        DomainMetaStore savedMetaStore = zmsImpl.domainMetaStore;
        DomainMetaStore mockDomainMetaStore = Mockito.mock(DomainMetaStore.class);
        List<String> awsAccountsList = Collections.singletonList("awsAcc");
        when(mockDomainMetaStore.getValidAWSAccounts(isNull())).thenReturn(awsAccountsList);
        List<String> businessServicesList = Collections.singletonList("bservice");
        when(mockDomainMetaStore.getValidBusinessServices(isNull())).thenReturn(businessServicesList);
        List<String> azureList = Collections.singletonList("azureSub");
        when(mockDomainMetaStore.getValidAzureSubscriptions(isNull())).thenReturn(azureList);
        List<String> gcpList = Collections.singletonList("gcpProject");
        when(mockDomainMetaStore.getValidGcpProjects(isNull())).thenReturn(gcpList);
        List<String> productIdList = Collections.singletonList("product");
        when(mockDomainMetaStore.getValidProductIds(isNull())).thenReturn(productIdList);
        List<String> onCallList = Collections.singletonList("sre-team");
        when(mockDomainMetaStore.getValidOnCalls(isNull())).thenReturn(onCallList);
        zmsImpl.domainMetaStore = mockDomainMetaStore;
        assertEquals(zmsImpl.getDomainMetaStoreValidValuesList(ctx, "businessService", null).getValidValues().get(0), "bservice");
        assertEquals(zmsImpl.getDomainMetaStoreValidValuesList(ctx, "awsAccount", null).getValidValues().get(0), "awsAcc");
        assertEquals(zmsImpl.getDomainMetaStoreValidValuesList(ctx, "azureSubscription", null).getValidValues().get(0), "azureSub");
        assertEquals(zmsImpl.getDomainMetaStoreValidValuesList(ctx, "gcpProject", null).getValidValues().get(0), "gcpProject");
        assertEquals(zmsImpl.getDomainMetaStoreValidValuesList(ctx, "productId", null).getValidValues().get(0), "product");
        assertEquals(zmsImpl.getDomainMetaStoreValidValuesList(ctx, "productNumber", null).getValidValues().get(0), "product");
        assertEquals(zmsImpl.getDomainMetaStoreValidValuesList(ctx, "onCall", null).getValidValues().get(0), "sre-team");
        zmsImpl.domainMetaStore = savedMetaStore;
    }

    @Test
    public void testGetDomainMetaStoreValidValuesListException() throws ServerResourceException {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        DomainMetaStore savedMetaStore = zmsImpl.domainMetaStore;
        DomainMetaStore mockDomainMetaStore = Mockito.mock(DomainMetaStore.class);
        when(mockDomainMetaStore.getValidOnCalls(isNull())).thenThrow(new ServerResourceException(500, "Test Exception"));
        zmsImpl.domainMetaStore = mockDomainMetaStore;
        try {
            zmsImpl.getDomainMetaStoreValidValuesList(ctx, "onCall", null);
            fail("Expected ServerResourceException not thrown");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("unable to retrieve valid values for attribute: onCall"));
        }
        zmsImpl.domainMetaStore = savedMetaStore;
    }

    @Test
    public void testGetDomainMetaStoreValidValuesListEmpty() {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        DomainMetaStore savedMetaStore = zmsImpl.domainMetaStore;
        zmsImpl.domainMetaStore = new TestDomainMetaStore();
        DomainMetaStoreValidValuesList emptyValidValuesList = new DomainMetaStoreValidValuesList();
        emptyValidValuesList.setValidValues(new ArrayList<>());
        assertEquals(zmsImpl.getDomainMetaStoreValidValuesList(ctx, "businessService", null), emptyValidValuesList);
        assertEquals(zmsImpl.getDomainMetaStoreValidValuesList(ctx, "awsAccount", null), emptyValidValuesList);
        assertEquals(zmsImpl.getDomainMetaStoreValidValuesList(ctx, "azureSubscription", null), emptyValidValuesList);
        assertEquals(zmsImpl.getDomainMetaStoreValidValuesList(ctx, "gcpProject", null), emptyValidValuesList);
        assertEquals(zmsImpl.getDomainMetaStoreValidValuesList(ctx, "productId", null), emptyValidValuesList);
        zmsImpl.domainMetaStore = savedMetaStore;
    }

    @Test
    public void testGetDomainMetaStoreValidValuesListBadAttribute() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        DomainMetaStore savedMetaStore = zmsImpl.domainMetaStore;
        zmsImpl.domainMetaStore = new TestDomainMetaStore();
        try {
            zmsImpl.getDomainMetaStoreValidValuesList(ctx, "badAttribute", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (400): {code: 400, message: \"Invalid attribute: badAttribute\"}");
        } finally {
            zmsImpl.domainMetaStore = savedMetaStore;
        }
    }

    @Test
    public void testGetDomainMetaStoreValidValuesListMissingAttribute() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        DomainMetaStore savedMetaStore = zmsImpl.domainMetaStore;
        zmsImpl.domainMetaStore = new TestDomainMetaStore();
        try {
            zmsImpl.getDomainMetaStoreValidValuesList(ctx, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getMessage(), "ResourceException (400): {code: 400, message: \"attributeName is mandatory\"}");
        } finally {
            zmsImpl.domainMetaStore = savedMetaStore;
        }
    }

    @Test
    public void testGetDomainMetaStoreValidValuesUsernameLowered() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();

        DomainMetaStore savedMetaStore = zmsImpl.domainMetaStore;
        DomainMetaStore mockDomainMetaStore = Mockito.mock(DomainMetaStore.class);
        List<String> businessServicesList = Collections.singletonList("bservice");
        when(mockDomainMetaStore.getValidBusinessServices(anyString())).thenReturn(businessServicesList);

        zmsImpl.domainMetaStore = mockDomainMetaStore;
        ArgumentCaptor<String> userCapture = ArgumentCaptor.forClass(String.class);
        zmsImpl.getDomainMetaStoreValidValuesList(ctx, "businessService", "TestUser");
        verify(mockDomainMetaStore, times(1)).getValidBusinessServices(userCapture.capture());

        assertEquals(userCapture.getValue(), "testuser");
        zmsImpl.domainMetaStore = savedMetaStore;
    }

    @Test
    public void testPutDomainMetaThrowException() {

        ZMSImplTest.TestAuditLogger alogger = new ZMSImplTest.TestAuditLogger();
        ZMSImpl zmsImpl = zmsTestInitializer.getZmsImpl(alogger);
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domName = "wrongDomainName";
        DomainMeta meta = new DomainMeta();
        meta.setYpmId(ZMSTestInitializer.getRandomProductId());
        try {
            zmsImpl.putDomainMeta(ctx, domName, auditRef, null, meta);
            fail("notfounderror not thrown.");
        } catch (ResourceException e) {
            assertEquals(e.getCode(), 404);
        }
    }

    @Test
    public void testPutDomainMeta() {

        final String domainName = "domain-meta-test";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain resDom1 = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(resDom1);
        assertEquals(resDom1.getDescription(), "Test Domain1");
        assertEquals(resDom1.getOrg(), "testorg");
        assertTrue(resDom1.getEnabled());
        assertFalse(resDom1.getAuditEnabled());
        assertNull(resDom1.getServiceCertExpiryMins());
        assertNull(resDom1.getRoleCertExpiryMins());
        assertNull(resDom1.getMemberExpiryDays());
        assertNull(resDom1.getServiceExpiryDays());
        assertNull(resDom1.getGroupExpiryDays());
        assertNull(resDom1.getTokenExpiryMins());
        assertNull(resDom1.getMemberPurgeExpiryDays());
        assertNull(resDom1.getProductId());
        assertNull(resDom1.getSlackChannel());
        assertNull(resDom1.getOnCall());

        DomainMeta meta = zmsTestInitializer.createDomainMetaObject("Test2 Domain", "NewOrg",
                true, true, "12345", 1001);
        meta.setCertDnsDomain("YAHOO.cloud");
        meta.setServiceCertExpiryMins(100);
        meta.setRoleCertExpiryMins(200);
        meta.setMemberPurgeExpiryDays(90);
        meta.setSignAlgorithm("ec");
        meta.setProductId("abcd-1234");
        meta.setSlackChannel("athenz");
        meta.setOnCall("athenz-oncall");
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);
        zmsImpl.putDomainSystemMeta(ctx, domainName, "auditenabled", auditRef, meta);
        zmsImpl.putDomainSystemMeta(ctx, domainName, "account", auditRef, meta);
        zmsImpl.putDomainSystemMeta(ctx, domainName, "certdnsdomain", auditRef, meta);

        zmsTestInitializer.setupPrincipalSystemMetaDelete(zmsImpl, ctx.principal().getFullName(),
                domainName, "domain", "productid", "org", "certdnsdomain");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "org", auditRef, meta);
        zmsImpl.putDomainSystemMeta(ctx, domainName, "productid", auditRef, meta);

        Domain resDom3 = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(resDom3);
        assertEquals(resDom3.getDescription(), "Test2 Domain");
        assertEquals(resDom3.getOrg(), "neworg");
        assertTrue(resDom3.getEnabled());
        assertTrue(resDom3.getAuditEnabled());
        assertEquals(resDom3.getAccount(), "12345");
        assertEquals(Integer.valueOf(1001), resDom3.getYpmId());
        assertEquals(resDom3.getProductId(), "abcd-1234");
        assertEquals(resDom3.getCertDnsDomain(), "yahoo.cloud");
        assertEquals(resDom3.getServiceCertExpiryMins(), Integer.valueOf(100));
        assertEquals(resDom3.getMemberPurgeExpiryDays(), Integer.valueOf(90));
        assertEquals(resDom3.getRoleCertExpiryMins(), Integer.valueOf(200));
        assertNull(resDom3.getMemberExpiryDays());
        assertNull(resDom3.getServiceExpiryDays());
        assertNull(resDom3.getGroupExpiryDays());
        assertNull(resDom3.getTokenExpiryMins());
        assertEquals(resDom3.getSignAlgorithm(), "ec");
        assertEquals(resDom3.getSlackChannel(), "athenz");
        assertEquals(resDom3.getOnCall(), "athenz-oncall");

        // put the metadata using same product id

        meta = zmsTestInitializer.createDomainMetaObject("just a new desc", "organs",
                true, true, "12345", 1001);
        meta.setMemberExpiryDays(300);
        meta.setServiceExpiryDays(350);
        meta.setGroupExpiryDays(375);
        meta.setTokenExpiryMins(400);
        meta.setProductId("abcd-1234");
        meta.setSlackChannel("");
        meta.setOnCall("");
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);

        resDom3 = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(resDom3);
        assertEquals(resDom3.getDescription(), "just a new desc");
        //org is system attr. so it won't be changed by putdomainmeta call
        assertEquals(resDom3.getOrg(), "neworg");
        assertTrue(resDom3.getEnabled());
        assertTrue(resDom3.getAuditEnabled());
        assertEquals(resDom3.getAccount(), "12345");
        assertEquals(resDom3.getProductId(), "abcd-1234");
        assertEquals(Integer.valueOf(1001), resDom3.getYpmId());
        assertEquals(resDom3.getServiceCertExpiryMins(), Integer.valueOf(100));
        assertEquals(resDom3.getRoleCertExpiryMins(), Integer.valueOf(200));
        assertEquals(resDom3.getMemberExpiryDays(), Integer.valueOf(300));
        assertEquals(resDom3.getServiceExpiryDays(), Integer.valueOf(350));
        assertEquals(resDom3.getGroupExpiryDays(), Integer.valueOf(375));
        assertEquals(resDom3.getTokenExpiryMins(), Integer.valueOf(400));
        assertEquals(resDom3.getMemberPurgeExpiryDays(), Integer.valueOf(90));
        assertNull(resDom3.getSlackChannel());
        assertNull(resDom3.getOnCall());

        zmsImpl.putDomainSystemMeta(ctx, domainName, "org", auditRef, meta);
        resDom3 = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(resDom3);
        assertEquals(resDom3.getOrg(), "organs");

        // put the metadata using new product
        meta = zmsTestInitializer.createDomainMetaObject("just a new desc", "organs",
                true, true, "12345", 1001);
        Integer newProductId = ZMSTestInitializer.getRandomProductId();
        meta.setYpmId(newProductId);
        meta.setProductId("abcd-1234-5678");
        meta.setServiceCertExpiryMins(5);
        meta.setRoleCertExpiryMins(0);
        meta.setMemberExpiryDays(15);
        meta.setServiceExpiryDays(17);
        meta.setGroupExpiryDays(18);
        meta.setTokenExpiryMins(20);
        meta.setMemberPurgeExpiryDays(120);
        meta.setSignAlgorithm("rsa");
        meta.setSlackChannel("coretech");
        meta.setOnCall("athenz-oncall");
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);
        zmsImpl.putDomainSystemMeta(ctx, domainName, "productid", auditRef, meta);

        resDom3 = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(resDom3);
        assertEquals(resDom3.getDescription(), "just a new desc");
        assertEquals(resDom3.getOrg(), "organs");
        assertTrue(resDom3.getEnabled());
        assertTrue(resDom3.getAuditEnabled());
        assertEquals(resDom3.getAccount(), "12345");
        assertEquals(resDom3.getProductId(), "abcd-1234-5678");
        assertEquals(newProductId, resDom3.getYpmId());
        assertEquals(resDom3.getServiceCertExpiryMins(), Integer.valueOf(5));
        assertNull(resDom3.getRoleCertExpiryMins());
        assertEquals(resDom3.getMemberExpiryDays(), Integer.valueOf(15));
        assertEquals(resDom3.getServiceExpiryDays(), Integer.valueOf(17));
        assertEquals(resDom3.getGroupExpiryDays(), Integer.valueOf(18));
        assertEquals(resDom3.getTokenExpiryMins(), Integer.valueOf(20));
        assertEquals(resDom3.getMemberPurgeExpiryDays(), Integer.valueOf(120));
        assertEquals(resDom3.getSignAlgorithm(), "rsa");
        assertNull(resDom3.getFeatureFlags());
        assertEquals(resDom3.getSlackChannel(), "coretech");
        assertEquals(resDom3.getOnCall(), "athenz-oncall");

        // put new feature flags for the domain

        meta.setFeatureFlags(3);
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);
        zmsImpl.putDomainSystemMeta(ctx, domainName, "featureflags", auditRef, meta);

        resDom3 = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(resDom3);
        assertEquals(resDom3.getDescription(), "just a new desc");
        assertEquals(resDom3.getOrg(), "organs");
        assertTrue(resDom3.getEnabled());
        assertTrue(resDom3.getAuditEnabled());
        assertEquals(resDom3.getAccount(), "12345");
        assertEquals(resDom3.getProductId(), "abcd-1234-5678");
        assertEquals(newProductId, resDom3.getYpmId());
        assertEquals(resDom3.getServiceCertExpiryMins(), Integer.valueOf(5));
        assertNull(resDom3.getRoleCertExpiryMins());
        assertEquals(resDom3.getMemberExpiryDays(), Integer.valueOf(15));
        assertEquals(resDom3.getServiceExpiryDays(), Integer.valueOf(17));
        assertEquals(resDom3.getGroupExpiryDays(), Integer.valueOf(18));
        assertEquals(resDom3.getTokenExpiryMins(), Integer.valueOf(20));
        assertEquals(resDom3.getMemberPurgeExpiryDays(), Integer.valueOf(120));
        assertEquals(resDom3.getSignAlgorithm(), "rsa");
        assertEquals(resDom3.getFeatureFlags().intValue(), 3);
        assertEquals(resDom3.getSlackChannel(), "coretech");
        assertEquals(resDom3.getOnCall(), "athenz-oncall");

        // update the feature flags value

        meta.setFeatureFlags(7);
        zmsImpl.putDomainSystemMeta(ctx, domainName, "featureflags", auditRef, meta);
        resDom3 = zmsImpl.getDomain(ctx, domainName);
        assertEquals(resDom3.getFeatureFlags().intValue(), 7);

        zmsTestInitializer.cleanupPrincipalSystemMetaDelete(zmsImpl, "domain");
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainSystemMetaModifiedTimestamp() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "metadomainmodified";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain resDom1 = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(resDom1);
        long domMod1 = resDom1.getModified().millis();

        ZMSTestUtils.sleep(1);

        DomainMeta meta = new DomainMeta();
        zmsImpl.putDomainSystemMeta(ctx, domainName, "modified", auditRef, meta);

        Domain resDom2 = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(resDom2);
        long domMod2 = resDom2.getModified().millis();

        assertTrue(domMod2 > domMod1);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainMetaInvalid() {

        // enable product id support

        System.setProperty(ZMSConsts.ZMS_PROP_PRODUCT_ID_SUPPORT, "true");
        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "MetaDomProductid";
        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        Domain resDom = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(resDom);
        assertEquals(resDom.getDescription(), "Test Domain");
        assertEquals(resDom.getOrg(), "testorg");
        assertTrue(resDom.getEnabled());
        assertFalse(resDom.getAuditEnabled());
        Integer productId = resDom.getYpmId();

        zmsTestInitializer.setupPrincipalSystemMetaDelete(zmsImpl, ctx.principal().getFullName(),
                domainName, "domain", "productid");
        DomainMeta meta = zmsTestInitializer.createDomainMetaObject("Test2 Domain", "NewOrg",
                true, true, "12345", null);
        try {
            zmsImpl.putDomainSystemMeta(ctx, domainName, "productid", auditRef, meta);
            fail("bad request exc not thrown");
        } catch (ResourceException exc) {
            assertEquals(exc.getCode(), 400);
            assertTrue(exc.getMessage().contains("Unique Product Id must be specified for top level domain"));
        }

        // put metadata using another domains productId
        dom = zmsTestInitializer.createTopLevelDomainObject("MetaDomProductid2",
                "Test Domain", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        resDom = zmsImpl.getDomain(ctx, "MetaDomProductid2");
        Integer productId2 = resDom.getYpmId();
        assertNotEquals(productId, productId2);

        meta = zmsTestInitializer.createDomainMetaObject("Test3 Domain", "NewOrg",
                true, true, "12345", productId2);
        try {
            zmsImpl.putDomainSystemMeta(ctx, domainName, "productid", auditRef, meta);
            fail("bad request exc not thrown");
        } catch (ResourceException exc) {
            assertEquals(exc.getCode(), 400);
            assertTrue(exc.getMessage().contains("is already assigned to domain"));
        }

        // test negative values

        meta = new DomainMeta().setServiceExpiryDays(-10);
        try {
            zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        meta = new DomainMeta().setGroupExpiryDays(-10);
        try {
            zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        meta = new DomainMeta().setMemberExpiryDays(-10);
        try {
            zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        meta = new DomainMeta().setRoleCertExpiryMins(-10);
        try {
            zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        meta = new DomainMeta().setServiceCertExpiryMins(-10);
        try {
            zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        meta = new DomainMeta().setTokenExpiryMins(-10);
        try {
            zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        zmsTestInitializer.cleanupPrincipalSystemMetaDelete(zmsImpl, "domain");
        zmsImpl.deleteTopLevelDomain(ctx, "MetaDomProductid", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, "MetaDomProductid2", auditRef, null);
        System.clearProperty(ZMSConsts.ZMS_PROP_PRODUCT_ID_SUPPORT);
        zmsImpl.objectStore.clearConnections();
    }

    @Test
    public void testPutDomainMetaDefaults() {

        final String domainName = "meta-dom-values";
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, null, null,
                zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain resDom1 = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(resDom1);
        assertNull(resDom1.getDescription());
        assertNull(resDom1.getOrg());
        assertTrue(resDom1.getEnabled());
        assertFalse(resDom1.getAuditEnabled());

        DomainMeta meta = zmsTestInitializer.createDomainMetaObject("Test2 Domain", "NewOrg", true, false, null, 0);
        zmsImpl.putDomainMeta(ctx, domainName, auditRef, null, meta);

        zmsImpl.putDomainSystemMeta(ctx, domainName, "org", auditRef, meta);

        Domain resDom3 = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(resDom3);
        assertEquals(resDom3.getDescription(), "Test2 Domain");
        assertEquals(resDom3.getOrg(), "neworg");
        assertTrue(resDom3.getEnabled());
        assertFalse(resDom3.getAuditEnabled());
        assertNull(resDom3.getAccount());
        assertNull(resDom3.getAzureSubscription());
        assertNull(resDom3.getGcpProject());
        assertNull(resDom3.getBusinessService());
        assertEquals(Integer.valueOf(0), resDom3.getYpmId());

        meta.setAccount("aws");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "account", auditRef, meta);
        resDom3 = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(resDom3);
        assertEquals(resDom3.getOrg(), "neworg");
        assertEquals(resDom3.getAccount(), "aws");
        assertNull(resDom3.getAzureSubscription());
        assertNull(resDom3.getGcpProject());
        assertNull(resDom3.getBusinessService());

        meta.setAzureSubscription("azure");
        meta.setAzureTenant("tenant");
        meta.setAzureClient("client");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "azuresubscription", auditRef, meta);
        resDom3 = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(resDom3);
        assertEquals(resDom3.getOrg(), "neworg");
        assertEquals(resDom3.getAccount(), "aws");
        assertEquals(resDom3.getAzureSubscription(), "azure");
        assertEquals(resDom3.getAzureTenant(), "tenant");
        assertEquals(resDom3.getAzureClient(), "client");
        assertNull(resDom3.getGcpProject());
        assertNull(resDom3.getGcpProjectNumber());
        assertNull(resDom3.getBusinessService());

        meta.setGcpProject("gcp");
        meta.setGcpProjectNumber("1239");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "gcpproject", auditRef, meta);
        resDom3 = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(resDom3);
        assertEquals(resDom3.getOrg(), "neworg");
        assertEquals(resDom3.getAccount(), "aws");
        assertEquals(resDom3.getAzureSubscription(), "azure");
        assertEquals(resDom3.getAzureTenant(), "tenant");
        assertEquals(resDom3.getAzureClient(), "client");
        assertEquals(resDom3.getGcpProject(), "gcp");
        assertEquals(resDom3.getGcpProjectNumber(), "1239");
        assertNull(resDom3.getBusinessService());

        meta.setBusinessService("123:business service");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "businessservice", auditRef, meta);
        resDom3 = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(resDom3);
        assertEquals(resDom3.getOrg(), "neworg");
        assertEquals(resDom3.getAccount(), "aws");
        assertEquals(resDom3.getAzureSubscription(), "azure");
        assertEquals(resDom3.getAzureTenant(), "tenant");
        assertEquals(resDom3.getAzureClient(), "client");
        assertEquals(resDom3.getGcpProject(), "gcp");
        assertEquals(resDom3.getGcpProjectNumber(), "1239");
        assertEquals(resDom3.getBusinessService(), "123:business service");

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainMetaMissingAuditRef() {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        String domain = "testSetDomainMetaMissingAuditRef";
        TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject(
                domain, "Test1 Domain", "testOrg", zmsTestInitializer.getAdminUser());
        dom.setAuditEnabled(true);
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);

        Domain resDom = zmsImpl.getDomain(ctx, domain);
        assertNotNull(resDom);
        assertEquals(resDom.getDescription(), "Test1 Domain");
        assertEquals(resDom.getOrg(), "testorg");
        assertTrue(resDom.getAuditEnabled());

        DomainMeta meta = zmsTestInitializer.createDomainMetaObject("Test2 Domain", "NewOrg", false, true, null, 0);
        try {
            zmsImpl.putDomainMeta(ctx, domain, null, null, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Audit reference required"));
        } finally {
            zmsImpl.deleteTopLevelDomain(ctx, domain, auditRef, null);
        }
    }

    @Test
    public void testPutDomainMetaSubDomain() {
        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        try {
            TopLevelDomain dom = zmsTestInitializer.createTopLevelDomainObject("MetaDomProductid",
                    "Test Domain", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
            zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom);
        } catch (ResourceException rexc) {
            assertEquals(rexc.getCode(), 400);
        }

        SubDomain subDom = zmsTestInitializer.createSubDomainObject("metaSubDom", "MetaDomProductid",
                "sub Domain", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postSubDomain(ctx, "MetaDomProductid", auditRef, null, subDom);

        // put metadata with null productId
        DomainMeta meta = zmsTestInitializer.createDomainMetaObject("Test sub Domain", "NewOrg",
                true, true, "12345", null);
        zmsImpl.putDomainMeta(ctx, "MetaDomProductid.metaSubDom", auditRef, null, meta);

        // put metadata with a productId
        meta = zmsTestInitializer.createDomainMetaObject("Test sub Domain", "NewOrg",
                true, true, "12345", ZMSTestInitializer.getRandomProductId());
        zmsImpl.putDomainMeta(ctx, "MetaDomProductid.metaSubDom", auditRef, null, meta);

        // set the expiry days to 30

        meta.setMemberExpiryDays(30);
        meta.setServiceExpiryDays(25);
        meta.setGroupExpiryDays(35);
        zmsImpl.putDomainMeta(ctx, "MetaDomProductid.metaSubDom", auditRef, null, meta);
        Domain domain = zmsImpl.getDomain(ctx, "MetaDomProductid.metaSubDom");
        assertEquals(domain.getMemberExpiryDays(), Integer.valueOf(30));
        assertEquals(domain.getServiceExpiryDays(), Integer.valueOf(25));
        assertEquals(domain.getGroupExpiryDays(), Integer.valueOf(35));

        // if value is null we're not going to change it

        meta.setMemberExpiryDays(null);
        meta.setServiceExpiryDays(null);
        meta.setGroupExpiryDays(null);
        meta.setDescription("test1");
        zmsImpl.putDomainMeta(ctx, "MetaDomProductid.metaSubDom", auditRef, null, meta);
        domain = zmsImpl.getDomain(ctx, "MetaDomProductid.metaSubDom");
        assertEquals(domain.getMemberExpiryDays(), Integer.valueOf(30));
        assertEquals(domain.getServiceExpiryDays(), Integer.valueOf(25));
        assertEquals(domain.getGroupExpiryDays(), Integer.valueOf(35));
        assertEquals(domain.getDescription(), "test1");

        // setting is to 0

        meta.setMemberExpiryDays(0);
        meta.setServiceExpiryDays(0);
        meta.setGroupExpiryDays(0);
        meta.setDescription("test2");
        zmsImpl.putDomainMeta(ctx, "MetaDomProductid.metaSubDom", auditRef, null, meta);
        domain = zmsImpl.getDomain(ctx, "MetaDomProductid.metaSubDom");
        assertNull(domain.getMemberExpiryDays());
        assertNull(domain.getServiceExpiryDays());
        assertNull(domain.getGroupExpiryDays());
        assertEquals(domain.getDescription(), "test2");

        zmsImpl.deleteSubDomain(ctx, "MetaDomProductid", "metaSubDom", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, "MetaDomProductid", auditRef, null);
    }

    @Test
    public void testPutDomainSystemMetaX509CertSignerKeyId() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "athenz-domain-with-x509-cert-signer-key-id";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertNull(domain.getX509CertSignerKeyId());

        // set the x509 cert signer key id

        DomainMeta dm = new DomainMeta().setX509CertSignerKeyId("x509-keyid");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "x509certsignerkeyid", auditRef, dm);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getX509CertSignerKeyId(), "x509-keyid");

        // update the x509 cert signer key id
        // first we're going to be rejected with invalid authorization

        dm.setX509CertSignerKeyId("x509-keyid-2");
        try {
            zmsImpl.putDomainSystemMeta(ctx, domainName, "x509certsignerkeyid", auditRef, dm);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("unauthorized to reset system meta attribute: x509certsignerkeyid"));
        }

        // let's create the role and policy to allow this operation

        Role role1 = zmsTestInitializer.createRoleObject("sys.auth", "meta-cert-signer-keyid", null, "user.user1",
                zmsTestInitializer.getAdminUser());
        zmsImpl.putRole(ctx, "sys.auth", "meta-cert-signer-keyid", auditRef, false, null, role1);

        Policy policy1 = zmsTestInitializer.createPolicyObject("sys.auth", "meta-cert-signer-keyid",
                "meta-cert-signer-keyid", "delete", "sys.auth:meta.domain.x509certsignerkeyid.*",
                AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, "sys.auth", "meta-cert-signer-keyid", auditRef, false, null, policy1);

        // now our operation should succeed

        zmsImpl.putDomainSystemMeta(ctx, domainName, "x509certsignerkeyid", auditRef, dm);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getX509CertSignerKeyId(), "x509-keyid-2");

        // set an invalid value and verify failure

        dm = new DomainMeta().setX509CertSignerKeyId("invalid key id");
        try {
            zmsImpl.putDomainSystemMeta(ctx, domainName, "x509certsignerkeyid", auditRef, dm);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid CompoundName error"));
        }

        // remove the x509 cert signer key id

        dm = new DomainMeta().setX509CertSignerKeyId("");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "x509certsignerkeyid", auditRef, dm);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertNull(domain.getX509CertSignerKeyId());

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testPutDomainSystemMetaSshCertSignerKeyId() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "athenz-domain-with-ssh-cert-signer-key-id";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Domain domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertNull(domain.getSshCertSignerKeyId());

        // set the ssh cert signer key id

        DomainMeta dm = new DomainMeta().setSshCertSignerKeyId("ssh-keyid");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "sshcertsignerkeyid", auditRef, dm);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getSshCertSignerKeyId(), "ssh-keyid");

        // update the ssh cert signer key id
        // first we're going to be rejected with invalid authorization

        dm.setSshCertSignerKeyId("ssh-keyid-2");
        try {
            zmsImpl.putDomainSystemMeta(ctx, domainName, "sshcertsignerkeyid", auditRef, dm);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("unauthorized to reset system meta attribute: sshcertsignerkeyid"));
        }

        // let's create the role and policy to allow this operation

        Role role1 = zmsTestInitializer.createRoleObject("sys.auth", "meta-cert-signer-keyid", null, "user.user1",
                zmsTestInitializer.getAdminUser());
        zmsImpl.putRole(ctx, "sys.auth", "meta-cert-signer-keyid", auditRef, false, null, role1);

        Policy policy1 = zmsTestInitializer.createPolicyObject("sys.auth", "meta-cert-signer-keyid",
                "meta-cert-signer-keyid", "delete", "sys.auth:meta.domain.sshcertsignerkeyid.*",
                AssertionEffect.ALLOW);
        zmsImpl.putPolicy(ctx, "sys.auth", "meta-cert-signer-keyid", auditRef, false, null, policy1);

        // now our operation should succeed

        zmsImpl.putDomainSystemMeta(ctx, domainName, "sshcertsignerkeyid", auditRef, dm);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertEquals(domain.getSshCertSignerKeyId(), "ssh-keyid-2");

        // set an invalid value and verify failure

        dm = new DomainMeta().setSshCertSignerKeyId("invalid key id");
        try {
            zmsImpl.putDomainSystemMeta(ctx, domainName, "sshcertsignerkeyid", auditRef, dm);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid CompoundName error"));
        }

        // remove the ssh cert signer key id

        dm = new DomainMeta().setSshCertSignerKeyId("");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "sshcertsignerkeyid", auditRef, dm);

        domain = zmsImpl.getDomain(ctx, domainName);
        assertNotNull(domain);
        assertNull(domain.getX509CertSignerKeyId());

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testSubDomainSignerKeyIdInherit() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "athenz-domain-inherit-signer-key";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // create subdomain and verify no signer key ids

        SubDomain subDom1 = zmsTestInitializer.createSubDomainObject("sub1", domainName,
                "sub Domain", "testOrg", zmsTestInitializer.getAdminUser(), "user.user1");
        zmsImpl.postSubDomain(ctx, domainName, auditRef, null, subDom1);

        Domain domain = zmsImpl.getDomain(ctx, domainName + ".sub1");
        assertNotNull(domain);
        assertNull(domain.getX509CertSignerKeyId());
        assertNull(domain.getSshCertSignerKeyId());

        // now set the x509 and ssh cert signer key ids

        DomainMeta dm = new DomainMeta().setSshCertSignerKeyId("ssh-keyid")
                        .setX509CertSignerKeyId("x509-keyid");
        zmsImpl.putDomainSystemMeta(ctx, domainName, "sshcertsignerkeyid", auditRef, dm);
        zmsImpl.putDomainSystemMeta(ctx, domainName, "x509certsignerkeyid", auditRef, dm);

        // create a new subdomain and verify the key ids are inherited

        SubDomain subDom2 = zmsTestInitializer.createSubDomainObject("sub2", domainName,
                "sub Domain", "testOrg", zmsTestInitializer.getAdminUser(), "user.user1");
        zmsImpl.postSubDomain(ctx, domainName, auditRef, null, subDom2);

        domain = zmsImpl.getDomain(ctx, domainName + ".sub2");
        assertNotNull(domain);
        assertEquals(domain.getSshCertSignerKeyId(), "ssh-keyid");
        assertEquals(domain.getX509CertSignerKeyId(), "x509-keyid");

        // create another subdomain for the subdomain and verify the key ids are inherited

        SubDomain subDom3 = zmsTestInitializer.createSubDomainObject("sub3", domainName + ".sub2",
                "sub Domain", "testOrg", zmsTestInitializer.getAdminUser(), "user.user1");
        zmsImpl.postSubDomain(ctx, domainName + ".sub2", auditRef, null, subDom3);

        domain = zmsImpl.getDomain(ctx, domainName + ".sub2.sub3");
        assertNotNull(domain);
        assertEquals(domain.getSshCertSignerKeyId(), "ssh-keyid");
        assertEquals(domain.getX509CertSignerKeyId(), "x509-keyid");

        zmsImpl.deleteSubDomain(ctx, domainName + ".sub2", "sub3", auditRef, null);
        zmsImpl.deleteSubDomain(ctx, domainName, "sub2", auditRef, null);
        zmsImpl.deleteSubDomain(ctx, domainName, "sub1", auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testValidateDomainRegularMetaStoreValuesNotValid() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        DomainMetaStore metaStore = Mockito.mock(DomainMetaStore.class);
        when(metaStore.isValidBusinessService(Mockito.anyString(), Mockito.anyString()))
                .thenReturn(false);
        when(metaStore.isValidOnCall(Mockito.anyString(), Mockito.anyString()))
                .thenReturn(false);

        DomainMetaStore savedMetaStore = zmsImpl.domainMetaStore;
        zmsImpl.domainMetaStore = metaStore;

        Domain domain = new Domain().setBusinessService("service1");
        DomainMeta meta = new DomainMeta().setBusinessService("service2");

        try {
            zmsImpl.validateDomainRegularMetaStoreValues(domain, meta);
            fail("should have thrown exception");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("invalid business service name for domain"));
        }

        domain = new Domain().setOnCall("oncall1");
        meta = new DomainMeta().setOnCall("oncall2");

        try {
            zmsImpl.validateDomainRegularMetaStoreValues(domain, meta);
            fail("should have thrown exception");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("invalid on-call support team id/name for domain"));
        }

        // restore the original meta store
        zmsImpl.domainMetaStore = savedMetaStore;
    }

    @Test
    public void testValidateDomainRegularMetaStoreValuesException() throws ServerResourceException {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();

        DomainMetaStore metaStore = Mockito.mock(DomainMetaStore.class);
        when(metaStore.isValidBusinessService(Mockito.anyString(), Mockito.anyString()))
                .thenThrow(new ServerResourceException(400));
        when(metaStore.isValidOnCall(Mockito.anyString(), Mockito.anyString()))
                .thenThrow(new ServerResourceException(400));

        DomainMetaStore savedMetaStore = zmsImpl.domainMetaStore;
        zmsImpl.domainMetaStore = metaStore;

        Domain domain = new Domain().setBusinessService("service1");
        DomainMeta meta = new DomainMeta().setBusinessService("service2");

        try {
            zmsImpl.validateDomainRegularMetaStoreValues(domain, meta);
            fail("should have thrown exception");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("invalid business service name for domain"));
        }

        domain = new Domain().setOnCall("oncall1");
        meta = new DomainMeta().setOnCall("oncall2");

        try {
            zmsImpl.validateDomainRegularMetaStoreValues(domain, meta);
            fail("should have thrown exception");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("invalid on-call support team id/name for domain"));
        }

        // restore the original meta store
        zmsImpl.domainMetaStore = savedMetaStore;
    }
}
