package com.yahoo.athenz.zms;

import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.common.messaging.DomainChangeMessage;
import com.yahoo.athenz.common.messaging.MockDomainChangePublisher;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Ignore;
import org.testng.annotations.Test;

import java.util.List;
import java.util.stream.Collectors;

import static com.yahoo.athenz.zms.ZMSConsts.ZMS_PROP_DOMAIN_CHANGE_TOPIC_NAMES;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

@Ignore
public class ZMSImplDomainChangeEventTest {

    private ZMSImpl zms = null;
    private final ResourceContext mockContext = Mockito.mock(ResourceContext.class);

    @BeforeMethod
    public void setUp() throws Exception {
        System.setProperty(ZMSConsts.ZMS_PROP_OBJECT_STORE_FACTORY_CLASS, "com.yahoo.athenz.zms.store.MockObjectStoreFactory");
        System.setProperty(ZMSConsts.ZMS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS, "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zms_private.pem");
        System.setProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN, "user.testadminuser");
        //System.setProperty(ZMS_PROP_DOMAIN_CHANGE_PUBLISHER_CLASS, "com.yahoo.athenz.common.messaging.MockDomainChangePublisher");
        System.setProperty(ZMS_PROP_DOMAIN_CHANGE_TOPIC_NAMES, "topic");
        zms = new ZMSImpl();
    }

    @AfterMethod
    public void tearDown() throws Exception {
        System.clearProperty(ZMSConsts.ZMS_PROP_OBJECT_STORE_FACTORY_CLASS);
        System.clearProperty(ZMSConsts.ZMS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS);
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        System.clearProperty(ZMSConsts.ZMS_PROP_DOMAIN_ADMIN);
       // System.clearProperty(ZMS_PROP_DOMAIN_CHANGE_PUBLISHER_CLASS);
        System.clearProperty(ZMS_PROP_DOMAIN_CHANGE_TOPIC_NAMES);
    }
    
    private MockDomainChangePublisher.Recorder getEventRecorder() {
        return ((MockDomainChangePublisher) zms.domainChangePublishers.get(0)).getRecorder();
    }

    private DomainChangeMessage getActualDomainChangeMessage() {
        MockDomainChangePublisher.Recorder evtRecorder = getEventRecorder();
        ArgumentCaptor<DomainChangeMessage> evtArgumentCaptor = ArgumentCaptor.forClass(DomainChangeMessage.class);
        verify(evtRecorder, Mockito.times(1)).record(evtArgumentCaptor.capture());
        return evtArgumentCaptor.getValue();
    }
    
    @Test
    public void testNoConfiguredTopic() {
        System.clearProperty(ZMS_PROP_DOMAIN_CHANGE_TOPIC_NAMES);
        zms = new ZMSImpl();
        assertNull(zms.domainChangePublishers);
    }

    @Test
    public void testMultipleTopics() {
        System.setProperty(ZMS_PROP_DOMAIN_CHANGE_TOPIC_NAMES, "topic1 , topic2");
        zms = new ZMSImpl();
        assertNotNull(zms.domainChangePublishers);
        List<String> topicNames = zms.domainChangePublishers.stream()
            .map(publisher -> ((MockDomainChangePublisher) publisher).getTopicName())
            .collect(Collectors.toList());
        assertThat(topicNames, containsInAnyOrder("topic1", "topic2"));
    }
    
    @Test
    public void testOperationFailure() {
        String apiName = "postTopLevelDomain";
        String name = "domain-name";
        TopLevelDomain detail = new TopLevelDomain().setName(name);
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 500);

        MockDomainChangePublisher.Recorder evtRecorder = getEventRecorder();
        ArgumentCaptor<DomainChangeMessage> evtArgumentCaptor = ArgumentCaptor.forClass(DomainChangeMessage.class);
        verify(evtRecorder, Mockito.times(0)).record(evtArgumentCaptor.capture());
    }
    

    
    @Test
    public void testPutServiceIdentity() {
        String apiName = "putServiceIdentity";
        String domain = "domain-name";
        String service = "service-name";
        ServiceIdentity detail = new ServiceIdentity();
        when(mockContext.getApiName()).thenReturn(apiName);
        //zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}", domain, service, detail);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.SERVICE);
        assertEquals(actual.getDomainName(), domain);
        assertEquals(actual.getObjectName(), service);
    }

    @Test
    public void testDeleteServiceIdentity() {
        String apiName = "deleteServiceIdentity";
        String domain = "domain-name";
        String service = "service-name";
        when(mockContext.getApiName()).thenReturn(apiName);
        //zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}", domain, service);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.SERVICE);
        assertEquals(actual.getDomainName(), domain);
        assertEquals(actual.getObjectName(), service);
    }

    @Test
    public void testPutPublicKeyEntry() {
        String apiName = "putPublicKeyEntry";
        String domain = "domain-name";
        String service = "service-name";
        String id = "id";
        PublicKeyEntry publicKeyEntry = new PublicKeyEntry();
        when(mockContext.getApiName()).thenReturn(apiName);
        //zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}/publickey/{id}", domain, service, id, publicKeyEntry);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.SERVICE);
        assertEquals(actual.getDomainName(), domain);
        assertEquals(actual.getObjectName(), service);
    }

    @Test
    public void testDeletePublicKeyEntry() {
        String apiName = "deletePublicKeyEntry";
        String domain = "domain-name";
        String service = "service-name";
        String id = "id";
        when(mockContext.getApiName()).thenReturn(apiName);
        //zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}/publickey/{id}", domain, service, id);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.SERVICE);
        assertEquals(actual.getDomainName(), domain);
        assertEquals(actual.getObjectName(), service);
    }

    @Test
    public void testPutServiceIdentitySystemMeta() {
        String apiName = "putServiceIdentitySystemMeta";
        String domain = "domain-name";
        String service = "service-name";
        String attribute = "attribute";
        ServiceIdentitySystemMeta detail = new ServiceIdentitySystemMeta();
        when(mockContext.getApiName()).thenReturn(apiName);
        //zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}/meta/system/{attribute}", domain, service, attribute, detail);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.SERVICE);
        assertEquals(actual.getDomainName(), domain);
        assertEquals(actual.getObjectName(), service);
    }

    @Test
    public void testPutTenancy() {
        String apiName = "putTenancy";
        String domain = "domain-name";
        String service = "service-name";
        Tenancy detail = new Tenancy();
        when(mockContext.getApiName()).thenReturn(apiName);
        //zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/tenancy/{service}", domain, service, detail);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.SERVICE);
        assertEquals(actual.getDomainName(), domain);
        assertEquals(actual.getObjectName(), service);
    }

    @Test
    public void testDeleteTenancy() {
        String apiName = "deleteTenancy";
        String domain = "domain-name";
        String service = "service-name";
        when(mockContext.getApiName()).thenReturn(apiName);
        //zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/tenancy/{service}", domain, service);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.SERVICE);
        assertEquals(actual.getDomainName(), domain);
        assertEquals(actual.getObjectName(), service);
    }

    @Test
    public void testPutTenant() {
        String apiName = "putTenant";
        String domain = "domain-name";
        String service = "service-name";
        String tenantDomain = "tenant-domain";
        Tenancy detail = new Tenancy();
        when(mockContext.getApiName()).thenReturn(apiName);
        //zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}/tenant/{tenantDomain}", domain, service, tenantDomain, detail);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.SERVICE);
        assertEquals(actual.getDomainName(), domain);
        assertEquals(actual.getObjectName(), service);
    }

    @Test
    public void testDeleteTenant() {
        String apiName = "deleteTenant";
        String domain = "domain-name";
        String service = "service-name";
        String tenantDomain = "tenant-domain";
        when(mockContext.getApiName()).thenReturn(apiName);
        //zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}/tenant/{tenantDomain}", domain, service, tenantDomain);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.SERVICE);
        assertEquals(actual.getDomainName(), domain);
        assertEquals(actual.getObjectName(), service);
    }

    @Test
    public void testPutTenantResourceGroupRoles() {
        String apiName = "putTenantResourceGroupRoles";
        String domain = "domain-name";
        String service = "service-name";
        String tenantDomain = "tenant-domain";
        String resourceGroup = "res-group";
        TenantResourceGroupRoles detail = new TenantResourceGroupRoles();
        when(mockContext.getApiName()).thenReturn(apiName);
        //zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}/tenant/{tenantDomain}/resourceGroup/{resourceGroup}", domain, service, tenantDomain, resourceGroup, detail);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.SERVICE);
        assertEquals(actual.getDomainName(), domain);
        assertEquals(actual.getObjectName(), service);
    }

    @Test
    public void testDeleteTenantResourceGroupRoles() {
        String apiName = "deleteTenantResourceGroupRoles";
        String domain = "domain-name";
        String service = "service-name";
        String tenantDomain = "tenant-domain";
        String resourceGroup = "res-group";
        when(mockContext.getApiName()).thenReturn(apiName);
        //zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}/tenant/{tenantDomain}/resourceGroup/{resourceGroup}", domain, service, tenantDomain, resourceGroup);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.SERVICE);
        assertEquals(actual.getDomainName(), domain);
        assertEquals(actual.getObjectName(), service);
    }

    @Test
    public void testPutProviderResourceGroupRoles() {
        String apiName = "putProviderResourceGroupRoles";
        String tenantDomain = "tenant-domain";
        String resourceGroup = "res-group";
        String provDomain = "prov-domain";
        String provService = "prov-service";
        ProviderResourceGroupRoles detail = new ProviderResourceGroupRoles();
        when(mockContext.getApiName()).thenReturn(apiName);
        //zms.publishChangeEvent(mockContext, 200, "/domain/{tenantDomain}/provDomain/{provDomain}/provService/{provService}/resourceGroup/{resourceGroup}", tenantDomain, provDomain, provService, resourceGroup, detail);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.SERVICE);
        assertEquals(actual.getDomainName(), tenantDomain);
        assertEquals(actual.getObjectName(), provService);
    }

    @Test
    public void testDeleteProviderResourceGroupRoles() {
        String apiName = "deleteProviderResourceGroupRoles";
        String tenantDomain = "tenant-domain";
        String resourceGroup = "res-group";
        String provDomain = "prov-domain";
        String provService = "prov-service";
        when(mockContext.getApiName()).thenReturn(apiName);
        //zms.publishChangeEvent(mockContext, 200, "/domain/{tenantDomain}/provDomain/{provDomain}/provService/{provService}/resourceGroup/{resourceGroup}", tenantDomain, provDomain, provService, resourceGroup);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.SERVICE);
        assertEquals(actual.getDomainName(), tenantDomain);
        assertEquals(actual.getObjectName(), provService);
    }

    @Test
    public void testDeleteUser() {
        String apiName = "deleteUser";
        String name = "user-name";
        when(mockContext.getApiName()).thenReturn(apiName);
        //zms.publishChangeEvent(mockContext, 200, "/user/{name}", name);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        //assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.USER);
        assertNull(actual.getDomainName());
        assertEquals(actual.getObjectName(), name);
    }

    @Test
    public void testDeleteDomainRoleMember() {
        String apiName = "deleteDomainRoleMember";
        String domainName = "domain-name";
        String memberName = "member-name";
        when(mockContext.getApiName()).thenReturn(apiName);
        //zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/member/{memberName}", domainName, memberName);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.ROLE);
        assertEquals(actual.getObjectName(), memberName); //TODO: what is expected result here?
    }

    @Test
    public void testPutQuota() {
        String apiName = "putQuota";
        String name = "domain-name";
        Quota quota = new Quota();
        when(mockContext.getApiName()).thenReturn(apiName);
        //zms.publishChangeEvent(mockContext, 200, "/domain/{name}/quota", name, quota);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.DOMAIN);
        assertEquals(actual.getObjectName(), "quota"); //TODO: what is expected result here?
    }

    @Test
    public void testDeleteQuota() {
        String apiName = "deleteQuota";
        String name = "domain-name";
        when(mockContext.getApiName()).thenReturn(apiName);
        //zms.publishChangeEvent(mockContext, 200, "/domain/{name}/quota", name);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.DOMAIN);
        assertEquals(actual.getObjectName(), "quota"); //TODO: what is expected result here?
    }
}
