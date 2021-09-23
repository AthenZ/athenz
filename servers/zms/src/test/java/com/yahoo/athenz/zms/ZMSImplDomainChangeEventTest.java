package com.yahoo.athenz.zms;

import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.common.messaging.DomainChangeMessage;
import com.yahoo.athenz.common.messaging.MockDomainChangePublisher;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.List;
import java.util.stream.Collectors;

import static com.yahoo.athenz.zms.ZMSConsts.ZMS_PROP_DOMAIN_CHANGE_TOPIC_NAMES;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

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
        zms.publishChangeEvent(mockContext, 500, "/domain", detail);

        MockDomainChangePublisher.Recorder evtRecorder = getEventRecorder();
        ArgumentCaptor<DomainChangeMessage> evtArgumentCaptor = ArgumentCaptor.forClass(DomainChangeMessage.class);
        verify(evtRecorder, Mockito.times(0)).record(evtArgumentCaptor.capture());
    }
    
    // done
    @Test
    public void testPostTopLevelDomain() {
        String apiName = "postTopLevelDomain";
        String name = "domain-name";
        TopLevelDomain detail = new TopLevelDomain().setName(name);
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain", detail);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.DOMAIN);
        assertEquals(actual.getDomainName(), name);
        assertEquals(actual.getObjectName(), name);
    }

    //DONE
    @Test
    public void testPostSubDomain() {
        String apiName = "postSubDomain";
        String name = "subdomain-name";
        SubDomain detail = new SubDomain().setName(name);
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/subdomain/{parent}", "parent", detail);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.DOMAIN);
        assertEquals(actual.getDomainName(), name);
        assertEquals(actual.getObjectName(), name);
    }

    // done
    @Test
    public void testPostUserDomain() {
        String apiName = "postUserDomain";
        String name = "userdomain-name";
        UserDomain detail = new UserDomain().setName(name);
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/userdomain/{name}", name, detail);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.DOMAIN);
        assertEquals(actual.getDomainName(), name);
        assertEquals(actual.getObjectName(), name);
    }

    // done
    @Test
    public void testDeleteTopLevelDomain() {
        String apiName = "deleteTopLevelDomain";
        String name = "domain-name";
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{name}", name);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.DOMAIN);
        assertEquals(actual.getDomainName(), name);
        assertEquals(actual.getObjectName(), name);
    }

    // done
    @Test
    public void testDeleteSubDomain() {
        String apiName = "deleteSubDomain";
        String name = "subdomain-name";
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/subdomain/{parent}/{name}", "parent", name);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.DOMAIN);
        assertEquals(actual.getDomainName(), name);
        assertEquals(actual.getObjectName(), name);
    }

    // done
    @Test
    public void testDeleteUserDomain() {
        String apiName = "deleteUserDomain";
        String name = "userdomain-name";
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/userdomain/{name}", name);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.DOMAIN);
        assertEquals(actual.getDomainName(), name);
        assertEquals(actual.getObjectName(), name);
    }

    // done
    @Test
    public void testPutDomainMeta() {
        String apiName = "putDomainMeta";
        String name = "domain-name";
        DomainMeta detail = new DomainMeta();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{name}/meta", name, detail);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.DOMAIN);
        assertEquals(actual.getDomainName(), name);
        assertEquals(actual.getObjectName(), name);
    }

    // done
    @Test
    public void testPutDomainSystemMeta() {
        String apiName = "putDomainSystemMeta";
        String name = "domain-name";
        String attribute = "domain-attribute";
        DomainMeta detail = new DomainMeta();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{name}/meta/system/{attribute}", name, attribute, detail);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.DOMAIN);
        assertEquals(actual.getDomainName(), name);
        assertEquals(actual.getObjectName(), attribute);
    }

    // done
    @Test
    public void testPutDomainTemplate() {
        String apiName = "putDomainTemplate";
        String name = "domain-name";
        DomainTemplate domainTemplate = new DomainTemplate();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{name}/template", name, domainTemplate);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.DOMAIN);
        assertEquals(actual.getDomainName(), name);
        assertEquals(actual.getObjectName(), name);
    }

    // done 
    @Test
    public void testPutDomainTemplateExt() {
        String apiName = "putDomainTemplateExt";
        String name = "domain-name";
        String template = "template";
        DomainTemplate domainTemplate = new DomainTemplate();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{name}/template/{template}", name, template, domainTemplate);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.DOMAIN);
        assertEquals(actual.getDomainName(), name);
        assertEquals(actual.getObjectName(), template);
    }

    // done
    @Test
    public void testDeleteDomainTemplate() {
        String apiName = "deleteDomainTemplate";
        String name = "domain-name";
        String template = "template";
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{name}/template/{template}", name, template);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.DOMAIN);
        assertEquals(actual.getDomainName(), name);
        assertEquals(actual.getObjectName(), template);
    }

    // done
    @Test
    public void testPutEntity() {
        String apiName = "putEntity";
        String domainName = "domain-name";
        String entityName = "entity-name";
        Entity entity = new Entity();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/entity/{entityName}", domainName, entityName, entity);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.ENTITY);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), entityName);
    }

    // done
    @Test
    public void testDeleteEntity() {
        String apiName = "deleteEntity";
        String domainName = "domain-name";
        String entityName = "entity-name";
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/entity/{entityName}", domainName, entityName);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.ENTITY);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), entityName);
    }

    // done
    @Test
    public void testPutRole() {
        String apiName = "putRole";
        String domainName = "domain-name";
        String roleName = "role-name";
        Role role = new Role();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/role/{roleName}", domainName, roleName, role);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.ROLE);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), roleName);
    }

    @Test
    public void testDeleteRole() {
        String apiName = "deleteRole";
        String domainName = "domain-name";
        String roleName = "role-name";
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/role/{roleName}", domainName, roleName);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.ROLE);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), roleName);
    }

    // done
    @Test
    public void testPutMembership() {
        String apiName = "putMembership";
        String domainName = "domain-name";
        String roleName = "role-name";
        String memberName = "member-name";
        Membership membership = new Membership();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/role/{roleName}/member/{memberName}", domainName, roleName, memberName, membership);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.ROLE);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), roleName); //TODO: what should be the changed object? role or member? or combine it somehow?
    }

    // done
    @Test
    public void testDeleteMembership() {
        String apiName = "deleteMembership";
        String domainName = "domain-name";
        String roleName = "role-name";
        String memberName = "member-name";
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/role/{roleName}/member/{memberName}", domainName, roleName, memberName);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.ROLE);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), roleName); //TODO: what should be the changed object? role or member? or combine it somehow?
    }

    //done
    @Test
    public void testDeletePendingMembership() {
        String apiName = "deletePendingMembership";
        String domainName = "domain-name";
        String roleName = "role-name";
        String memberName = "member-name";
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/role/{roleName}/pendingmember/{memberName}", domainName, roleName, memberName);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.ROLE);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), roleName); //TODO: what should be the changed object? role or member? or combine it somehow?
    }

    @Test
    public void testPutDefaultAdmins() {
        String apiName = "putDefaultAdmins";
        String domainName = "domain-name";
        DefaultAdmins defaultAdmins = new DefaultAdmins();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/admins", domainName, defaultAdmins);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.DOMAIN);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), domainName); //TODO: what should be the changed object? role or member? or combine it somehow?
    }

    @Test
    public void testPutRoleSystemMeta() {
        String apiName = "putRoleSystemMeta";
        String domainName = "domain-name";
        String roleName = "role-name";
        String attribute = "attribute";
        RoleSystemMeta detail = new RoleSystemMeta();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/role/{roleName}/meta/system/{attribute}", domainName, roleName, attribute, detail);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.ROLE);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), roleName); //TODO: what should be the changed object? role or member? or combine it somehow?
    }

    // done
    @Test
    public void testPutRoleMeta() {
        String apiName = "putRoleMeta";
        String domainName = "domain-name";
        String roleName = "role-name";
        RoleMeta detail = new RoleMeta();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/role/{roleName}/meta", domainName, roleName, detail);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.ROLE);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), roleName); //TODO: what should be the changed object? role or member? or combine it somehow?
    }

    // done
    @Test
    public void testPutMembershipDecision() {
        String apiName = "putMembershipDecision";
        String domainName = "domain-name";
        String roleName = "role-name";
        String memberName = "member-name";
        Membership membership = new Membership();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/role/{roleName}/member/{memberName}/decision", domainName, roleName, memberName, membership);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.ROLE);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), roleName); //TODO: what should be the changed object? role or member? or combine it somehow?
    }

    // done
    @Test
    public void testPutRoleReview() {
        String apiName = "putRoleReview";
        String domainName = "domain-name";
        String roleName = "role-name";
        Role role = new Role();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/role/{roleName}/review", domainName, roleName, role);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.ROLE);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), roleName);
    }

    @Test
    public void testPutGroup() {
        String apiName = "putGroup";
        String domainName = "domain-name";
        String groupName = "group-name";
        Group group = new Group();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/group/{groupName}", domainName, groupName, group);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.GROUP);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), groupName);
    }

    @Test
    public void testDeleteGroup() {
        String apiName = "deleteGroup";
        String domainName = "domain-name";
        String groupName = "group-name";
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/group/{groupName}", domainName, groupName);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.GROUP);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), groupName);
    }

    @Test
    public void testPutGroupMembership() {
        String apiName = "putGroupMembership";
        String domainName = "domain-name";
        String groupName = "group-name";
        String memberName = "member-name";
        GroupMembership membership = new GroupMembership();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/group/{groupName}/member/{memberName}", domainName, groupName, memberName, membership);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.GROUP);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), groupName);
    }

    @Test
    public void testDeleteGroupMembership() {
        String apiName = "deleteGroupMembership";
        String domainName = "domain-name";
        String groupName = "group-name";
        String memberName = "member-name";
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/group/{groupName}/member/{memberName}", domainName, groupName, memberName);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.GROUP);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), groupName);
    }

    @Test
    public void testDeletePendingGroupMembership() {
        String apiName = "deletePendingGroupMembership";
        String domainName = "domain-name";
        String groupName = "group-name";
        String memberName = "member-name";
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/group/{groupName}/pendingmember/{memberName}", domainName, groupName, memberName);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.GROUP);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), groupName);
    }

    @Test
    public void testPutGroupSystemMeta() {
        String apiName = "putGroupSystemMeta";
        String domainName = "domain-name";
        String groupName = "group-name";
        String attribute = "attribute";
        GroupSystemMeta detail = new GroupSystemMeta();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/group/{groupName}/meta/system/{attribute}", domainName, groupName, attribute, detail);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.GROUP);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), groupName);
    }

    @Test
    public void testPutGroupMeta() {
        String apiName = "putGroupMeta";
        String domainName = "domain-name";
        String groupName = "group-name";
        String attribute = "attribute";
        GroupMeta detail = new GroupMeta();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/group/{groupName}/meta", domainName, groupName, detail);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.GROUP);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), groupName);
    }

    @Test
    public void testPutGroupMembershipDecision() {
        String apiName = "putGroupMembershipDecision";
        String domainName = "domain-name";
        String groupName = "group-name";
        String memberName = "member-name";
        GroupMembership membership = new GroupMembership();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/group/{groupName}/member/{memberName}/decision", domainName, groupName, memberName, membership);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.GROUP);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), groupName);
    }

    @Test
    public void testPutGroupReview() {
        String apiName = "putGroupReview";
        String domainName = "domain-name";
        String groupName = "group-name";
        Group group = new Group();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/group/{groupName}/review", domainName, groupName, group);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.GROUP);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), groupName);
    }

    @Test
    public void testPutPolicy() {
        String apiName = "putPolicy";
        String domainName = "domain-name";
        String policyName = "policy-name";
        Policy policy = new Policy();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/policy/{policyName}", domainName, policyName, policy);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.POLICY);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), policyName);
    }

    @Test
    public void testDeletePolicy() {
        String apiName = "deletePolicy";
        String domainName = "domain-name";
        String policyName = "policy-name";
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/policy/{policyName}", domainName, policyName);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.POLICY);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), policyName);
    }

    @Test
    public void testPutAssertion() {
        String apiName = "putAssertion";
        String domainName = "domain-name";
        String policyName = "policy-name";
        Assertion assertion = new Assertion();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/policy/{policyName}/assertion", domainName, policyName, assertion);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.POLICY);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), policyName);
    }

    @Test
    public void testPutAssertionPolicyVersion() {
        String apiName = "putAssertionPolicyVersion";
        String domainName = "domain-name";
        String policyName = "policy-name";
        String version = "version";
        Assertion assertion = new Assertion();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/policy/{policyName}/version/{version}/assertion", domainName, policyName, version, assertion);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.POLICY);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), policyName);
    }

    @Test
    public void testDeleteAssertion() {
        String apiName = "deleteAssertion";
        String domainName = "domain-name";
        String policyName = "policy-name";
        Long assertionId = 1L;
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/policy/{policyName}/assertion/{assertionId}", domainName, policyName, assertionId);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.POLICY);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), policyName);
    }

    @Test
    public void testDeleteAssertionPolicyVersion() {
        String apiName = "deleteAssertionPolicyVersion";
        String domainName = "domain-name";
        String policyName = "policy-name";
        String version = "version";
        Long assertionId = 1L;
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/policy/{policyName}/version/{version}/assertion/{assertionId}", domainName, policyName, version, assertionId);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.POLICY);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), policyName);
    }

    @Test
    public void testPutAssertionConditions() {
        String apiName = "putAssertionConditions";
        String domainName = "domain-name";
        String policyName = "policy-name";
        AssertionConditions assertionConditions = new AssertionConditions();
        Long assertionId = 1L;
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/policy/{policyName}/assertion/{assertionId}/conditions", domainName, policyName, assertionId, assertionConditions);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.POLICY);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), policyName);
    }

    @Test
    public void testPutAssertionCondition() {
        String apiName = "putAssertionCondition";
        String domainName = "domain-name";
        String policyName = "policy-name";
        AssertionCondition assertionCondition = new AssertionCondition();
        Long assertionId = 1L;
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/policy/{policyName}/assertion/{assertionId}/condition", domainName, policyName, assertionId, assertionCondition);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.POLICY);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), policyName);
    }

    @Test
    public void testDeleteAssertionConditions() {
        String apiName = "deleteAssertionConditions";
        String domainName = "domain-name";
        String policyName = "policy-name";
        Long assertionId = 1L;
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/policy/{policyName}/assertion/{assertionId}/conditions", domainName, policyName, assertionId);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.POLICY);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), policyName);
    }

    @Test
    public void testDeleteAssertionCondition() {
        String apiName = "deleteAssertionCondition";
        String domainName = "domain-name";
        String policyName = "policy-name";
        Integer conditionId = 1;
        Long assertionId = 1L;
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/policy/{policyName}/assertion/{assertionId}/condition/{conditionId}", domainName, policyName, assertionId, conditionId);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.POLICY);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), policyName);
    }

    @Test
    public void testPutPolicyVersion() {
        String apiName = "putPolicyVersion";
        String domainName = "domain-name";
        String policyName = "policy-name";
        PolicyOptions policyOptions = new PolicyOptions();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/policy/{policyName}/version/create", domainName, policyName, policyOptions);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.POLICY);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), policyName);
    }

    @Test
    public void testSetActivePolicyVersion() {
        String apiName = "setActivePolicyVersion";
        String domainName = "domain-name";
        String policyName = "policy-name";
        PolicyOptions policyOptions = new PolicyOptions();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/policy/{policyName}/version/active", domainName, policyName, policyOptions);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.POLICY);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), policyName);
    }

    @Test
    public void testDeletePolicyVersion() {
        String apiName = "deletePolicyVersion";
        String domainName = "domain-name";
        String policyName = "policy-name";
        String version = "version";
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/policy/{policyName}/version/{version}", domainName, policyName, version);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.POLICY);
        assertEquals(actual.getDomainName(), domainName);
        assertEquals(actual.getObjectName(), policyName);
    }

    @Test
    public void testPutServiceIdentity() {
        String apiName = "putServiceIdentity";
        String domain = "domain-name";
        String service = "service-name";
        ServiceIdentity detail = new ServiceIdentity();
        when(mockContext.getApiName()).thenReturn(apiName);
        zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}", domain, service, detail);

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
        zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}", domain, service);

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
        zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}/publickey/{id}", domain, service, id, publicKeyEntry);

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
        zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}/publickey/{id}", domain, service, id);

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
        zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}/meta/system/{attribute}", domain, service, attribute, detail);

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
        zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/tenancy/{service}", domain, service, detail);

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
        zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/tenancy/{service}", domain, service);

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
        zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}/tenant/{tenantDomain}", domain, service, tenantDomain, detail);

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
        zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}/tenant/{tenantDomain}", domain, service, tenantDomain);

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
        zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}/tenant/{tenantDomain}/resourceGroup/{resourceGroup}", domain, service, tenantDomain, resourceGroup, detail);

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
        zms.publishChangeEvent(mockContext, 200, "/domain/{domain}/service/{service}/tenant/{tenantDomain}/resourceGroup/{resourceGroup}", domain, service, tenantDomain, resourceGroup);

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
        zms.publishChangeEvent(mockContext, 200, "/domain/{tenantDomain}/provDomain/{provDomain}/provService/{provService}/resourceGroup/{resourceGroup}", tenantDomain, provDomain, provService, resourceGroup, detail);

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
        zms.publishChangeEvent(mockContext, 200, "/domain/{tenantDomain}/provDomain/{provDomain}/provService/{provService}/resourceGroup/{resourceGroup}", tenantDomain, provDomain, provService, resourceGroup);

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
        zms.publishChangeEvent(mockContext, 200, "/user/{name}", name);

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
        zms.publishChangeEvent(mockContext, 200, "/domain/{domainName}/member/{memberName}", domainName, memberName);

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
        zms.publishChangeEvent(mockContext, 200, "/domain/{name}/quota", name, quota);

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
        zms.publishChangeEvent(mockContext, 200, "/domain/{name}/quota", name);

        DomainChangeMessage actual = getActualDomainChangeMessage();
        assertEquals(actual.getApiName(), apiName);
        assertEquals(actual.getObjectType(), DomainChangeMessage.ObjectType.DOMAIN);
        assertEquals(actual.getObjectName(), "quota"); //TODO: what is expected result here?
    }
}
