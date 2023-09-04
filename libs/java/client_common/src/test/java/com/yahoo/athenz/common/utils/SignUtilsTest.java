package com.yahoo.athenz.common.utils;

import static org.testng.Assert.*;

import java.util.ArrayList;
import java.util.List;

import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.zts.PolicyData;
import com.yahoo.athenz.zts.SignedPolicyData;

public class SignUtilsTest {
    
    @Mock
    PolicyData mockPolicy;
    @Mock
    DomainData mockDomain;
    @Mock
    DomainPolicies mockPolicies;
    @Mock
    SignedPolicyData mockSignedPolicy;

    @BeforeMethod
    public void setUp(){
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testEmptyConstructor() {
        SignUtils signUtils = new SignUtils();
        assertNotNull(signUtils);
    }

    @Test
    public void testAsCanonicalStringPolicyData() {
        Mockito.when(mockPolicy.getPolicies()).thenReturn(null);
        
        String check = SignUtils.asCanonicalString(mockPolicy);
        assertNotNull(check);
        assertEquals(check,"{\"policies\":[]}");
    }
    
    @Test
    public void testAsCanonicalStringDomainData() {
        Mockito.when(mockDomain.getAuditEnabled()).thenReturn(null);
        Mockito.when(mockDomain.getEnabled()).thenReturn(null);
        Mockito.when(mockDomain.getRoles()).thenReturn(null);
        Mockito.when(mockDomain.getGroups()).thenReturn(null);
        Mockito.when(mockDomain.getServices()).thenReturn(null);
        Mockito.when(mockDomain.getMemberExpiryDays()).thenReturn(null);
        Mockito.when(mockDomain.getServiceExpiryDays()).thenReturn(null);
        Mockito.when(mockDomain.getTokenExpiryMins()).thenReturn(null);

        String check = SignUtils.asCanonicalString(mockDomain);
        assertNotNull(check);
        assertEquals(check,"{\"roleCertExpiryMins\":0,\"roles\":[],\"serviceCertExpiryMins\":0,\"services\":[],\"ypmId\":0}");
    }
    
    @Test
    public void testAsCanonicalStringDomainPolicies() {
        String check = SignUtils.asCanonicalString(mockPolicies);
        assertNotNull(check);
        assertEquals(check,"{\"policies\":[]}");
    }
    
    @Test
    public void testAsCanonicalStringSignedPolicyData() {
        Mockito.when(mockSignedPolicy.getPolicyData()).thenReturn(mockPolicy);
        
        String check = SignUtils.asCanonicalString(mockSignedPolicy);
        assertNotNull(check);
        assertEquals(check,"{\"policyData\":{\"policies\":[]}}");
    }
    
    @Test
    public void testAsStructPolicy() {
        List<Policy> policies = new ArrayList<>();
        Policy mPolicy = Mockito.mock(Policy.class);
        policies.add(mPolicy);
        
        List<Assertion> assertions = new ArrayList<>();
        Assertion mAssertion = Mockito.mock(Assertion.class);
        assertions.add(mAssertion);
        
        Mockito.when(mockPolicies.getPolicies()).thenReturn(policies);
        Mockito.when(mPolicy.getAssertions()).thenReturn(assertions);
        
        String check = SignUtils.asCanonicalString(mockPolicies);
        assertNotNull(check);
        assertEquals(check,"{\"policies\":[{\"assertions\":[{}]}]}");
        
        Mockito.when(mPolicy.getAssertions()).thenReturn(null);
        
        check = SignUtils.asCanonicalString(mockPolicies);
        assertNotNull(check);
        assertEquals(check,"{\"policies\":[{}]}");
    }
    
    @Test
    public void testAsStructZTSPolicy() {
        List<com.yahoo.athenz.zts.Policy> policies = new ArrayList<>();
        com.yahoo.athenz.zts.Policy mPolicy = Mockito.mock(com.yahoo.athenz.zts.Policy.class);
        policies.add(mPolicy);
        
        List<com.yahoo.athenz.zts.Assertion> assertions = new ArrayList<>();
        com.yahoo.athenz.zts.Assertion mAssertion = Mockito.mock(com.yahoo.athenz.zts.Assertion.class);
        assertions.add(mAssertion);
        
        Mockito.when(mockPolicy.getPolicies()).thenReturn(policies);
        Mockito.when(mPolicy.getAssertions()).thenReturn(assertions);
        
        String check = SignUtils.asCanonicalString(mockPolicy);
        assertNotNull(check);
        assertEquals(check,"{\"policies\":[{\"assertions\":[{}]}]}");
        
        Mockito.when(mPolicy.getAssertions()).thenReturn(null);
        
        check = SignUtils.asCanonicalString(mockPolicy);
        assertNotNull(check);
        assertEquals(check,"{\"policies\":[{}]}");
    }
    
    @Test
    public void testAsStructRoleService() {
        List<Role> roles = new ArrayList<>();
        Role mRole = Mockito.mock(Role.class);
        Mockito.when(mRole.getAuditEnabled()).thenReturn(null);
        Mockito.when(mRole.getSelfServe()).thenReturn(null);
        Mockito.when(mRole.getMemberExpiryDays()).thenReturn(null);
        Mockito.when(mRole.getServiceExpiryDays()).thenReturn(null);
        Mockito.when(mRole.getMemberReviewDays()).thenReturn(null);
        Mockito.when(mRole.getServiceReviewDays()).thenReturn(null);
        Mockito.when(mRole.getTokenExpiryMins()).thenReturn(null);
        Mockito.when(mRole.getGroupExpiryDays()).thenReturn(null);
        Mockito.when(mRole.getGroupReviewDays()).thenReturn(null);
        roles.add(mRole);
        
        List<String> items = new ArrayList<>();
        String item = "check_item";
        items.add(item);
        
        List<ServiceIdentity> services = new ArrayList<>();
        ServiceIdentity mService = Mockito.mock(ServiceIdentity.class);
        services.add(mService);
        
        List<PublicKeyEntry> publicKeys = new ArrayList<>();
        PublicKeyEntry mPublicKey = Mockito.mock(PublicKeyEntry.class);
        publicKeys.add(mPublicKey);
        
        SignedPolicies signedPolicies = Mockito.mock(SignedPolicies.class);

        Mockito.when(mockDomain.getAuditEnabled()).thenReturn(null);
        Mockito.when(mockDomain.getEnabled()).thenReturn(null);
        Mockito.when(mockDomain.getAccount()).thenReturn("chk_string");
        Mockito.when(mockDomain.getGroups()).thenReturn(null);
        Mockito.when(mockDomain.getRoles()).thenReturn(roles);
        Mockito.when(mRole.getMembers()).thenReturn(items);
        Mockito.when(mockDomain.getServices()).thenReturn(services);
        Mockito.when(mService.getHosts()).thenReturn(null);
        Mockito.when(mService.getPublicKeys()).thenReturn(publicKeys);
        Mockito.when(mockDomain.getPolicies()).thenReturn(signedPolicies);
        Mockito.when(signedPolicies.getContents()).thenReturn(mockPolicies);
        Mockito.when(mockDomain.getMemberExpiryDays()).thenReturn(30);
        Mockito.when(mockDomain.getServiceExpiryDays()).thenReturn(40);
        Mockito.when(mockDomain.getTokenExpiryMins()).thenReturn(450);
        
        String check = SignUtils.asCanonicalString(mockDomain);
        assertNotNull(check);
        assertEquals(check, "{\"account\":\"chk_string\",\"memberExpiryDays\":30,\"policies\""
                +":{\"contents\":{\"policies\":[]}},\"roleCertExpiryMins\":0,\"roles\":[{\"certExpiryMins\":0,\"members\":[\"check_item\"],"
                +"\"roleMembers\":[]}],\"serviceCertExpiryMins\":0,\"serviceExpiryDays\":40,\"services\":[{\"publicKeys\":[{}]}],"
                +"\"tokenExpiryMins\":450,\"ypmId\":0}");
        
        Mockito.when(mService.getPublicKeys()).thenReturn(null);
        Mockito.when(mockDomain.getMemberExpiryDays()).thenReturn(null);
        Mockito.when(mockDomain.getServiceExpiryDays()).thenReturn(null);

        check = SignUtils.asCanonicalString(mockDomain);
        assertNotNull(check);
        assertEquals(check,"{\"account\":\"chk_string\",\"policies\":{\"contents\":{\"policies\":[]}},"
                +"\"roleCertExpiryMins\":0,\"roles\":[{\"certExpiryMins\":0,\"members\":[\"check_item\"],\"roleMembers\":[]}],"
                +"\"serviceCertExpiryMins\":0,\"services\""
                +":[{\"publicKeys\":[]}],\"tokenExpiryMins\":450,\"ypmId\":0}");
    }

    @Test
    public void testAsStructRole() {

        List<RoleMember> roleMembers1 = new ArrayList<>();
        Role role1 = new Role().setName("role1").setRoleMembers(roleMembers1)
                .setMemberExpiryDays(30).setTokenExpiryMins(450)
                .setCertExpiryMins(300).setServiceExpiryDays(40)
                .setGroupExpiryDays(70).setGroupReviewDays(80);

        List<RoleMember> roleMembers2 = new ArrayList<>();
        roleMembers2.add(new RoleMember().setMemberName("user.joe").setExpiration(Timestamp.fromMillis(0)));
        roleMembers2.add(new RoleMember().setMemberName("user.jane").setExpiration(Timestamp.fromMillis(0)));
        Role role2 = new Role().setName("role2").setRoleMembers(roleMembers2).setSignAlgorithm("ec");

        List<Role> roles = new ArrayList<>();
        roles.add(role1);
        roles.add(role2);
        roles.add(new Role().setName("role3"));
        DomainData data = new DomainData().setRoles(roles).setYpmId(100)
                .setEnabled(Boolean.TRUE);

        final String check = SignUtils.asCanonicalString(data);
        final String expected = "{\"enabled\":true,\"roles\":[{\"certExpiryMins\":300,"
            +"\"memberExpiryDays\":30,\"name\":\"role1\","
            +"\"roleMembers\":[],\"serviceExpiryDays\":40,\"tokenExpiryMins\":450},"
            +"{\"name\":\"role2\",\"roleMembers\":[{\"expiration\":\"1970-01-01T00:00:00.000Z\","
            +"\"memberName\":\"user.joe\"},{\"expiration\":\"1970-01-01T00:00:00.000Z\","
            +"\"memberName\":\"user.jane\"}],\"signAlgorithm\":\"ec\"},{\"name\":\"role3\"}],\"services\":[],\"ypmId\":100}";
        assertEquals(check, expected);
    }

    @Test
    public void testAsCannonicalStringObject() {

        Struct struct = new Struct();
        struct.append("long", 100L);
        struct.append("float", 100f);

        final String check = SignUtils.asCanonicalString(struct);
        final String expected = "{\"float\":100.0,\"long\":100}";
        assertEquals(check, expected);
    }

    @Test
    public void testAsStructRoleDomainWithAuditEnabled() {

        List<RoleMember> roleMembers1 = new ArrayList<>();
        Role role1 = new Role().setName("role1").setRoleMembers(roleMembers1).setAuditEnabled(true);

        List<RoleMember> roleMembers2 = new ArrayList<>();
        roleMembers2.add(new RoleMember().setMemberName("user.joe").setExpiration(Timestamp.fromMillis(0)));
        roleMembers2.add(new RoleMember().setMemberName("user.jane").setExpiration(Timestamp.fromMillis(0)));
        Role role2 = new Role().setName("role2").setRoleMembers(roleMembers2);

        List<Role> roles = new ArrayList<>();
        roles.add(role1);
        roles.add(role2);
        roles.add(new Role().setName("role3"));
        DomainData data = new DomainData().setRoles(roles).setYpmId(100)
                .setEnabled(Boolean.TRUE).setAuditEnabled(true)
                .setRoleCertExpiryMins(100).setServiceCertExpiryMins(200)
                .setTokenExpiryMins(300).setSignAlgorithm("rsa");

        final String check = SignUtils.asCanonicalString(data);
        final String expected = "{\"auditEnabled\":true,\"enabled\":true,\"roleCertExpiryMins\":100,"
                +"\"roles\":[{\"auditEnabled\":true,\"name\":\"role1\",\"roleMembers\":[]},"
                +"{\"name\":\"role2\",\"roleMembers\":[{\"expiration\":\"1970-01-01T00:00:00.000Z\","
                +"\"memberName\":\"user.joe\"},{\"expiration\":\"1970-01-01T00:00:00.000Z\","
                +"\"memberName\":\"user.jane\"}]},{\"name\":\"role3\"}],\"serviceCertExpiryMins\":200,"
                +"\"services\":[],\"signAlgorithm\":\"rsa\",\"tokenExpiryMins\":300,\"ypmId\":100}";
        assertEquals(check, expected);
    }

    @Test
    public void testAsStructGroupService() {
        List<Group> groups = new ArrayList<>();
        Group mGroup = Mockito.mock(Group.class);
        Mockito.when(mGroup.getAuditEnabled()).thenReturn(null);
        Mockito.when(mGroup.getSelfServe()).thenReturn(null);
        Mockito.when(mGroup.getMemberExpiryDays()).thenReturn(null);
        Mockito.when(mGroup.getServiceExpiryDays()).thenReturn(null);
        groups.add(mGroup);

        List<GroupMember> groupMembers = new ArrayList<>();
        GroupMember groupMember = new GroupMember();
        groupMember.setMemberName("groupMemberName1");
        groupMembers.add(groupMember);

        List<ServiceIdentity> services = new ArrayList<>();
        ServiceIdentity mService = Mockito.mock(ServiceIdentity.class);
        services.add(mService);

        List<PublicKeyEntry> publicKeys = new ArrayList<>();
        PublicKeyEntry mPublicKey = Mockito.mock(PublicKeyEntry.class);
        publicKeys.add(mPublicKey);

        SignedPolicies signedPolicies = Mockito.mock(SignedPolicies.class);

        Mockito.when(mockDomain.getAuditEnabled()).thenReturn(null);
        Mockito.when(mockDomain.getEnabled()).thenReturn(null);
        Mockito.when(mockDomain.getAccount()).thenReturn("chk_string");
        Mockito.when(mockDomain.getGroups()).thenReturn(groups);
        Mockito.when(mockDomain.getRoles()).thenReturn(null);
        Mockito.when(mGroup.getGroupMembers()).thenReturn(groupMembers);
        Mockito.when(mockDomain.getServices()).thenReturn(services);
        Mockito.when(mService.getHosts()).thenReturn(null);
        Mockito.when(mService.getPublicKeys()).thenReturn(publicKeys);
        Mockito.when(mockDomain.getPolicies()).thenReturn(signedPolicies);
        Mockito.when(signedPolicies.getContents()).thenReturn(mockPolicies);
        Mockito.when(mockDomain.getMemberExpiryDays()).thenReturn(30);
        Mockito.when(mockDomain.getServiceExpiryDays()).thenReturn(40);
        Mockito.when(mockDomain.getTokenExpiryMins()).thenReturn(450);

        String check = SignUtils.asCanonicalString(mockDomain);
        assertNotNull(check);
        assertEquals(check, "{\"account\":\"chk_string\",\"groups\":[{\"groupMembers\":[{\"memberName\":\"groupMemberName1\"}]," +
                "\"reviewEnabled\":false}],\"memberExpiryDays\":30,\"policies\":{\"contents\":{\"policies\":[]}}," +
                "\"roleCertExpiryMins\":0,\"roles\":[],\"serviceCertExpiryMins\":0,\"serviceExpiryDays\":40,\"services\":[{\"publicKeys\":[{}]}]," +
                "\"tokenExpiryMins\":450,\"ypmId\":0}");

        Mockito.when(mService.getPublicKeys()).thenReturn(null);
        Mockito.when(mockDomain.getMemberExpiryDays()).thenReturn(null);
        Mockito.when(mockDomain.getServiceExpiryDays()).thenReturn(null);

        check = SignUtils.asCanonicalString(mockDomain);
        assertNotNull(check);
        assertEquals(check,"{\"account\":\"chk_string\",\"groups\":[{\"groupMembers\":[{\"memberName\":\"groupMemberName1\"}]," +
                "\"reviewEnabled\":false}],\"policies\":{\"contents\":{\"policies\":[]}},\"roleCertExpiryMins\":0,\"roles\":[]," +
                "\"serviceCertExpiryMins\":0,\"services\":[{\"publicKeys\":[]}],\"tokenExpiryMins\":450,\"ypmId\":0}");
    }


    @Test
    public void testAsStructGroup() {

        List<GroupMember> groupMembers1 = new ArrayList<>();
        Group group1 = new Group().setName("group1").setGroupMembers(groupMembers1)
                .setMemberExpiryDays(30).setServiceExpiryDays(40)
                .setReviewEnabled(true).setSelfServe(true).setAuditEnabled(true);

        List<GroupMember> groupMembers2 = new ArrayList<>();
        groupMembers2.add(new GroupMember().setMemberName("user.joe").setExpiration(Timestamp.fromMillis(0)));
        groupMembers2.add(new GroupMember().setMemberName("user.jane").setExpiration(Timestamp.fromMillis(0)));
        Group group2 = new Group().setName("group2").setGroupMembers(groupMembers2);

        List<Group> groups = new ArrayList<>();
        groups.add(group1);
        groups.add(group2);
        groups.add(new Group().setName("group3"));
        DomainData data = new DomainData().setGroups(groups).setYpmId(100)
                .setEnabled(Boolean.TRUE);

        final String check = SignUtils.asCanonicalString(data);
        final String expected = "{\"enabled\":true,\"groups\":[{\"auditEnabled\":true,"
                +"\"groupMembers\":[],\"memberExpiryDays\":30,\"name\":\"group1\",\"reviewEnabled\":true,\"selfServe\":true,\"serviceExpiryDays\":40},"
                +"{\"groupMembers\":[{\"expiration\":\"1970-01-01T00:00:00.000Z\","
                +"\"memberName\":\"user.joe\"},{\"expiration\":\"1970-01-01T00:00:00.000Z\","
                +"\"memberName\":\"user.jane\"}],\"name\":\"group2\"},{\"name\":\"group3\"}],"
                +"\"roles\":[],\"services\":[],\"ypmId\":100}";
        assertEquals(check, expected);
    }
}
