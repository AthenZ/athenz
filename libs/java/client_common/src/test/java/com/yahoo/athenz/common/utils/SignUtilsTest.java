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
        MockitoAnnotations.initMocks(this);
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
        Mockito.when(mockDomain.getEnabled()).thenReturn(null);
        Mockito.when(mockDomain.getRoles()).thenReturn(null);
        Mockito.when(mockDomain.getServices()).thenReturn(null);
        
        String check = SignUtils.asCanonicalString(mockDomain);
        assertNotNull(check);
        assertEquals(check,"{\"roles\":[],\"services\":[],\"ypmId\":0}");
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
        
        Mockito.when(mockDomain.getEnabled()).thenReturn(null);
        Mockito.when(mockDomain.getAccount()).thenReturn("chk_string");
        Mockito.when(mockDomain.getRoles()).thenReturn(roles);
        Mockito.when(mRole.getMembers()).thenReturn(items);
        Mockito.when(mockDomain.getServices()).thenReturn(services);
        Mockito.when(mService.getHosts()).thenReturn(null);
        Mockito.when(mService.getPublicKeys()).thenReturn(publicKeys);
        Mockito.when(mockDomain.getPolicies()).thenReturn(signedPolicies);
        Mockito.when(signedPolicies.getContents()).thenReturn(mockPolicies);
        
        String check = SignUtils.asCanonicalString(mockDomain);
        assertNotNull(check);
        assertEquals(check,"{\"account\":\"chk_string\",\"policies\":{\"contents\":{\"policies\":[]}},\"roles\":[{\"members\":[\"check_item\"],\"roleMembers\":[]}],\"services\":[{\"publicKeys\":[{}]}],\"ypmId\":0}");
        
        Mockito.when(mService.getPublicKeys()).thenReturn(null);
        
        check = SignUtils.asCanonicalString(mockDomain);
        assertNotNull(check);
        assertEquals(check,"{\"account\":\"chk_string\",\"policies\":{\"contents\":{\"policies\":[]}},\"roles\":[{\"members\":[\"check_item\"],\"roleMembers\":[]}],\"services\":[{\"publicKeys\":[]}],\"ypmId\":0}");
    }

    @Test
    public void testAsStructRole() {

        List<RoleMember> roleMembers1 = new ArrayList<>();
        Role role1 = new Role().setName("role1").setRoleMembers(roleMembers1);

        List<RoleMember> roleMembers2 = new ArrayList<>();
        roleMembers2.add(new RoleMember().setMemberName("user.joe").setExpiration(Timestamp.fromMillis(0)));
        roleMembers2.add(new RoleMember().setMemberName("user.jane").setExpiration(Timestamp.fromMillis(0)));
        Role role2 = new Role().setName("role2").setRoleMembers(roleMembers2);

        List<Role> roles = new ArrayList<>();
        roles.add(role1);
        roles.add(role2);
        roles.add(new Role().setName("role3"));
        DomainData data = new DomainData().setRoles(roles).setYpmId(100)
                .setEnabled(Boolean.TRUE);

        final String check = SignUtils.asCanonicalString(data);
        final String expected = "{\"enabled\":true,\"roles\":[{\"name\":\"role1\",\"roleMembers\":[]},"
            +"{\"name\":\"role2\",\"roleMembers\":[{\"expiration\":\"1970-01-01T00:00:00.000Z\","
            +"\"memberName\":\"user.joe\"},{\"expiration\":\"1970-01-01T00:00:00.000Z\","
            +"\"memberName\":\"user.jane\"}]},{\"name\":\"role3\"}],\"services\":[],\"ypmId\":100}";
        assertEquals(check, expected);
    }

    @Test
    public void testAsCannonicalStringObject() {

        Struct struct = new Struct();
        struct.append("long", Long.valueOf(100));
        struct.append("float", Float.valueOf(100f));

        final String check = SignUtils.asCanonicalString(struct);
        final String expected = "{\"float\":100.0,\"long\":100}";
        assertEquals(check, expected);
    }
}
