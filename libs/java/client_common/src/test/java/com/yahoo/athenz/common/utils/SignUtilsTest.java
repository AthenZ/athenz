package com.yahoo.athenz.common.utils;

import static org.testng.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.DomainPolicies;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.PublicKeyEntry;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.ServiceIdentity;
import com.yahoo.athenz.zms.SignedPolicies;
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
    
    SignUtils chk_utils = new SignUtils();
    
    @BeforeMethod
    public void setUp(){
        MockitoAnnotations.initMocks(this);
    }
    
    @Test
    public void testAsCanonicalStringPolicyData() {     
        Mockito.when(mockPolicy.getPolicies()).thenReturn(null);
        
        String check = SignUtils.asCanonicalString(mockPolicy);
        assertNotNull(check);
        assertEquals(check,"{\"domain\":}");
    }
    
    @Test
    public void testAsCanonicalStringDomainData() {     
        Mockito.when(mockDomain.getRoles()).thenReturn(null);
        Mockito.when(mockDomain.getServices()).thenReturn(null);
        
        String check = SignUtils.asCanonicalString(mockDomain);
        assertNotNull(check);
        assertEquals(check,"{\"modified\":,\"ypmId\":\"0\"}");
    }
    
    @Test
    public void testAsCanonicalStringDomainPolicies() {
        String check = SignUtils.asCanonicalString(mockPolicies);
        assertNotNull(check);
        assertEquals(check,"{\"domain\":}");
    }
    
    @Test
    public void testAsCanonicalStringSignedPolicyData() {
        Mockito.when(mockSignedPolicy.getPolicyData()).thenReturn(mockPolicy);
        
        String check = SignUtils.asCanonicalString(mockSignedPolicy);
        assertNotNull(check);
        assertEquals(check,"{\"expires\":,\"modified\":,\"policyData\":{\"domain\":},\"zmsKeyId\":,\"zmsSignature\":}");
    }
    
    @Test
    public void testAsStructPolicy() {
        List<Policy> policies = new ArrayList<Policy>();
        Policy mPolicy = Mockito.mock(Policy.class);
        policies.add(mPolicy);
        
        List<Assertion> assertions = new ArrayList<Assertion>();
        Assertion mAssertion = Mockito.mock(Assertion.class);
        assertions.add(mAssertion);
        
        Mockito.when(mockPolicies.getPolicies()).thenReturn(policies);
        Mockito.when(mPolicy.getAssertions()).thenReturn(assertions);
        
        String check = SignUtils.asCanonicalString(mockPolicies);
        assertNotNull(check);
        assertEquals(check,"{\"domain\":,\"policies\":[{\"assertions\":[{\"action\":,\"resource\":,\"role\":}],\"modified\":,\"name\":}]}");
        
        Mockito.when(mPolicy.getAssertions()).thenReturn(null);
        
        check = SignUtils.asCanonicalString(mockPolicies);
        assertNotNull(check);
        assertEquals(check,"{\"domain\":,\"policies\":[{\"modified\":,\"name\":}]}");
    }
    
    @Test
    public void testAsStructZTSPolicy() {
        List<com.yahoo.athenz.zts.Policy> policies = new ArrayList<com.yahoo.athenz.zts.Policy>();
        com.yahoo.athenz.zts.Policy mPolicy = Mockito.mock(com.yahoo.athenz.zts.Policy.class);
        policies.add(mPolicy);
        
        List<com.yahoo.athenz.zts.Assertion> assertions = new ArrayList<com.yahoo.athenz.zts.Assertion>();
        com.yahoo.athenz.zts.Assertion mAssertion = Mockito.mock(com.yahoo.athenz.zts.Assertion.class);
        assertions.add(mAssertion);
        
        Mockito.when(mockPolicy.getPolicies()).thenReturn(policies);
        Mockito.when(mPolicy.getAssertions()).thenReturn(assertions);
        
        String check = SignUtils.asCanonicalString(mockPolicy);
        assertNotNull(check);
        assertEquals(check,"{\"domain\":,\"policies\":[{\"assertions\":[{\"action\":,\"resource\":,\"role\":}],\"modified\":,\"name\":}]}");
        
        Mockito.when(mPolicy.getAssertions()).thenReturn(null);
        
        check = SignUtils.asCanonicalString(mockPolicy);
        assertNotNull(check);
        assertEquals(check,"{\"domain\":,\"policies\":[{\"modified\":,\"name\":}]}");
    }
    
    @Test
    public void testAsStructRoleService() {
        List<Role> roles = new ArrayList<Role>();
        Role mRole = Mockito.mock(Role.class);
        roles.add(mRole);
        
        List<String> items = new ArrayList<String>();
        String item = "check_item";
        items.add(item);
        
        List<ServiceIdentity> services = new ArrayList<ServiceIdentity >();
        ServiceIdentity mService = Mockito.mock(ServiceIdentity.class);
        services.add(mService);
        
        List<PublicKeyEntry> publicKeys = new ArrayList<PublicKeyEntry>();
        PublicKeyEntry mPublicKey = Mockito.mock(PublicKeyEntry.class);
        publicKeys.add(mPublicKey);
        
        SignedPolicies signedPolicies = Mockito.mock(SignedPolicies.class);
        
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
        assertEquals(check,"{\"account\":\"chk_string\",\"modified\":,\"policies\":{\"contents\":{\"domain\":}},\"roles\":[{\"members\":[\"check_item\"],\"modified\":,\"name\":}],\"services\":[{\"modified\":,\"name\":,\"publicKeys\":[{\"id\":,\"key\":}]}],\"ypmId\":\"0\"}");
        
        Mockito.when(mService.getPublicKeys()).thenReturn(null);
        
        check = SignUtils.asCanonicalString(mockDomain);
        assertNotNull(check);
        assertEquals(check,"{\"account\":\"chk_string\",\"modified\":,\"policies\":{\"contents\":{\"domain\":}},\"roles\":[{\"members\":[\"check_item\"],\"modified\":,\"name\":}],\"services\":[{\"modified\":,\"name\":}],\"ypmId\":\"0\"}");
    }
}
