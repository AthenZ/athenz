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
package com.yahoo.athenz.auth.impl;

import static org.mockito.Mockito.*;
import static org.testng.Assert.*;
import com.yahoo.athenz.auth.Principal;

import org.testng.annotations.Test;

import javax.naming.AuthenticationException;
import javax.naming.AuthenticationNotSupportedException;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;

public class LDAPAuthorityTest {

    private LDAPAuthority ldapAuthority;
    private Principal principal;
    private StringBuilder errMsg;
    private final String baseDNProp = LDAPAuthority.ATHENZ_PROP_LDAP_BASE_DN;
    private final String portNumberProp = LDAPAuthority.ATHENZ_PROP_LDAP_PORT;
    private final String hostnameProp = LDAPAuthority.ATHENZ_PROP_HOSTNAME;
    private String oldBaseDN, oldPortNumber, oldHostname;

    @Test
    public void testLDAPAuthorityCredsInvalidFormat() {
        ldapAuthority = new LDAPAuthority();
        setProperties();
        ldapAuthority.initialize();
        errMsg = new StringBuilder();
        //the credentials doesn't start with Basic and hence is invalid and should return null
        principal = ldapAuthority.authenticate("dGVzdHVzZXI6dGVzdHB3ZA==", "", "", errMsg);
        assertNull(principal);
        //set the value of baseDN and portNumber to original values
        resetProperties();
    }

    @Test
    public void testLDAPAuthorityPropertyNotSet() {

        ldapAuthority = new LDAPAuthority();
        errMsg = new StringBuilder();
        setProperties();
        System.clearProperty(portNumberProp);
        ldapAuthority.initialize();
        //port number is null and hence should should return null
        principal = ldapAuthority.authenticate("Basic dGVzdHVzZXI6dGVzdHB3ZA==", "", "", errMsg);
        assertNull(principal);
        resetProperties();

        setProperties();
        System.clearProperty(baseDNProp);
        ldapAuthority.initialize();
        //base dn is null and hence principal should be null
        principal = ldapAuthority.authenticate("Basic dGVzdHVzZXI6dGVzdHB3ZA==", "", "",errMsg);
        assertNull(principal);
        resetProperties();

        setProperties();
        System.clearProperty(hostnameProp);
        ldapAuthority.initialize();
        //hostname is null and hence principal should be null
        principal = ldapAuthority.authenticate("Basic dGVzdHVzZXI6dGVzdHB3ZA==", "", "",errMsg);
        assertNull(principal);
    }

    @Test
    public void testAllowAuthorization() {
        ldapAuthority = new LDAPAuthority();
        ldapAuthority.initialize();
        assertFalse(ldapAuthority.allowAuthorization());
    }

    @Test
    public void testGetID() {
        ldapAuthority = new LDAPAuthority();
        ldapAuthority.initialize();
        assertEquals("Auth-LDAP", ldapAuthority.getID());
    }

    @Test
    public void testAuthenticationChallenge() {
        ldapAuthority = new LDAPAuthority();
        ldapAuthority.initialize();
        assertEquals(ldapAuthority.getAuthenticateChallenge(), "LDAPAuthentication realm=\"athenz\"");
    }

    @Test
    public void testGetDomain() {
        ldapAuthority = new LDAPAuthority();
        ldapAuthority.initialize();
        assertEquals(ldapAuthority.getDomain(),"user");
    }

    @Test
    public void testLdapAuthorityBase64Decode() {
        setProperties();
        ldapAuthority = new LDAPAuthority();
        ldapAuthority.initialize();
        errMsg = new StringBuilder();
        principal = ldapAuthority.authenticate("Basic !@#$%", "", "",  errMsg);
        assertNull(principal);
        resetProperties();
    }

    @Test
    public void testHeader() {
        ldapAuthority = new LDAPAuthority();
        assertEquals(ldapAuthority.getHeader(), "Authorization");
    }

    @Test
    public void testLDAPAuthorityConnection() throws NamingException {

        setProperties();
        ldapAuthority = new LDAPAuthority();
        ldapAuthority.initialize();
        errMsg = new StringBuilder();
        // naming exception
        principal = ldapAuthority.authenticate("Basic dGVzdHVzZXI6dGVzdHB3ZA==", "", "", errMsg);
        assertNull(principal);

        //authentication exception - wrong username password combination
        errMsg = new StringBuilder();
        ldapAuthority = mock(LDAPAuthority.class);
        doCallRealMethod().when(ldapAuthority).initialize();
        ldapAuthority.initialize();
        when(ldapAuthority.getDirContext("cn=testuser,dc=example,dc=com", "wrongpwd")).thenThrow(new AuthenticationException());
        when(ldapAuthority.authenticate("Basic dGVzdHVzZXI6d3Jvbmdwd2Q=", "", "", errMsg)).thenCallRealMethod();
        principal = ldapAuthority.authenticate("Basic dGVzdHVzZXI6d3Jvbmdwd2Q=", "", "", errMsg);
        assertNull(principal);

        //authentication not supported exception
        errMsg = new StringBuilder();
        ldapAuthority = mock(LDAPAuthority.class);
        doCallRealMethod().when(ldapAuthority).initialize();
        ldapAuthority.initialize();
        when(ldapAuthority.getDirContext("cn=testuser,dc=example,dc=com", "wrongpwd")).thenThrow(new AuthenticationNotSupportedException());
        when(ldapAuthority.authenticate("Basic dGVzdHVzZXI6d3Jvbmdwd2Q=", "", "", errMsg)).thenCallRealMethod();
        principal = ldapAuthority.authenticate("Basic dGVzdHVzZXI6d3Jvbmdwd2Q=", "", "", errMsg);
        assertNull(principal);

        //success case
        errMsg = new StringBuilder();
        ldapAuthority = mock(LDAPAuthority.class);
        doCallRealMethod().when(ldapAuthority).initialize();
        doCallRealMethod().when(ldapAuthority).getDomain();
        doCallRealMethod().when(ldapAuthority).getSimplePrincipal("Basic dGVzdHVzZXI6d3Jvbmdwd2Q=", "testuser");
        ldapAuthority.initialize();

        when(ldapAuthority.getDirContext("cn=testuser,dc=example,dc=com", "wrongpwd")).thenReturn(new InitialDirContext());
        when(ldapAuthority.authenticate("Basic dGVzdHVzZXI6d3Jvbmdwd2Q=", "", "", errMsg)).thenCallRealMethod();
        when(ldapAuthority.authenticate("Basic dGVzdHVzZXIK", "", "", errMsg)).thenCallRealMethod();
        principal = ldapAuthority.authenticate("Basic dGVzdHVzZXI6d3Jvbmdwd2Q=", "", "", errMsg);
        assertNotNull(principal);
        assertEquals(principal.getName(), "testuser");
        assertEquals(principal.getDomain(), "user");
        assertEquals(principal.getCredentials(), "Basic dGVzdHVzZXI6d3Jvbmdwd2Q=");
        assertEquals(principal.getUnsignedCredentials(), "testuser");

        // pass credentials without password component

        principal = ldapAuthority.authenticate("Basic dGVzdHVzZXIK", "", "", errMsg);
        assertNull(principal);

        //null principal s returned from function
        System.setProperty(baseDNProp,"dc=example,dc=com");
        System.setProperty(portNumberProp,"389");
        errMsg = new StringBuilder();
        ldapAuthority = mock(LDAPAuthority.class);
        doCallRealMethod().when(ldapAuthority).initialize();
        doCallRealMethod().when(ldapAuthority).getDomain();
        when(ldapAuthority.getSimplePrincipal("Basic dGVzdHVzZXI6d3Jvbmdwd2Q=", "testuser")).thenReturn(null);
        ldapAuthority.initialize();
        when(ldapAuthority.getDirContext("cn=testuser,dc=example,dc=com", "wrongpwd")).thenReturn(new InitialDirContext());
        when(ldapAuthority.authenticate("Basic dGVzdHVzZXI6d3Jvbmdwd2Q=", "", "", errMsg)).thenCallRealMethod();
        principal = ldapAuthority.authenticate("Basic dGVzdHVzZXI6d3Jvbmdwd2Q=", "", "", errMsg);
        assertNull(principal);

        resetProperties();
    }

    public void setProperties() {
        oldBaseDN = System.setProperty(baseDNProp,"dc=example,dc=com");
        oldPortNumber = System.setProperty(portNumberProp,"389");
        oldHostname = System.setProperty(hostnameProp, "localhost");
    }

    public void resetProperties() {
        if (oldBaseDN == null) {
            System.clearProperty(baseDNProp);
        } else {
            System.setProperty(baseDNProp, oldBaseDN);
        }

        if (oldPortNumber == null) {
            System.clearProperty(portNumberProp);
        } else {
            System.setProperty(portNumberProp, oldPortNumber);
        }

        if (oldHostname == null) {
            System.clearProperty(hostnameProp);
        } else {
            System.setProperty(hostnameProp, oldHostname);
        }
    }
}
