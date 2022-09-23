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

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import org.jvnet.libpam.PAM;
import org.jvnet.libpam.PAMException;
import org.jvnet.libpam.UnixUser;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.testng.Assert.*;

public class UserAuthorityTest {

    @Test
    public void testUserAuthority() throws PAMException {
        PAM pam = Mockito.mock(PAM.class);
        UnixUser user = Mockito.mock(UnixUser.class);
        Mockito.when(pam.authenticate("testuser", "testpwd")).thenReturn(user);
        UserAuthority userAuthority = new UserAuthority();
        userAuthority.setPAM(pam);
        String expectedDomain = "user";
        assertEquals(userAuthority.getDomain(), expectedDomain);
        String expectedHeader = "Authorization";
        assertEquals(userAuthority.getHeader(), expectedHeader);
        assertTrue(userAuthority.isValidUser("user1"));

        StringBuilder errMsg = new StringBuilder();
        String testToken = "Basic dGVzdHVzZXI6dGVzdHB3ZA==";
        Principal principal = userAuthority.authenticate(testToken, "10.72.118.45", "GET", errMsg);
        assertNotNull(principal);

        assertEquals(principal.getName(), "testuser");
        assertEquals(principal.getDomain(), expectedDomain);
        assertEquals(principal.getCredentials(), testToken);
        assertEquals(principal.getUnsignedCredentials(), "testuser");

        assertNotNull(principal.getAuthority());
        assertEquals(principal.getCredentials(), testToken);

        assertTrue(userAuthority.isValidUser("user1"));

        // authenticate user without password which should fail

        principal = userAuthority.authenticate("Basic dGVzdHVzZXIK", "10.72.118.45", "GET", errMsg);
        assertNull(principal);
    }

    @Test
    public void testGetPAM() throws PAMException {
        UserAuthority userAuthority = new UserAuthority();
        assertNotNull(userAuthority.getPAM());
    }

    @Test
    public void testGetID() {
        UserAuthority authority = new UserAuthority();
        authority.initialize();
        assertEquals("Auth-UNIX", authority.getID());
    }

    @Test
    public void testUserAuthorityAuthenticateException() throws PAMException {
        PAM pam = Mockito.mock(PAM.class);
        UserAuthority userAuthority = new UserAuthority();
        userAuthority.setPAM(pam);
        Mockito.when(pam.authenticate("testuser", "testpwd")).thenThrow(RuntimeException.class);
        Principal principal = userAuthority.authenticate("Basic dGVzdHVzZXI6dGVždšB3ZA==", "10.72.118.45", "GET", null);
        assertNull(principal);

        principal = userAuthority.authenticate("Basic dGVzdHVzZXI6dGVzdHB3ZA==", "10.72.118.45", "GET", null);
        assertNull(principal);
    }

    @Test
    public void testNullSimplePrincipal() throws PAMException {
        PAM pam = Mockito.mock(PAM.class);
        UnixUser user = Mockito.mock(UnixUser.class);
        Mockito.when(pam.authenticate("testuser", "testpwd")).thenReturn(user);
        UserAuthority authority = new UserAuthority();
        UserAuthority userAuthority = Mockito.spy(authority);
        doReturn(null).when(userAuthority).getSimplePrincipal(anyString(), anyString(), anyLong());
        userAuthority.setPAM(pam);
        String expectedDomain = "user";
        assertEquals(userAuthority.getDomain(), expectedDomain);
        String expectedHeader = "Authorization";
        assertEquals(userAuthority.getHeader(), expectedHeader);
        assertTrue(userAuthority.isValidUser("user1"));

        StringBuilder errMsg = new StringBuilder();
        String testToken = "Basic dGVzdHVzZXI6dGVzdHB3ZA==";
        Principal principal = userAuthority.authenticate(testToken, "10.72.118.45", "GET", errMsg);
        assertNull(principal);
    }

    @Test
    public void testUserAuthorityInvalidFormat() {
        PAM pam = Mockito.mock(PAM.class);
        UserAuthority userAuthority = new UserAuthority();
        userAuthority.setPAM(pam);
        StringBuilder errMsg = new StringBuilder();
        Principal principal = userAuthority.authenticate("dGVzdHVzZXI6dGVzdHB3ZA==", "10.72.118.45", "GET", errMsg);
        assertNull(principal);
    }

    @Test
    public void testAllowAuthorization() {
        PAM pam = Mockito.mock(PAM.class);
        UserAuthority userAuthority = new UserAuthority();
        userAuthority.setPAM(pam);

        assertFalse(userAuthority.allowAuthorization());
    }

    @Test
    public void testAuthenticateException() throws PAMException {
        PAM pam = Mockito.mock(PAM.class);
        UserAuthority userAuthority = new UserAuthority();
        userAuthority.setPAM(pam);
        Mockito.when(pam.authenticate("testuser", "testpwd")).thenReturn(null);
        Principal principal = userAuthority.authenticate("Basic dGVzdHVzZXI6dGVzdHB3ZA==", "10.72.118.45", "GET", null);
        assertNull(principal);

        principal = userAuthority.authenticate("Basic ", "10.72.118.45", "GET", null);
        assertNull(principal);
    }

    @Test
    public void testGetAuthenticateChallenge() {
        UserAuthority userAuthority = new UserAuthority();
        assertEquals(userAuthority.getAuthenticateChallenge(), "Basic realm=\"athenz\"");
    }

    @Test
    public void testIsValidUser() {

        Authority userAuthority = new Authority() {

            @Override
            public void initialize() {
            }

            @Override
            public String getDomain() {
                return null;
            }

            @Override
            public String getHeader() {
                return null;
            }

            @Override
            public Principal authenticate(String creds, String remoteAddr, String httpMethod, StringBuilder errMsg) {
                return null;
            }

            @Override
            public boolean isValidUser(String username) {
                return username.equals("validuser");
            }
        };

        assertFalse(userAuthority.isValidUser("invaliduser"));
        assertTrue(userAuthority.isValidUser("validuser"));
    }
}