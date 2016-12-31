/**
 * Copyright 2016 Yahoo Inc.
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

import static org.testng.Assert.*;

import org.jvnet.libpam.PAM;
import org.jvnet.libpam.PAMException;
import org.jvnet.libpam.UnixUser;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.Principal;

import org.mockito.Mockito;

public class UserAuthorityTest {
    private String testToken = "Basic dGVzdHVzZXI6dGVzdHB3ZA==";
    private String expectedDomain = "user";
    private String expectedHeader = "Authorization";
    private String expectedUserId = "testuser";

    @Test
    public void testUserAuthority() throws PAMException {
        PAM pam = Mockito.mock(PAM.class);
        UnixUser user = new UnixUser(System.getenv("USER"));
        Mockito.when(pam.authenticate("testuser", "testpwd")).thenReturn(user);
        UserAuthority userAuthority = new UserAuthority();
        userAuthority.setPAM(pam);
        assertEquals(userAuthority.getDomain(), expectedDomain);
        assertEquals(userAuthority.getHeader(), expectedHeader);

        StringBuilder errMsg = new StringBuilder();
        Principal principal = userAuthority.authenticate(testToken, "10.72.118.45", "GET", errMsg);

        assertNotNull(principal);
        assertNotNull(principal.getAuthority());
        assertEquals(principal.getCredentials(), testToken);
        assertEquals(principal.getDomain(), expectedDomain);
        assertEquals(principal.getName(), expectedUserId);
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
        
        principal = userAuthority.authenticate("Basic ", "10.72.118.45", "GET", null);

        assertNull(principal);
    }
}
