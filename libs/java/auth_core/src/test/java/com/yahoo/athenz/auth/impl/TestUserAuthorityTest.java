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

import com.yahoo.athenz.auth.Principal;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.any;
import static org.testng.Assert.*;

public class TestUserAuthorityTest {

    @Test
    public void testGetID() {
        TestUserAuthority tua = new TestUserAuthority();
        assertEquals(tua.getID(), "Auth-TESTUSER");
    }

    @Test
    public void testGetDomain() {
        TestUserAuthority tua = new TestUserAuthority();
        assertEquals(tua.getDomain(), "user");
    }

    @Test
    public void testGetHeader() {
        TestUserAuthority tua = new TestUserAuthority();
        assertEquals(tua.getHeader(), "Authorization");
    }

    @Test
    public void testGetAuthenticateChallenge() {
        TestUserAuthority tua = new TestUserAuthority();
        assertEquals(tua.getAuthenticateChallenge(), TestUserAuthority.ATHENZ_AUTH_CHALLENGE);
    }

    @Test
    public void testAllowAuthorization() {
        TestUserAuthority tua = new TestUserAuthority();
        assertFalse(tua.allowAuthorization());
    }

    @Test
    public void testAuthenticate() {
        TestUserAuthority tua = new TestUserAuthority();
        StringBuilder errMsg = new StringBuilder();

        try {
            tua.initialize();
        }catch (Exception ex) {
            fail();
        }

        // happy path
        String testToken = "Basic dGVzdHVzZXI6dGVzdHVzZXI=";
        Principal principal = tua.authenticate(testToken, "10.72.118.45", "GET", errMsg);
        assertNotNull(principal);

        // username and password dont match
        testToken = "Basic dGVzdHVzZXI6dGVzdHB3ZA==";
        principal = tua.authenticate(testToken, "10.72.118.45", "GET", errMsg);
        assertNull(principal);

        // invalid format
        testToken = "dGVzdHVzZXI6dGVzdHB3ZA==";
        principal = tua.authenticate(testToken, "10.72.118.45", "GET", errMsg);
        assertNull(principal);

        // invalid format 2
        testToken = "Basic ";
        principal = tua.authenticate(testToken, "10.72.118.45", "GET", null);
        assertNull(principal);

        // invalid format 3
        testToken = "Basic feeewa";
        principal = tua.authenticate(testToken, "10.72.118.45", "GET", errMsg);
        assertNull(principal);

        // invalid format 4
        testToken = "Basic dGVzdHVzZXI6";
        principal = tua.authenticate(testToken, "10.72.118.45", "GET", errMsg);
        assertNull(principal);

        // invalid format 5
        testToken = "Basic dGVzdHVzZXI=";
        principal = tua.authenticate(testToken, "10.72.118.45", "GET", errMsg);
        assertNull(principal);

        // Failed to create principal
        try (MockedStatic<SimplePrincipal> theMock = Mockito.mockStatic(SimplePrincipal.class)) {
            theMock.when((MockedStatic.Verification) SimplePrincipal.create(anyString(), anyString(), anyString(), anyLong(), any())).thenReturn(null);
            testToken = "Basic dGVzdHVzZXI6dGVzdHVzZXI=";
            principal = tua.authenticate(testToken, "10.72.118.45", "GET", errMsg);
            assertNull(principal);
        }

    }

    @Test
    public void testGetSimplePrincipal() {
        TestUserAuthority tua = new TestUserAuthority();
        long issueTime = System.currentTimeMillis();
        SimplePrincipal sp = tua.getSimplePrincipal("abc", "xyz", issueTime);
        assertNotNull(sp);
        assertEquals(sp.getAuthority().getClass(), TestUserAuthority.class);
    }
}