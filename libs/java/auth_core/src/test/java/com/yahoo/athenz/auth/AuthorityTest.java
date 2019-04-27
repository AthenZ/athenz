/*
 * Copyright 2019 Oath Holdings, Inc
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
package com.yahoo.athenz.auth;

import org.testng.annotations.Test;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;

import static org.testng.Assert.*;

public class AuthorityTest {

    @Test
    public void testAuthority() {

        Authority authority = new Authority() {
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
        };

        assertNull(authority.getAuthenticateChallenge());
        assertEquals(Authority.CredSource.HEADER, authority.getCredSource());
        assertTrue(authority.allowAuthorization());
        assertEquals("user", authority.getUserDomainName("user"));
        assertTrue(authority.isValidUser("john"));
        assertNull(authority.authenticate((X509Certificate[]) null, null));
        assertNull(authority.authenticate((HttpServletRequest) null, null));
    }
}
