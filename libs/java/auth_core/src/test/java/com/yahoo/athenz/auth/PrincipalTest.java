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

import java.util.List;

import static org.testng.Assert.*;

public class PrincipalTest {

    @Test
    public void testPrincipal() {

        Principal principal = new Principal() {
            @Override
            public String getDomain() {
                return null;
            }

            @Override
            public String getName() {
                return null;
            }

            @Override
            public String getFullName() {
                return null;
            }

            @Override
            public String getCredentials() {
                return null;
            }

            @Override
            public String getUnsignedCredentials() {
                return null;
            }

            @Override
            public List<String> getRoles() {
                return null;
            }

            @Override
            public Authority getAuthority() {
                return null;
            }

            @Override
            public long getIssueTime() {
                return 0;
            }

            @Override
            public String getAuthorizedService() {
                return null;
            }
        };

        assertNull(principal.getX509Certificate());
        assertNull(principal.getIP());
        assertNull(principal.getOriginalRequestor());
        assertNull(principal.getKeyService());
        assertNull(principal.getKeyId());
        assertNull(principal.getApplicationId());
    }
}
