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
        assertFalse(principal.getMtlsRestricted());
        assertEquals(principal.getState(), Principal.State.ACTIVE);
    }

    @Test
    public void testPrincipalState() {
        Principal.State state = Principal.State.ACTIVE;
        assertEquals(state.getValue(), 0);

        state = Principal.State.AUTHORITY_FILTER_DISABLED;
        assertEquals(state.getValue(), 1);

        state = Principal.State.AUTHORITY_SYSTEM_SUSPENDED;
        assertEquals(state.getValue(), 2);

        assertEquals(Principal.State.getState(0), Principal.State.ACTIVE);
        assertEquals(Principal.State.getState(1), Principal.State.AUTHORITY_FILTER_DISABLED);
        assertEquals(Principal.State.getState(2), Principal.State.AUTHORITY_SYSTEM_SUSPENDED);
        assertEquals(Principal.State.getState(3), Principal.State.ACTIVE);
    }

    @Test
    public void testPrincipalType() {
        Principal.Type type = Principal.Type.UNKNOWN;
        assertEquals(type.getValue(), 0);

        type = Principal.Type.USER;
        assertEquals(type.getValue(), 1);

        type = Principal.Type.SERVICE;
        assertEquals(type.getValue(), 2);

        type = Principal.Type.GROUP;
        assertEquals(type.getValue(), 3);

        type = Principal.Type.USER_HEADLESS;
        assertEquals(type.getValue(), 4);

        assertEquals(Principal.Type.getType(0), Principal.Type.UNKNOWN);
        assertEquals(Principal.Type.getType(1), Principal.Type.USER);
        assertEquals(Principal.Type.getType(2), Principal.Type.SERVICE);
        assertEquals(Principal.Type.getType(3), Principal.Type.GROUP);
        assertEquals(Principal.Type.getType(4), Principal.Type.USER_HEADLESS);
        assertEquals(Principal.Type.getType(5), Principal.Type.UNKNOWN);
    }
}
