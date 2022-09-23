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
package com.yahoo.athenz.zts;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class ZTSAuthorizerTest {

    @Test
    public void testAccessAuthoritySupport() {
        ZTSAuthorizer authz = new ZTSAuthorizer(null);

        Authority authority = Mockito.mock(Authority.class);
        Mockito.when(authority.allowAuthorization()).thenReturn(false);

        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(principal.getAuthority()).thenReturn(authority);

        assertFalse(authz.access("op", "resource", principal, null));
    }

    @Test
    public void testAccessInvalidResourceDomain() {
        ZTSAuthorizer authz = new ZTSAuthorizer(null);

        Authority authority = Mockito.mock(Authority.class);
        Mockito.when(authority.allowAuthorization()).thenReturn(true);

        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(principal.getAuthority()).thenReturn(authority);

        try {
            authz.access("op", "invalid-resource", principal, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }
}
