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
package com.yahoo.athenz.common.server.debug;

import org.testng.annotations.Test;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;

import static org.testng.Assert.*;

public class DebugUserAuthorityTest {

    @Test
    public void testUserAuthority() {
        
        Authority userAuthority = new com.yahoo.athenz.common.server.debug.DebugUserAuthority();
        assertNotNull(userAuthority);
        
        userAuthority.initialize();
        
        assertEquals(userAuthority.getDomain(), "user");
        assertEquals(userAuthority.getHeader(), "Authorization");
        assertFalse(userAuthority.allowAuthorization());
        
        // invalid authenticate values
        StringBuilder errMsg = new StringBuilder();
        assertNull(userAuthority.authenticate("Test Creds", "10.11.12.13", "GET", null));
        assertNull(userAuthority.authenticate("Basic !@#$#!@$#", "10.11.12.13", "GET", null));
        assertNull(userAuthority.authenticate("BasicdGVzdHVzZXI6dGVzdHB3ZA==", "10.11.12.13", "GET", null));
        assertNull(userAuthority.authenticate("BasicdGVzdHVzZXI6dGVzdHB3ZA==", "10.11.12.13", "GET", errMsg));

        // valid values
        
        String token = "Basic dGVzdHVzZXI6dGVzdHB3ZA==";
        Principal p = userAuthority.authenticate(token, "10.11.12.13", "GET", null);
        assertNotNull(p);
        assertEquals(p.getDomain(), "user");
        assertEquals(p.getName(), "testuser");
    }
}
