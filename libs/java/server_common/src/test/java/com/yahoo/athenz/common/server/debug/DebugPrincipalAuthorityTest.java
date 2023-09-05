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

import com.yahoo.athenz.auth.Principal;

import static org.testng.Assert.*;

public class DebugPrincipalAuthorityTest {
    
    @Test
    public void testPrincipalAuthority() {

        DebugPrincipalAuthority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        assertNotNull(principalAuthority);
        
        principalAuthority.initialize();
        principalAuthority.setKeyStore(null);
        
        assertNull(principalAuthority.getDomain());
        assertEquals(principalAuthority.getHeader(), "Athenz-Principal-Auth");
        
        // invalid authenticate values
        
        assertNull(principalAuthority.authenticate(null, "10.11.12.13", "GET", null));
        assertNull(principalAuthority.authenticate("abc", "10.11.12.13", "GET", null));
        assertNull(principalAuthority.authenticate("v=S1;d=coretech;s=signature", "10.11.12.13", "GET", null));
        assertNull(principalAuthority.authenticate("v=S1;n=storage;s=signature", "10.11.12.13", "GET", null));
        assertNull(principalAuthority.authenticate("v==S1;n=storage;s=signature", "10.11.12.13", "GET", null));

        // valid values

        String token = "v=S1;d=coretech;n=storage;s=signature";
        Principal p = principalAuthority.authenticate(token, "10.11.12.13", "GET", null);
        assertNotNull(p);
        assertEquals(p.getDomain(), "coretech");
        assertEquals(p.getName(), "storage");
        assertEquals(p.getCredentials(), token);
        assertNull(p.getRoles());
    }
}
