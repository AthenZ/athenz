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

import java.util.List;

import org.testng.annotations.Test;

import com.yahoo.athenz.auth.Principal;

import static org.testng.Assert.*;

public class DebugRoleAuthorityTest {

    @Test
    public void testRoleAuthority() {

        DebugRoleAuthority roleAuthority = new com.yahoo.athenz.common.server.debug.DebugRoleAuthority();
        assertNotNull(roleAuthority);
        
        roleAuthority.initialize();
        roleAuthority.setKeyStore(null);
        
        assertNull(roleAuthority.getDomain());
        assertEquals(roleAuthority.getHeader(), "Athenz-Role-Auth");
        
        // invalid authenticate values
        assertNull(roleAuthority.authenticate(null, "10.11.12.13", "GET", null));
        assertNull(roleAuthority.authenticate("abc", "10.11.12.13", "GET", null));
        assertNull(roleAuthority.authenticate("v=Z1;d=coretech;s=signature", "10.11.12.13", "GET", null));
        assertNull(roleAuthority.authenticate("v=Z1;r=role1,role2,role3;s=signature", "10.11.12.13", "GET", null));
        assertNull(roleAuthority.authenticate("v=U1;d=coretech;r=role1,role2,role3;s=signature", "10.11.12.13", "GET", null));
        assertNull(roleAuthority.authenticate("v==U1;d=coretech;r=role1,role2,role3;s=signature", "10.11.12.13", "GET", null));

        // valid values
        String token = "v=Z1;d=coretech;r=role1,role2,role3;s=signature";
        Principal p = roleAuthority.authenticate(token, "10.11.12.13", "GET", null);
        assertNotNull(p);
        assertEquals(p.getDomain(), "coretech");
        assertEquals(p.getCredentials(), token);
        
        assertNull(p.getName());
        
        List<String> roles = p.getRoles();
        assertEquals(roles.size(), 3);
        assertTrue(roles.contains("role1"));
        assertTrue(roles.contains("role2"));
        assertTrue(roles.contains("role3"));
    }
}
