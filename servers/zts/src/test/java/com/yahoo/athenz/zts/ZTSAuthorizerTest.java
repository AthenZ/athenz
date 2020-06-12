/*
 * Copyright 2018 Oath Inc.
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
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;

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

    @Test
    public void testCheckRoleMemberExpiration() {

        ZTSAuthorizer authz = new ZTSAuthorizer(null);

        RoleMember roleMember1 = new RoleMember();
        roleMember1.setExpiration(Timestamp.fromMillis(1001));
        roleMember1.setMemberName("user.athenz1");

        RoleMember roleMember2 = new RoleMember();
        roleMember2.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 10000));
        roleMember2.setMemberName("user.athenz2");

        List<RoleMember> members = new ArrayList<>();
        members.add(roleMember1);
        members.add(roleMember2);

        assertTrue(authz.checkRoleMemberValidity(members, "user.athenz2"));
        assertFalse(authz.checkRoleMemberValidity(members, "user.athenz1"));
    }

    @Test
    public void testIsMemberEnabled() {

        ZTSAuthorizer authz = new ZTSAuthorizer(null);

        RoleMember roleMember = new RoleMember();

        roleMember.setSystemDisabled(null);
        assertTrue(authz.isMemberEnabled(roleMember));

        roleMember.setSystemDisabled(0);
        assertTrue(authz.isMemberEnabled(roleMember));

        roleMember.setSystemDisabled(1);
        assertFalse(authz.isMemberEnabled(roleMember));

        roleMember.setSystemDisabled(3);
        assertFalse(authz.isMemberEnabled(roleMember));
    }

    @Test
    public void testIsMemberExpired() {

        ZTSAuthorizer authz = new ZTSAuthorizer(null);

        RoleMember roleMember = new RoleMember();

        roleMember.setExpiration(null);
        assertFalse(authz.isMemberExpired(roleMember));

        roleMember.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 100000));
        assertFalse(authz.isMemberExpired(roleMember));

        roleMember.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 1));
        assertTrue(authz.isMemberExpired(roleMember));
    }

    @Test
    public void testCheckRoleMemberValidity() {

        ZTSAuthorizer authz = new ZTSAuthorizer(null);

        List<RoleMember> roleMembers = new ArrayList<>();

        // valid members

        RoleMember roleMemberJoe = new RoleMember()
                .setMemberName("user.joe");
        RoleMember roleMemberJane = new RoleMember()
                .setMemberName("user.jane")
                .setSystemDisabled(null)
                .setExpiration(null);
        RoleMember roleMemberJohn = new RoleMember()
                .setSystemDisabled(0)
                .setMemberName("user.john")
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 100000));

        roleMembers.add(roleMemberJoe);
        roleMembers.add(roleMemberJane);
        roleMembers.add(roleMemberJohn);

        // invalid members

        RoleMember roleMemberJoeBad = new RoleMember()
                .setMemberName("user.joe-bad")
                .setSystemDisabled(1);
        RoleMember roleMemberJaneBad = new RoleMember()
                .setMemberName("user.jane-bad")
                .setSystemDisabled(null)
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 1));
        RoleMember roleMemberJohnBad = new RoleMember()
                .setSystemDisabled(3)
                .setMemberName("user.john-bad")
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 10000));

        roleMembers.add(roleMemberJoeBad);
        roleMembers.add(roleMemberJaneBad);
        roleMembers.add(roleMemberJohnBad);

        // carry out the checks

        assertTrue(authz.checkRoleMemberValidity(roleMembers, "user.joe"));
        assertTrue(authz.checkRoleMemberValidity(roleMembers, "user.jane"));
        assertTrue(authz.checkRoleMemberValidity(roleMembers, "user.john"));

        assertFalse(authz.checkRoleMemberValidity(roleMembers, "user.joe-bad"));
        assertFalse(authz.checkRoleMemberValidity(roleMembers, "user.jane-bad"));
        assertFalse(authz.checkRoleMemberValidity(roleMembers, "user.john-bad"));
    }
}
