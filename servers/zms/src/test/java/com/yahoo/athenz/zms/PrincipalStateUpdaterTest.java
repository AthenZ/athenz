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

package com.yahoo.athenz.zms;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;

import static com.yahoo.athenz.zms.ZMSConsts.ZMS_PROP_PRINCIPAL_STATE_UPDATER_DISABLE_TIMER;
import static org.testng.Assert.*;

public class PrincipalStateUpdaterTest {

    @Mock
    DBService dbsvc;

    @Mock
    Authority authority;

    @BeforeClass
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testRefreshUserStateFromAuthority() {
        List<Principal> currSuspended = new ArrayList<>();
        Principal p = SimplePrincipal.create("user", "user1", (String) null);
        currSuspended.add(p);

        p = SimplePrincipal.create("user", "user2", (String) null);
        currSuspended.add(p);

        p = SimplePrincipal.create("user", "user3", (String) null);
        currSuspended.add(p);


        List<Principal> newSuspended = new ArrayList<>();
        p = SimplePrincipal.create("user", "user2", (String) null);
        newSuspended.add(p);

        p = SimplePrincipal.create("user", "user3", (String) null);
        newSuspended.add(p);

        p = SimplePrincipal.create("user", "user4", (String) null);
        newSuspended.add(p);

        Mockito.when(dbsvc.getPrincipals(Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue())).thenReturn(currSuspended);
        Mockito.when(authority.getPrincipals(EnumSet.of(Principal.State.AUTHORITY_SYSTEM_SUSPENDED))).thenReturn(newSuspended);

        try {
            new PrincipalStateUpdater(dbsvc, authority);
        }catch (ResourceException rex){
            fail();
        }
    }

    @Test
    public void testShutdown() {
        Mockito.when(dbsvc.getPrincipals(Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue())).thenReturn(Collections.emptyList());
        Mockito.when(authority.getPrincipals(EnumSet.of(Principal.State.AUTHORITY_SYSTEM_SUSPENDED))).thenReturn(Collections.emptyList());

        try {
            PrincipalStateUpdater principalStateUpdater = new PrincipalStateUpdater(dbsvc, authority);
            principalStateUpdater.shutdown();
        }catch (ResourceException rex){
            fail();
        }
    }

    @Test
    public void testNoTimer() {
        Mockito.when(dbsvc.getPrincipals(Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue())).thenReturn(Collections.emptyList());
        Mockito.when(authority.getPrincipals(EnumSet.of(Principal.State.AUTHORITY_SYSTEM_SUSPENDED))).thenReturn(Collections.emptyList());
        System.setProperty(ZMS_PROP_PRINCIPAL_STATE_UPDATER_DISABLE_TIMER, "true");
        try {
            new PrincipalStateUpdater(dbsvc, authority);
        }catch (ResourceException rex){
            fail();
        }
        System.clearProperty(ZMS_PROP_PRINCIPAL_STATE_UPDATER_DISABLE_TIMER);
    }

}