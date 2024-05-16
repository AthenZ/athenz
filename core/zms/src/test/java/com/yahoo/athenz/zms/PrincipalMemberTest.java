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

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class PrincipalMemberTest {

    @Test
    public void testPrincipal() {
        PrincipalMember principal1 = new PrincipalMember().setPrincipalName("athenz.api")
                .setSuspendedState(7);
        assertEquals(principal1.getPrincipalName(), "athenz.api");
        assertEquals(principal1.getSuspendedState(), 7);

        PrincipalMember principal2 = new PrincipalMember().setPrincipalName("athenz.api")
                .setSuspendedState(7);
        assertEquals(principal1, principal2);
        assertNotEquals(null, principal1);
        assertNotEquals("principal", principal1);

        principal1.setPrincipalName("athenz.api2");
        assertNotEquals(principal1, principal2);
        principal1.setPrincipalName(null);
        assertNotEquals(principal1, principal2);
        principal1.setPrincipalName("athenz.api");
        assertEquals(principal1, principal2);

        principal1.setSuspendedState(8);
        assertNotEquals(principal1, principal2);
    }

    @Test
    public void testPrincipalState() {
        PrincipalState state1 = new PrincipalState().setSuspended(true);
        assertTrue(state1.getSuspended());

        PrincipalState state2 = new PrincipalState().setSuspended(true);

        assertEquals(state1, state2);
        assertNotEquals(null, state1);
        assertNotEquals("state", state1);

        state1.setSuspended(false);
        assertNotEquals(state1, state2);
    }
}
