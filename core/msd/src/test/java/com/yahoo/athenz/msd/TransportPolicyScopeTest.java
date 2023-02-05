/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.msd;

import org.testng.annotations.Test;

import static org.testng.Assert.assertNotEquals;
import static org.testng.AssertJUnit.*;

public class TransportPolicyScopeTest {

    @Test
    public void testTransportPolicyScope() {
        TransportPolicyScope scope1 = TransportPolicyScope.AWS;
        TransportPolicyScope scope2 = TransportPolicyScope.AWS;
        assertEquals(scope1, scope2);
        assertFalse(scope1.equals(null));
        assertFalse(scope1.equals(new Object()));

        scope1 = TransportPolicyScope.ONPREM;
        assertNotEquals(scope1, scope2);
        scope2 = TransportPolicyScope.ONPREM;
        assertEquals(scope1, scope2);

        scope1 = TransportPolicyScope.ALL;
        assertNotEquals(scope1, scope2);
        scope2 = TransportPolicyScope.ALL;
        assertEquals(scope1, scope2);

        assertEquals(TransportPolicyScope.AWS, TransportPolicyScope.fromString("AWS"));
        assertEquals(TransportPolicyScope.ONPREM, TransportPolicyScope.fromString("ONPREM"));
        assertEquals(TransportPolicyScope.ALL, TransportPolicyScope.fromString("ALL"));

        try {
            TransportPolicyScope.fromString("bad");
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid string representation for TransportPolicyScope: bad");
        }
    }
}
