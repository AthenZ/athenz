/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.msd;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class NetworkPolicyChangeImpactDetailTest {

    @Test
    public void testFields() {
        NetworkPolicyChangeImpactDetail o1 = new NetworkPolicyChangeImpactDetail().setPolicy("dummypol")
                .setTransportPolicyId(12345).setDomain("dummydom");

        NetworkPolicyChangeImpactDetail o2 = new NetworkPolicyChangeImpactDetail().setPolicy("dummypol")
                .setTransportPolicyId(12345).setDomain("dummydom");

        assertEquals(o1.getTransportPolicyId(), 12345);
        assertEquals(o1.getPolicy(), "dummypol");
        assertEquals(o1.getDomain(), "dummydom");


        assertEquals(o1, o2);
        assertFalse(o1.equals("abc"));

        o2.setPolicy("dummypol2");
        assertNotEquals(o1, o2);

        o2.setPolicy("dummypol");
        o2.setTransportPolicyId(23456);
        assertNotEquals(o1, o2);

        o2.setTransportPolicyId(12345);
        o2.setDomain("dummydom2");
        assertNotEquals(o1, o2);
    }
}