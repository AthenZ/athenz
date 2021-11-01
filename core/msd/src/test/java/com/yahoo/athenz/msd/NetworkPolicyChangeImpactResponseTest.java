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

import java.util.Collections;

import static org.testng.Assert.*;

public class NetworkPolicyChangeImpactResponseTest {

    @Test
    public void testFields() {
        NetworkPolicyChangeImpactDetail d1 = new NetworkPolicyChangeImpactDetail().setPolicy("dummypol")
                .setTransportPolicyId(12345).setDomain("dummydom");

        NetworkPolicyChangeImpactDetail d2 = new NetworkPolicyChangeImpactDetail().setPolicy("dummypol")
                .setTransportPolicyId(12345).setDomain("dummydom");

        NetworkPolicyChangeImpactResponse o1 = new NetworkPolicyChangeImpactResponse()
                .setEffect(NetworkPolicyChangeEffect.IMPACT)
                .setDetails(Collections.singletonList(d1));

        NetworkPolicyChangeImpactResponse o2 = new NetworkPolicyChangeImpactResponse()
                .setEffect(NetworkPolicyChangeEffect.IMPACT)
                .setDetails(Collections.singletonList(d2));

        assertEquals(o1, o2);
        assertEquals(o1, o1);
        assertFalse(o1.equals("abc"));

        assertEquals(o1.getEffect(), NetworkPolicyChangeEffect.IMPACT);
        assertEquals(o1.getDetails(), Collections.singletonList(d1));

        o2.setDetails(null);
        assertNotEquals(o1, o2);

        o2.setDetails(Collections.singletonList(d2));
        o2.setEffect(NetworkPolicyChangeEffect.NO_IMPACT);
        assertNotEquals(o1, o2);
    }
}