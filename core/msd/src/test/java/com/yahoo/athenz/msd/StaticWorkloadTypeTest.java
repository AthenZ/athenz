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

public class StaticWorkloadTypeTest {
    @Test
    public void StaticWorkloadTypeTest() {

        StaticWorkloadType swt1 = StaticWorkloadType.VIP;
        assertTrue(swt1 == swt1);
        assertFalse(swt1.equals("abc"));

        StaticWorkloadType swt2 = StaticWorkloadType.ENTERPRISE_APPLIANCE;
        assertFalse(swt1 == swt2);

        swt2 = StaticWorkloadType.CLOUD_LB;
        assertFalse(swt1 == swt2);

        swt2 = StaticWorkloadType.CLOUD_NAT;
        assertFalse(swt1 == swt2);

        swt2 = StaticWorkloadType.EXTERNAL_APPLIANCE;
        assertFalse(swt1 == swt2);

        swt2 = StaticWorkloadType.VIP;
        assertEquals(swt1, swt2);


        assertEquals(StaticWorkloadType.fromString("VIP"), StaticWorkloadType.VIP);
        assertEquals(StaticWorkloadType.fromString("ENTERPRISE_APPLIANCE"), StaticWorkloadType.ENTERPRISE_APPLIANCE);
        assertEquals(StaticWorkloadType.fromString("CLOUD_LB"), StaticWorkloadType.CLOUD_LB);
        assertEquals(StaticWorkloadType.fromString("CLOUD_NAT"), StaticWorkloadType.CLOUD_NAT);
        assertEquals(StaticWorkloadType.fromString("EXTERNAL_APPLIANCE"), StaticWorkloadType.EXTERNAL_APPLIANCE);

        try {
            StaticWorkloadType.fromString("XYZ");
        } catch (Exception ignored) {
        }
    }
}