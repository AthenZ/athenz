/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.msd;

import org.testng.annotations.Test;

import static org.testng.Assert.*;
import static org.testng.Assert.assertEquals;

public class TransportPolicyTrafficDirectionTest {

    @Test
    public void testTransportPolicyTrafficDirection() {
        TransportPolicyTrafficDirection td1 = TransportPolicyTrafficDirection.INGRESS;
        assertTrue(td1 == td1);
        assertFalse(td1.equals("abc"));

        TransportPolicyTrafficDirection td2 = TransportPolicyTrafficDirection.EGRESS;
        assertFalse(td1 == td2);

        td2 = TransportPolicyTrafficDirection.INGRESS;
        assertEquals(td1, td2);

        assertEquals(TransportPolicyTrafficDirection.fromString("INGRESS"), TransportPolicyTrafficDirection.INGRESS);

        try {
            TransportPolicyTrafficDirection.fromString("XYZ");
        } catch (Exception ignored) {
        }
    }

}