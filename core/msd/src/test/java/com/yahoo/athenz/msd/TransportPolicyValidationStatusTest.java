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

public class TransportPolicyValidationStatusTest {

    @Test
    public void testTransportPolicyValidationStatus() {

        TransportPolicyValidationStatus tpvs1 = TransportPolicyValidationStatus.VALID;
        assertTrue(tpvs1 == tpvs1);
        assertFalse(tpvs1.equals("abc"));

        TransportPolicyValidationStatus tpvs2 = TransportPolicyValidationStatus.INVALID;
        assertFalse(tpvs1 == tpvs2);

        tpvs2 = TransportPolicyValidationStatus.VALID;
        assertEquals(tpvs1, tpvs2);

        TransportPolicyValidationStatus tpvs3 = TransportPolicyValidationStatus.PARTIAL;
        assertFalse(tpvs3 == tpvs2);

        tpvs2 = TransportPolicyValidationStatus.PARTIAL;
        assertEquals(tpvs2, tpvs3);

        assertEquals(TransportPolicyValidationStatus.fromString("VALID"), TransportPolicyValidationStatus.VALID);

        try {
            TransportPolicyValidationStatus.fromString("XYZ");
        } catch (Exception ignored) {
        }
    }

}