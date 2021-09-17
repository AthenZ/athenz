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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;
import static org.testng.Assert.assertEquals;

public class TransportPolicyValidationResponseTest {

    @Test
    public void testTransportPolicyValidationResponse() {

        List<String> errors = new ArrayList<String>();
        errors.add("error1");

        TransportPolicyValidationResponse tpvr1 = new TransportPolicyValidationResponse().setStatus(TransportPolicyValidationStatus.INVALID).setErrors(null);
        assertEquals(tpvr1.getStatus(), TransportPolicyValidationStatus.INVALID);
        assertEquals(tpvr1.getErrors(), null);
        assertNotEquals(tpvr1.getErrors(), errors);

        tpvr1.setErrors(errors);
        assertEquals(tpvr1.getErrors(), errors);

        tpvr1.setStatus(TransportPolicyValidationStatus.VALID);
        assertNotEquals(tpvr1.getStatus(), TransportPolicyValidationStatus.INVALID);
        assertEquals(tpvr1.getStatus(), TransportPolicyValidationStatus.VALID);

        TransportPolicyValidationResponse tpvr2 = new TransportPolicyValidationResponse().setStatus(TransportPolicyValidationStatus.VALID).setErrors(errors);
        assertTrue(tpvr2.equals(tpvr1));

        tpvr2.setErrors(null);
        assertFalse(tpvr2.equals(tpvr1));

        tpvr2.setStatus(TransportPolicyValidationStatus.PARTIAL);
        assertFalse(tpvr2.equals(tpvr1));

        assertFalse(tpvr1.equals("abc"));
        assertTrue(tpvr1.equals(tpvr1));
    }

}