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

package com.yahoo.athenz.msd;

import org.testng.annotations.Test;

import java.util.Collections;

import static org.testng.Assert.*;

public class TransportPolicyValidationResponseListTest {

    @Test
    public void testTransportPolicyValidationResponseList() {
        TransportPolicyValidationResponseList responseList1 = new TransportPolicyValidationResponseList();
        TransportPolicyValidationResponseList responseList2 = new TransportPolicyValidationResponseList();

        TransportPolicyValidationResponse response1 = new TransportPolicyValidationResponse();
        response1.setStatus(TransportPolicyValidationStatus.VALID);

        TransportPolicyValidationResponse response2 = new TransportPolicyValidationResponse();
        response2.setStatus(TransportPolicyValidationStatus.VALID);

        responseList1.setResponseList(Collections.singletonList(response1));
        responseList2.setResponseList(Collections.singletonList(response2));

        assertEquals(responseList1.getResponseList(), responseList2.getResponseList());
        assertTrue(responseList1.equals(responseList2));

        response2.setStatus(TransportPolicyValidationStatus.INVALID);
        assertFalse(responseList1.equals(responseList2));
        assertFalse(responseList1.equals(null));
    }
}
