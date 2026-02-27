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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotEquals;

import org.testng.annotations.Test;

public class TransportPolicySnapshotUpdateRequestTest {

    @Test
    public void testTransportPolicySnapshotUpdateRequestFields() {

        TransportPolicySnapshotUpdateRequest request1 = new TransportPolicySnapshotUpdateRequest()
                .setActive(true);

        assertEquals(request1.getActive(), true);

        TransportPolicySnapshotUpdateRequest request2 = new TransportPolicySnapshotUpdateRequest()
                .setActive(true);

        assertEquals(request1, request1);
        assertEquals(request1, request2);

        request2.setActive(false);
        assertNotEquals(request1, request2);

        assertFalse(request1.equals("xyz"));
    }

    @Test
    public void testTransportPolicySnapshotUpdateRequestToggleActive() {

        TransportPolicySnapshotUpdateRequest request1 = new TransportPolicySnapshotUpdateRequest()
                .setActive(false);

        TransportPolicySnapshotUpdateRequest request2 = new TransportPolicySnapshotUpdateRequest()
                .setActive(false);

        assertEquals(request1, request2);

        request2.setActive(true);
        assertNotEquals(request1, request2);

        // Test toggling back
        request2.setActive(false);
        assertEquals(request1, request2);
    }

    @Test
    public void testTransportPolicySnapshotUpdateRequestSetAndGet() {

        TransportPolicySnapshotUpdateRequest request = new TransportPolicySnapshotUpdateRequest();

        // Test that we can set and get active field
        request.setActive(false);
        assertEquals(request.getActive(), false);

        request.setActive(true);
        assertEquals(request.getActive(), true);
    }
}
