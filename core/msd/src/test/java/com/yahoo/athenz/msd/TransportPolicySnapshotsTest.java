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

import com.yahoo.rdl.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.testng.annotations.Test;

public class TransportPolicySnapshotsTest {

    @Test
    public void testTransportPolicySnapshotsFields() {

        TransportPolicySnapshotMetadata metadata1 = new TransportPolicySnapshotMetadata()
                .setDomainName("domain1")
                .setServiceName("service1")
                .setName("snapshot-v1")
                .setCreatedTime(Timestamp.fromMillis(123456789123L))
                .setActive(true);

        TransportPolicySnapshotMetadata metadata2 = new TransportPolicySnapshotMetadata()
                .setDomainName("domain1")
                .setServiceName("service1")
                .setName("snapshot-v2")
                .setCreatedTime(Timestamp.fromMillis(123456789456L))
                .setActive(false);

        List<TransportPolicySnapshotMetadata> snapshotList1 = new ArrayList<>();
        snapshotList1.add(metadata1);
        snapshotList1.add(metadata2);

        TransportPolicySnapshots snapshots1 = new TransportPolicySnapshots()
                .setSnapshots(snapshotList1);

        assertEquals(snapshots1.getSnapshots(), snapshotList1);
        assertEquals(snapshots1.getSnapshots().size(), 2);

        List<TransportPolicySnapshotMetadata> snapshotList2 = new ArrayList<>();
        snapshotList2.add(metadata1);
        snapshotList2.add(metadata2);

        TransportPolicySnapshots snapshots2 = new TransportPolicySnapshots()
                .setSnapshots(snapshotList2);

        assertEquals(snapshots1, snapshots1);
        assertEquals(snapshots1, snapshots2);

        snapshots2.setSnapshots(Collections.singletonList(metadata1));
        assertNotEquals(snapshots1, snapshots2);

        snapshots2.setSnapshots(null);
        assertNotEquals(snapshots1, snapshots2);

        assertFalse(snapshots1.equals("xyz"));
    }

    @Test
    public void testTransportPolicySnapshotsNullFields() {

        TransportPolicySnapshots snapshots1 = new TransportPolicySnapshots()
                .setSnapshots(null);

        TransportPolicySnapshots snapshots2 = new TransportPolicySnapshots()
                .setSnapshots(null);

        assertEquals(snapshots1, snapshots2);

        TransportPolicySnapshotMetadata metadata = new TransportPolicySnapshotMetadata()
                .setDomainName("domain1")
                .setServiceName("service1")
                .setName("snapshot-v1");

        snapshots2.setSnapshots(Collections.singletonList(metadata));
        assertNotEquals(snapshots1, snapshots2);
    }

    @Test
    public void testTransportPolicySnapshotsEmptyList() {

        TransportPolicySnapshots snapshots1 = new TransportPolicySnapshots()
                .setSnapshots(new ArrayList<>());

        assertEquals(snapshots1.getSnapshots().size(), 0);

        TransportPolicySnapshots snapshots2 = new TransportPolicySnapshots()
                .setSnapshots(new ArrayList<>());

        assertEquals(snapshots1, snapshots2);
    }
}
