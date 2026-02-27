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
import org.testng.annotations.Test;

public class TransportPolicySnapshotMetadataTest {

    @Test
    public void testTransportPolicySnapshotMetadataFields() {

        TransportPolicySnapshotMetadata metadata1 = new TransportPolicySnapshotMetadata()
                .setDomainName("domain1")
                .setServiceName("service1")
                .setName("snapshot-v1")
                .setCreatedTime(Timestamp.fromMillis(123456789123L))
                .setModified(Timestamp.fromMillis(123456789456L))
                .setActive(true);

        assertEquals(metadata1.getDomainName(), "domain1");
        assertEquals(metadata1.getServiceName(), "service1");
        assertEquals(metadata1.getName(), "snapshot-v1");
        assertEquals(metadata1.getCreatedTime(), Timestamp.fromMillis(123456789123L));
        assertEquals(metadata1.getModified(), Timestamp.fromMillis(123456789456L));
        assertEquals(metadata1.getActive(), true);

        TransportPolicySnapshotMetadata metadata2 = new TransportPolicySnapshotMetadata()
                .setDomainName("domain1")
                .setServiceName("service1")
                .setName("snapshot-v1")
                .setCreatedTime(Timestamp.fromMillis(123456789123L))
                .setModified(Timestamp.fromMillis(123456789456L))
                .setActive(true);

        assertEquals(metadata1, metadata1);
        assertEquals(metadata1, metadata2);

        metadata2.setDomainName("domain2");
        assertNotEquals(metadata1, metadata2);

        metadata2.setDomainName("domain1");
        metadata2.setServiceName("service2");
        assertNotEquals(metadata1, metadata2);

        metadata2.setServiceName("service1");
        metadata2.setName("snapshot-v2");
        assertNotEquals(metadata1, metadata2);

        metadata2.setName("snapshot-v1");
        metadata2.setCreatedTime(Timestamp.fromMillis(999999999L));
        assertNotEquals(metadata1, metadata2);

        metadata2.setCreatedTime(Timestamp.fromMillis(123456789123L));
        metadata2.setModified(Timestamp.fromMillis(999999999L));
        assertNotEquals(metadata1, metadata2);

        metadata2.setModified(Timestamp.fromMillis(123456789456L));
        metadata2.setActive(false);
        assertNotEquals(metadata1, metadata2);

        assertFalse(metadata1.equals("xyz"));
    }

    @Test
    public void testTransportPolicySnapshotMetadataNullFields() {

        TransportPolicySnapshotMetadata metadata1 = new TransportPolicySnapshotMetadata()
                .setDomainName(null)
                .setServiceName(null)
                .setName(null)
                .setCreatedTime(null)
                .setModified(null)
                .setActive(false);

        TransportPolicySnapshotMetadata metadata2 = new TransportPolicySnapshotMetadata()
                .setDomainName(null)
                .setServiceName(null)
                .setName(null)
                .setCreatedTime(null)
                .setModified(null)
                .setActive(false);

        assertEquals(metadata1, metadata2);

        metadata2.setDomainName("domain1");
        assertNotEquals(metadata1, metadata2);

        metadata1.setDomainName("domain1");
        metadata2.setServiceName("service1");
        assertNotEquals(metadata1, metadata2);

        metadata1.setServiceName("service1");
        metadata2.setName("name1");
        assertNotEquals(metadata1, metadata2);

        metadata1.setName("name1");
        metadata2.setCreatedTime(Timestamp.fromMillis(123L));
        assertNotEquals(metadata1, metadata2);

        metadata1.setCreatedTime(Timestamp.fromMillis(123L));
        metadata2.setModified(Timestamp.fromMillis(456L));
        assertNotEquals(metadata1, metadata2);
    }
}
