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
import org.testng.annotations.Test;

public class TransportPolicySnapshotTest {

    @Test
    public void testTransportPolicySnapshotFields() {

        TransportPolicyRules rules1 = new TransportPolicyRules()
                .setIngress(new ArrayList<>())
                .setEgress(new ArrayList<>());

        TransportPolicySnapshot snapshot1 = new TransportPolicySnapshot()
                .setDomainName("domain1")
                .setServiceName("service1")
                .setName("snapshot-v1")
                .setCreatedTime(Timestamp.fromMillis(123456789123L))
                .setModified(Timestamp.fromMillis(123456789456L))
                .setActive(true)
                .setTransportPolicyRules(rules1);

        assertEquals(snapshot1.getDomainName(), "domain1");
        assertEquals(snapshot1.getServiceName(), "service1");
        assertEquals(snapshot1.getName(), "snapshot-v1");
        assertEquals(snapshot1.getCreatedTime(), Timestamp.fromMillis(123456789123L));
        assertEquals(snapshot1.getModified(), Timestamp.fromMillis(123456789456L));
        assertEquals(snapshot1.getActive(), true);
        assertEquals(snapshot1.getTransportPolicyRules(), rules1);

        TransportPolicyRules rules2 = new TransportPolicyRules()
                .setIngress(new ArrayList<>())
                .setEgress(new ArrayList<>());

        TransportPolicySnapshot snapshot2 = new TransportPolicySnapshot()
                .setDomainName("domain1")
                .setServiceName("service1")
                .setName("snapshot-v1")
                .setCreatedTime(Timestamp.fromMillis(123456789123L))
                .setModified(Timestamp.fromMillis(123456789456L))
                .setActive(true)
                .setTransportPolicyRules(rules2);

        assertEquals(snapshot1, snapshot1);
        assertEquals(snapshot1, snapshot2);

        snapshot2.setDomainName("domain2");
        assertNotEquals(snapshot1, snapshot2);

        snapshot2.setDomainName("domain1");
        snapshot2.setServiceName("service2");
        assertNotEquals(snapshot1, snapshot2);

        snapshot2.setServiceName("service1");
        snapshot2.setName("snapshot-v2");
        assertNotEquals(snapshot1, snapshot2);

        snapshot2.setName("snapshot-v1");
        snapshot2.setCreatedTime(Timestamp.fromMillis(999999999L));
        assertNotEquals(snapshot1, snapshot2);

        snapshot2.setCreatedTime(Timestamp.fromMillis(123456789123L));
        snapshot2.setModified(Timestamp.fromMillis(999999999L));
        assertNotEquals(snapshot1, snapshot2);

        snapshot2.setModified(Timestamp.fromMillis(123456789456L));
        snapshot2.setActive(false);
        assertNotEquals(snapshot1, snapshot2);

        snapshot2.setActive(true);
        snapshot2.setTransportPolicyRules(null);
        assertNotEquals(snapshot1, snapshot2);

        assertFalse(snapshot1.equals("xyz"));
    }

    @Test
    public void testTransportPolicySnapshotNullFields() {

        TransportPolicySnapshot snapshot1 = new TransportPolicySnapshot()
                .setDomainName(null)
                .setServiceName(null)
                .setName(null)
                .setCreatedTime(null)
                .setModified(null)
                .setActive(false)
                .setTransportPolicyRules(null);

        TransportPolicySnapshot snapshot2 = new TransportPolicySnapshot()
                .setDomainName(null)
                .setServiceName(null)
                .setName(null)
                .setCreatedTime(null)
                .setModified(null)
                .setActive(false)
                .setTransportPolicyRules(null);

        assertEquals(snapshot1, snapshot2);

        snapshot2.setDomainName("domain1");
        assertNotEquals(snapshot1, snapshot2);

        snapshot1.setDomainName("domain1");
        snapshot2.setServiceName("service1");
        assertNotEquals(snapshot1, snapshot2);

        snapshot1.setServiceName("service1");
        snapshot2.setName("name1");
        assertNotEquals(snapshot1, snapshot2);

        snapshot1.setName("name1");
        snapshot2.setCreatedTime(Timestamp.fromMillis(123L));
        assertNotEquals(snapshot1, snapshot2);

        snapshot1.setCreatedTime(Timestamp.fromMillis(123L));
        snapshot2.setModified(Timestamp.fromMillis(456L));
        assertNotEquals(snapshot1, snapshot2);

        snapshot1.setModified(Timestamp.fromMillis(456L));
        TransportPolicyRules rules = new TransportPolicyRules();
        snapshot2.setTransportPolicyRules(rules);
        assertNotEquals(snapshot1, snapshot2);
    }
}
