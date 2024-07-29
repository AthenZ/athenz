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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;

import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.Validator;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.List;

public class CompositeInstanceTest {
    @Test
    public void testCompositeInstanceFields() {
        CompositeInstance instance = new CompositeInstance();
        List<String> ipAddresses = Collections.singletonList("10.20.30.40");
        instance.setDomainName("athenz")
                .setServiceName("api")
                .setInstance("i-1333w3er3rr")
                .setInstanceType("ec2")
                .setProvider("aws")
                .setCertExpiryTime(Timestamp.fromMillis(1722347760000L))
                .setCertIssueTime(Timestamp.fromMillis(1722260648000L));

        assertNotNull(instance);
        assertEquals(instance.getDomainName(), "athenz");
        assertEquals(instance.getServiceName(), "api");
        assertEquals(instance.getInstance(), "i-1333w3er3rr");
        assertEquals(instance.getInstanceType(), "ec2");
        assertEquals(instance.getProvider(), "aws");
        assertEquals(instance.getCertExpiryTime(), Timestamp.fromMillis(1722347760000L));
        assertEquals(instance.getCertIssueTime(), Timestamp.fromMillis(1722260648000L));
        assertEquals(instance, instance);

        CompositeInstance instance2 = new CompositeInstance();
        instance2.setDomainName("athenz")
            .setServiceName("api")
            .setInstance("i-1333w3er3rr")
            .setInstanceType("ec2")
            .setProvider("aws")
            .setCertExpiryTime(Timestamp.fromMillis(1722347760000L))
            .setCertIssueTime(Timestamp.fromMillis(1722260648000L));

        assertEquals(instance, instance2);

        instance2.setDomainName("sports");
        assertNotEquals(instance, instance2);
        instance2.setDomainName(null);
        assertNotEquals(instance, instance2);

        instance2.setDomainName("athenz");
        instance2.setServiceName("apiv2");
        assertNotEquals(instance, instance2);
        instance2.setServiceName(null);
        assertNotEquals(instance, instance2);

        instance2.setServiceName("api");
        instance2.setInstance("i-2423w3er3rr");
        assertNotEquals(instance, instance2);
        instance2.setInstance(null);
        assertNotEquals(instance, instance2);

        instance2.setInstance("i-1333w3er3rr");
        instance2.setInstanceType("vm");
        assertNotEquals(instance, instance2);
        instance2.setInstanceType(null);
        assertNotEquals(instance, instance2);

        instance2.setInstanceType("ec2");
        instance2.setProvider("gcp");
        assertNotEquals(instance, instance2);
        instance2.setProvider(null);
        assertNotEquals(instance, instance2);

        instance2.setProvider("aws");
        instance2.setCertExpiryTime(Timestamp.fromMillis(1722247760000L));
        assertNotEquals(instance, instance2);
        instance2.setCertExpiryTime(null);
        assertNotEquals(instance, instance2);

        instance2.setCertExpiryTime(Timestamp.fromMillis(1722347760000L));
        instance2.setCertIssueTime(Timestamp.fromMillis(1722230648000L));
        assertNotEquals(instance, instance2);
        instance2.setCertIssueTime(null);
        assertNotEquals(instance, instance2);

        instance2.setCertIssueTime(Timestamp.fromMillis(1722260648000L));
        assertEquals(instance, instance2);

        assertNotEquals(instance, null);
        // for code coverage
        assertFalse(instance.equals("mystring"));
        assertNotEquals(instance, "mystring");

        assertEquals(instance, instance);
    }
}