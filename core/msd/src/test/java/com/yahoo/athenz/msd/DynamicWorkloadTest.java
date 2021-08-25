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

import com.yahoo.rdl.Timestamp;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.List;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class DynamicWorkloadTest {
    @Test
    public void testDynamicWorkloadFields() {
        DynamicWorkload wl1 = new DynamicWorkload();
        List<String> ipAddresses = Collections.singletonList("10.20.30.40");
        wl1.setDomainName("athenz")
                .setServiceName("api")
                .setIpAddresses(ipAddresses)
                .setProvider("kubernetes")
                .setUuid("1234-rsaq-422dcz")
                .setHostname("testhost-1")
                .setUpdateTime(Timestamp.fromMillis(123456789123L))
                .setCertIssueTime(Timestamp.fromMillis(123456789120L))
                .setCertExpiryTime(Timestamp.fromMillis(123456789123L));

        assertNotNull(wl1);
        assertEquals(wl1.getDomainName(), "athenz");
        assertEquals(wl1.getServiceName(), "api");
        assertEquals(wl1.getIpAddresses(), ipAddresses);
        assertEquals(wl1.getProvider(), "kubernetes");
        assertEquals(wl1.getUuid(), "1234-rsaq-422dcz");
        assertEquals(wl1.getUpdateTime(), Timestamp.fromMillis(123456789123L));
        assertEquals(wl1.getHostname(), "testhost-1");
        assertEquals(wl1.getCertIssueTime(), Timestamp.fromMillis(123456789120L));
        assertEquals(wl1.getCertExpiryTime(), Timestamp.fromMillis(123456789123L));
        assertEquals(wl1, wl1);

        DynamicWorkload wl2 = new DynamicWorkload();
        wl2.setDomainName("athenz")
                .setServiceName("api")
                .setIpAddresses(ipAddresses)
                .setProvider("kubernetes")
                .setUuid("1234-rsaq-422dcz")
                .setHostname("testhost-1")
                .setUpdateTime(Timestamp.fromMillis(123456789123L))
                .setCertIssueTime(Timestamp.fromMillis(123456789120L))
                .setCertExpiryTime(Timestamp.fromMillis(123456789123L));

        assertEquals(wl1, wl2);

        wl2.setDomainName("sports");
        assertNotEquals(wl1, wl2);
        wl2.setDomainName(null);
        assertNotEquals(wl1, wl2);

        wl2.setDomainName("athenz");
        wl2.setServiceName("apiv2");
        assertNotEquals(wl1, wl2);
        wl2.setServiceName(null);
        assertNotEquals(wl1, wl2);

        wl2.setServiceName("api");
        wl2.setIpAddresses(null);
        assertNotEquals(wl1, wl2);

        wl2.setIpAddresses(ipAddresses);
        wl2.setProvider("aws");
        assertNotEquals(wl1, wl2);
        wl2.setProvider(null);
        assertNotEquals(wl1, wl2);

        wl2.setProvider("kubernetes");
        wl2.setUuid("23rwf-ews-13");
        assertNotEquals(wl1, wl2);
        wl2.setUuid(null);
        assertNotEquals(wl1, wl2);

        wl2.setUuid("1234-rsaq-422dcz");
        wl2.setUpdateTime(Timestamp.fromMillis(123456789456L));
        assertNotEquals(wl1, wl2);
        wl2.setUpdateTime(null);
        assertNotEquals(wl1, wl2);

        wl2.setUpdateTime(Timestamp.fromMillis(123456789123L));
        wl2.setHostname("random");
        assertNotEquals(wl1, wl2);
        wl2.setHostname(null);
        assertNotEquals(wl1, wl2);

        wl2.setHostname("testhost-1");
        wl2.setCertExpiryTime(Timestamp.fromMillis(123456789000L));
        assertNotEquals(wl1, wl2);
        wl2.setCertExpiryTime(null);
        assertNotEquals(wl1, wl2);
        wl2.setCertExpiryTime(Timestamp.fromMillis(123456789123L));

        wl2.setCertIssueTime(Timestamp.fromMillis(123456789000L));
        assertNotEquals(wl1, wl2);
        wl2.setCertIssueTime(null);
        assertNotEquals(wl1, wl2);
        wl2.setCertIssueTime(Timestamp.fromMillis(123456789120L));

        assertEquals(wl1, wl2);

        assertNotEquals(wl1, null);
        // for code coverage
        assertFalse(wl1.equals("mystring"));
        assertNotEquals(wl1, "mystring");

        assertEquals(wl1, wl1);

    }
}