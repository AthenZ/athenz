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
package com.yahoo.athenz.zts;

import com.yahoo.rdl.Timestamp;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;

public class WorkloadsTest {
    @Test
    public void testWorkloadsFields() {
        Workloads workloads1 = new Workloads();
        Workload wl1 = new Workload();
        List<String> ipAddresses = Collections.singletonList("10.20.30.40");
        wl1.setDomainName("athenz").setServiceName("api").setIpAddresses(ipAddresses).setProvider("kubernetes").setUuid("1234-rsaq-422dcz")
                .setUpdateTime(Timestamp.fromMillis(123456789123L)).setHostname("testhost-1").setCertExpiryTime(Timestamp.fromMillis(123456789123L));

        List<Workload> workloadList1 = Collections.singletonList(wl1);

        workloads1.setWorkloadList(workloadList1);

        assertNotNull(workloads1.getWorkloadList());

        assertEquals(workloads1, workloads1);

        Workloads workloads2 = new Workloads();
        Workload wl2 = new Workload();
        wl2.setDomainName("athenz").setServiceName("api").setIpAddresses(ipAddresses).setProvider("kubernetes").setUuid("1234-rsaq-422dcz")
                .setUpdateTime(Timestamp.fromMillis(123456789123L)).setHostname("testhost-1").setCertExpiryTime(Timestamp.fromMillis(123456789123L));

        List<Workload> workloadList2 = Collections.singletonList(wl2);
        workloads2.setWorkloadList(workloadList2);

        assertNotNull(workloads2.getWorkloadList());

        workloads2.setWorkloadList(workloadList1);
        assertEquals(workloads1, workloads2);

        workloads2.setWorkloadList(null);
        assertNotEquals(workloads1, workloads2);

        Workload wl3 = new Workload();
        wl3.setDomainName("athenz").setServiceName("api").setIpAddresses(ipAddresses).setProvider("openstack").setUuid("1234-acbf")
                .setUpdateTime(Timestamp.fromMillis(123456789123L)).setHostname("testhost-1").setCertExpiryTime(Timestamp.fromMillis(123456789123L));

        List<Workload> workloadList3 = Collections.singletonList(wl3);
        workloads2.setWorkloadList(workloadList3);

        assertNotEquals(workloads1, workloads2);

        // for code coverage
        assertFalse(workloads1.equals("anotherstring"));

        assertNotEquals(workloads1, null);
        assertNotEquals(workloads1, "mystring");
    }
}