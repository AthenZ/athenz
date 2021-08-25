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

public class WorkloadsTest {
    @Test
    public void testWorkloadsFields() {
        Workloads workloads1 = new Workloads();

        Workload wl1 = new Workload();
        List<String> ipAddresses = Collections.singletonList("10.20.30.40");
        wl1.setDomainName("athenz").setServiceName("api").setIpAddresses(ipAddresses).setProvider("kubernetes").setUuid("1234-rsaq-422dcz")
                .setUpdateTime(Timestamp.fromMillis(123456789123L)).setHostname("testhost-1").setCertExpiryTime(Timestamp.fromMillis(123456789123L));

        List<Workload> workloadList1 = Collections.singletonList(wl1);

        DynamicWorkload dwl1 = new DynamicWorkload();
        dwl1.setDomainName("athenz").setServiceName("api").setIpAddresses(ipAddresses).setProvider("kubernetes").setUuid("1234-rsaq-422dcz")
                .setUpdateTime(Timestamp.fromMillis(123456789123L)).setHostname("testhost-1").setCertExpiryTime(Timestamp.fromMillis(123456789123L));
        List<DynamicWorkload> dynamicWorkloadList1 = Collections.singletonList(dwl1);

        StaticWorkload swl1 = new StaticWorkload();
        List<String> ipAddresses2 = Collections.singletonList("10.20.30.40");
        swl1.setDomainName("athenz")
                .setServiceName("api")
                .setIpAddresses(ipAddresses2)
                .setName("testhost-1")
                .setUpdateTime(Timestamp.fromMillis(123456789123L));
        List<StaticWorkload> staticWorkloadList1 = Collections.singletonList(swl1);

        workloads1.setWorkloadList(workloadList1);
        workloads1.setDynamicWorkloadList(dynamicWorkloadList1);
        workloads1.setStaticWorkloadList(staticWorkloadList1);

        assertNotNull(workloads1.getWorkloadList());
        assertNotNull(workloads1.getDynamicWorkloadList());
        assertNotNull(workloads1.getStaticWorkloadList());

        assertEquals(workloads1, workloads1);

        Workloads workloads2 = new Workloads();

        Workload wl2 = new Workload();
        wl2.setDomainName("athenz2").setServiceName("api2").setIpAddresses(ipAddresses).setProvider("kubernetes").setUuid("1234-rsaq-422dcz")
                .setUpdateTime(Timestamp.fromMillis(123456789123L)).setHostname("testhost-2").setCertExpiryTime(Timestamp.fromMillis(123456789123L));

        List<Workload> workloadList2 = Collections.singletonList(wl2);

        DynamicWorkload dwl2 = new DynamicWorkload();
        dwl2.setDomainName("athenz2").setServiceName("api2").setIpAddresses(ipAddresses).setProvider("kubernetes").setUuid("1234-rsaq-422dcz")
                .setUpdateTime(Timestamp.fromMillis(123456789123L)).setHostname("testhost-2").setCertExpiryTime(Timestamp.fromMillis(123456789123L));

        List<DynamicWorkload> dynamicWorkloadList2 = Collections.singletonList(dwl2);

        StaticWorkload swl2 = new StaticWorkload();
        swl2.setDomainName("athenz2")
                .setServiceName("api2")
                .setIpAddresses(ipAddresses2)
                .setName("testhost-2")
                .setUpdateTime(Timestamp.fromMillis(123456789123L));
        List<StaticWorkload> staticWorkloadList2 = Collections.singletonList(swl2);

        workloads2.setWorkloadList(workloadList2);
        workloads2.setDynamicWorkloadList(dynamicWorkloadList2);
        workloads2.setStaticWorkloadList(staticWorkloadList2);

        assertNotEquals(workloads1, workloads2);

        workloads2.setDynamicWorkloadList(dynamicWorkloadList1);
        assertNotEquals(workloads1, workloads2);

        workloads2.setStaticWorkloadList(staticWorkloadList1);
        assertNotEquals(workloads1, workloads2);

        workloads2.setWorkloadList(workloadList1);
        assertEquals(workloads1, workloads2);

        workloads2.setDynamicWorkloadList(null);
        assertNotEquals(workloads1, workloads2);

        workloads2.setDynamicWorkloadList(dynamicWorkloadList1);
        workloads2.setStaticWorkloadList(null);
        assertNotEquals(workloads1, workloads2);

        // for code coverage
        assertFalse(workloads1.equals("anotherstring"));

        assertNotEquals(workloads1, null);
        assertNotEquals(workloads1, "mystring");
    }
}