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

package com.yahoo.athenz.common.server.msd;

import com.yahoo.athenz.msd.Workload;
import com.yahoo.athenz.msd.WorkloadOptions;
import com.yahoo.rdl.Timestamp;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.List;

import static org.testng.Assert.assertEquals;

public class MsdStoreConnectionTest {

    class TestMsdStorageConnection implements MsdStoreConnection {
    }

    @Test
    public void testMsdStoreApi() {
        MsdStoreConnection msdStoreConnection = new TestMsdStorageConnection();

        Workload workload = new Workload();
        List<String> ipAddresses = Collections.singletonList("10.20.30.40");
        workload.setDomainName("athenz")
                .setServiceName("api")
                .setUuid("1234-rsaq-422dcz")
                .setIpAddresses(ipAddresses)
                .setHostname("testhost-1")
                .setProvider("kubernetes")
                .setUpdateTime(Timestamp.fromMillis(123456789123L))
                .setCertIssueTime(Timestamp.fromMillis(123456789120L))
                .setCertExpiryTime(Timestamp.fromMillis(123456789123L));

        msdStoreConnection.putWorkLoad(workload, new WorkloadOptions());

        List<Workload> workloadList = msdStoreConnection.getWorkloadsBySvc("athenz", "httpd");
        assertEquals(workloadList.size(), 0);

        workloadList = msdStoreConnection.getWorkloadsByIp("10.1.2.3");
        assertEquals(workloadList.size(), 0);
    }
}
