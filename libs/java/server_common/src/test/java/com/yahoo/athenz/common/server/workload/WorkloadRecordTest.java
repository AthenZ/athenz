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

package com.yahoo.athenz.common.server.workload;

import org.testng.annotations.Test;

import java.util.Date;

import static org.testng.Assert.*;

public class WorkloadRecordTest {

    @Test
    public void testWorkloadRecord() {
        WorkloadRecord wr = new WorkloadRecord();
        wr.setService("athenz.api");
        wr.setIp("10.0.0.1");
        wr.setProvider("aws");
        wr.setInstanceId("afve-24dq2d");
        wr.setHostname("test-host1");
        Date date = new Date();
        wr.setCreationTime(date);
        wr.setUpdateTime(date);
        wr.setCertExpiryTime(date);

        assertEquals(wr.getService(), "athenz.api");
        assertEquals(wr.getIp(), "10.0.0.1");
        assertEquals(wr.getProvider(), "aws");
        assertEquals(wr.getInstanceId(), "afve-24dq2d");
        assertEquals(wr.getHostname(), "test-host1");
        assertEquals(wr.getCreationTime(), date);
        assertEquals(wr.getUpdateTime(), date);
        assertEquals(wr.getCertExpiryTime(), date);

        wr.setCreationTime(null);
        wr.setUpdateTime(null);
        wr.setCertExpiryTime(null);

        assertEquals(wr.toString(), "WorkloadRecord{service='athenz.api', provider='aws', instanceId='afve-24dq2d', ip='10.0.0.1', creationTime=null, updateTime=null, hostname='test-host1', certExpiryTime=null}");
    }
}