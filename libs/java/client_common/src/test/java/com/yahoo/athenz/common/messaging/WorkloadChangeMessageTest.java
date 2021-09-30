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

package com.yahoo.athenz.common.messaging;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class WorkloadChangeMessageTest {

    @Test
    public void testDomainChange() {

        WorkloadChangeMessage workloadChangeMessage = new WorkloadChangeMessage()
                .setDomainName("athenz.examples")
                .setServiceName("httpd")
                .setMessageId("uuid123")
                .setObjectType(WorkloadChangeMessage.ObjectType.IP)
                .setPublished(123L);

        assertEquals(workloadChangeMessage.getDomainName(), "athenz.examples");
        assertEquals(workloadChangeMessage.getServiceName(), "httpd");
        assertEquals(workloadChangeMessage.getMessageId(), "uuid123");
        assertEquals(workloadChangeMessage.getPublished(), 123L);
        assertEquals(workloadChangeMessage.getObjectType(), WorkloadChangeMessage.ObjectType.IP);

        assertEquals(workloadChangeMessage, workloadChangeMessage);

        assertFalse(workloadChangeMessage.equals(null));
        assertFalse(workloadChangeMessage.equals("nonWorkloadChange"));

        WorkloadChangeMessage workloadChangeMessage1 = new WorkloadChangeMessage()
                .setDomainName("athenz.examples")
                .setServiceName("httpd")
                .setMessageId("uuid123")
                .setObjectType(WorkloadChangeMessage.ObjectType.IP)
                .setPublished(123L);

        assertEquals(workloadChangeMessage, workloadChangeMessage1);
        assertEquals(workloadChangeMessage.hashCode(), workloadChangeMessage1.hashCode());

        workloadChangeMessage1.setObjectType(WorkloadChangeMessage.ObjectType.HOSTNAME);
        assertNotEquals(workloadChangeMessage, workloadChangeMessage1);
    }
}
