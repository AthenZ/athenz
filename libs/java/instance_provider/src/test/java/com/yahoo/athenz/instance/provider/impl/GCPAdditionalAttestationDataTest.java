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

package com.yahoo.athenz.instance.provider.impl;

import org.testng.annotations.Test;

import java.math.BigDecimal;

import static org.testng.Assert.*;

public class GCPAdditionalAttestationDataTest {
    @Test
    public void testFields() {
        GCPAdditionalAttestationData addAttestationData = new GCPAdditionalAttestationData();
        addAttestationData.setInstanceId("instanceid");
        addAttestationData.setInstanceName("myinstance");
        addAttestationData.setZone("us-west1-a");
        addAttestationData.setProjectId("project-123");
        addAttestationData.setInstanceCreationTimestamp(BigDecimal.valueOf(123456789099L));
        addAttestationData.setProjectNumber("12343");

        assertEquals(addAttestationData.getInstanceId(), "instanceid");
        assertEquals(addAttestationData.getInstanceName(), "myinstance");
        assertEquals(addAttestationData.getZone(), "us-west1-a");
        assertEquals(addAttestationData.getProjectId(), "project-123");
        assertEquals(addAttestationData.getInstanceCreationTimestamp().longValue(), 123456789099L);
        assertEquals(addAttestationData.getProjectNumber(), "12343");

    }
}