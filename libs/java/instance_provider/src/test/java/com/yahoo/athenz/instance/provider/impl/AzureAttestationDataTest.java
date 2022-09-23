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
package com.yahoo.athenz.instance.provider.impl;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

public class AzureAttestationDataTest {

    @Test
    public void testAzureAttestationData() {
        AzureAttestationData data = new AzureAttestationData();
        data.setLocation("location");
        data.setName("name");
        data.setResourceGroupName("resource-group-name");
        data.setSubscriptionId("sub-id");
        data.setVmId("vm-id");
        data.setToken("token");
        
        assertEquals(data.getLocation(), "location");
        assertEquals(data.getName(), "name");
        assertEquals(data.getResourceGroupName(), "resource-group-name");
        assertEquals(data.getSubscriptionId(), "sub-id");
        assertEquals(data.getVmId(), "vm-id");
        assertEquals(data.getToken(), "token");
    }
}
