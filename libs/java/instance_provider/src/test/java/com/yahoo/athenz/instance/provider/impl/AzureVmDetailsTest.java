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

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class AzureVmDetailsTest {

    @Test
    public void testAzureVmDetails() {

        final String vmDetailsComplete =
                "{\n" +
                "  \"name\": \"athenz-client\",\n" +
                "  \"id\": \"/subscriptions/123456/resourceGroups/Athenz/providers/Microsoft.Compute/virtualMachines/athenz-client\",\n" +
                "  \"type\": \"Microsoft.Compute/virtualMachines\",\n" +
                "  \"location\": \"westus2\",\n" +
                "  \"tags\": {\n" +
                "    \"athenz\": \"athenz.backend\"\n" +
                "  },\n" +
                "  \"identity\": {\n" +
                "    \"type\": \"SystemAssigned, UserAssigned\",\n" +
                "    \"principalId\": \"111111-2222-3333-4444-555555555\",\n" +
                "    \"tenantId\": \"222222-3333-4444-5555-66666666\"\n" +
                "  },\n" +
                "  \"properties\": {\n" +
                "    \"vmId\": \"3333333-4444-5555-6666-77777777\",\n" +
                "    \"hardwareProfile\": {\n" +
                "      \"vmSize\": \"Standard_B1s\"\n" +
                "    },\n" +
                "    \"provisioningState\": \"Succeeded\"\n" +
                "  }\n" +
                "}";

        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        AzureVmDetails details = null;
        try {
            details = jsonMapper.readValue(vmDetailsComplete, AzureVmDetails.class);
        } catch (Exception ignored) {
        }

        assertNotNull(details);
        assertEquals(details.getLocation(), "westus2");
        assertEquals(details.getName(), "athenz-client");
        assertNotNull(details.getTags());
        assertEquals(details.getTags().getAthenz(), "athenz.backend");
        assertNotNull(details.getIdentity());
        assertEquals(details.getIdentity().getPrincipalId(), "111111-2222-3333-4444-555555555");
        assertEquals(details.getIdentity().getTenantId(), "222222-3333-4444-5555-66666666");
        assertNotNull(details.getProperties());
        assertEquals(details.getProperties().getVmId(), "3333333-4444-5555-6666-77777777");
    }

    @Test
    public void testAzureVmDetailsMissingIds() {

        final String vmDetailsMissingIds =
                "{\n" +
                "  \"name\": \"athenz-client\",\n" +
                "  \"type\": \"Microsoft.Compute/virtualMachines\",\n" +
                "  \"location\": \"westus2\",\n" +
                "  \"identity\": {\n" +
                "    \"type\": \"SystemAssigned, UserAssigned\",\n" +
                "    \"principalId\": \"111111-2222-3333-4444-555555555\",\n" +
                "    \"tenantId\": \"222222-3333-4444-5555-66666666\"\n" +
                "  },\n" +
                "  \"properties\": {\n" +
                "    \"hardwareProfile\": {\n" +
                "      \"vmSize\": \"Standard_B1s\"\n" +
                "    },\n" +
                "    \"provisioningState\": \"Succeeded\"\n" +
                "  }\n" +
                "}";

        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        AzureVmDetails details = null;
        try {
            details = jsonMapper.readValue(vmDetailsMissingIds, AzureVmDetails.class);
        } catch (Exception ignored) {
        }

        assertNotNull(details);
        assertEquals(details.getLocation(), "westus2");
        assertEquals(details.getName(), "athenz-client");
        assertNull(details.getTags());
        assertNotNull(details.getIdentity());
        assertEquals(details.getIdentity().getPrincipalId(), "111111-2222-3333-4444-555555555");
        assertEquals(details.getIdentity().getTenantId(), "222222-3333-4444-5555-66666666");
        assertNotNull(details.getProperties());
        assertNull(details.getProperties().getVmId());
    }
}
