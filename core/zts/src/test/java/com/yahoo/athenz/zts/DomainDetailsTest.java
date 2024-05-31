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

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class DomainDetailsTest {

    @Test
    public void testDomainDetails() {

        DomainDetails dms1 = new DomainDetails()
                .setName("athenz")
                .setAwsAccount("aws-account")
                .setAzureSubscription("azure")
                .setAzureTenant("tenant")
                .setAzureClient("client")
                .setGcpProjectId("gcp-id")
                .setGcpProjectNumber("gcp-number");

        DomainDetails dms2 = new DomainDetails()
                .setName("athenz")
                .setAwsAccount("aws-account")
                .setAzureSubscription("azure")
                .setAzureTenant("tenant")
                .setAzureClient("client")
                .setGcpProjectId("gcp-id")
                .setGcpProjectNumber("gcp-number");

        assertEquals(dms1.getAwsAccount(), "aws-account");
        assertEquals(dms1.getGcpProjectId(), "gcp-id");
        assertEquals(dms1.getGcpProjectNumber(), "gcp-number");
        assertEquals(dms1.getName(), "athenz");
        assertEquals(dms1.getAzureSubscription(), "azure");
        assertEquals(dms1.getAzureTenant(), "tenant");
        assertEquals(dms1.getAzureClient(), "client");

        assertEquals(dms2, dms1);
        assertEquals(dms2, dms2);
        assertFalse(dms2.equals(null));

        dms2.setName("sports");
        assertNotEquals(dms2, dms1);
        dms2.setName(null);
        assertNotEquals(dms2, dms1);
        dms2.setName("athenz");
        assertEquals(dms2, dms1);

        dms2.setAwsAccount("aws2");
        assertNotEquals(dms2, dms1);
        dms2.setAwsAccount(null);
        assertNotEquals(dms2, dms1);
        dms2.setAwsAccount("aws-account");
        assertEquals(dms2, dms1);

        dms2.setAzureSubscription("azure2");
        assertNotEquals(dms2, dms1);
        dms2.setAzureSubscription(null);
        assertNotEquals(dms2, dms1);
        dms2.setAzureSubscription("azure");
        assertEquals(dms2, dms1);

        dms2.setAzureTenant("tenant2");
        assertNotEquals(dms2, dms1);
        dms2.setAzureTenant(null);
        assertNotEquals(dms2, dms1);
        dms2.setAzureTenant("tenant");
        assertEquals(dms2, dms1);

        dms2.setAzureClient("client2");
        assertNotEquals(dms2, dms1);
        dms2.setAzureClient(null);
        assertNotEquals(dms2, dms1);
        dms2.setAzureClient("client");
        assertEquals(dms2, dms1);

        dms2.setGcpProjectId("gcp2");
        assertNotEquals(dms2, dms1);
        dms2.setGcpProjectId(null);
        assertNotEquals(dms2, dms1);
        dms2.setGcpProjectId("gcp-id");
        assertEquals(dms2, dms1);

        dms2.setGcpProjectNumber("gcp2");
        assertNotEquals(dms2, dms1);
        dms2.setGcpProjectNumber(null);
        assertNotEquals(dms2, dms1);
        dms2.setGcpProjectNumber("gcp-number");
        assertEquals(dms2, dms1);
    }
}
