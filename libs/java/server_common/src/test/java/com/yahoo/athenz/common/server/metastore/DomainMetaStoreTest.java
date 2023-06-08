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
package com.yahoo.athenz.common.server.metastore;

import com.yahoo.athenz.common.server.metastore.impl.NoOpDomainMetaStoreFactory;
import org.testng.annotations.Test;

import java.util.ArrayList;

import static org.testng.Assert.*;

public class DomainMetaStoreTest {

    @Test
    public void testDomainMetaStoreDefaults() {

        DomainMetaStoreFactory metaStoreFactory = new NoOpDomainMetaStoreFactory();
        assertNotNull(metaStoreFactory);

        DomainMetaStore metaStore = metaStoreFactory.create(null);

        assertTrue(metaStore.isValidAzureSubscription("athenz", "azure"));
        assertTrue(metaStore.isValidAzureSubscription("athenz", null));

        assertTrue(metaStore.isValidGcpProject("athenz", "gcp"));
        assertTrue(metaStore.isValidGcpProject("athenz", null));

        assertTrue(metaStore.isValidAWSAccount("athenz", "aws"));
        assertTrue(metaStore.isValidAWSAccount("athenz", null));

        assertTrue(metaStore.isValidProductId("athenz", 42));
        assertTrue(metaStore.isValidProductId("athenz", (Integer) null));

        assertTrue(metaStore.isValidProductId("athenz", "abcd-42"));
        assertTrue(metaStore.isValidProductId("athenz", (String) null));

        assertTrue(metaStore.isValidBusinessService("athenz", "security"));
        assertTrue(metaStore.isValidBusinessService("athenz", null));

        assertEquals(metaStore.getValidBusinessServices(null), new ArrayList<>());
        assertEquals(metaStore.getValidBusinessServices("user"), new ArrayList<>());

        assertEquals(metaStore.getValidAWSAccounts(null), new ArrayList<>());
        assertEquals(metaStore.getValidAWSAccounts("user"), new ArrayList<>());

        assertEquals(metaStore.getValidAzureSubscriptions(null), new ArrayList<>());
        assertEquals(metaStore.getValidAzureSubscriptions("user"), new ArrayList<>());

        assertEquals(metaStore.getValidGcpProjects(null), new ArrayList<>());
        assertEquals(metaStore.getValidGcpProjects("user"), new ArrayList<>());

        assertEquals(metaStore.getValidProductIds(null), new ArrayList<>());
        assertEquals(metaStore.getValidProductIds("user"), new ArrayList<>());

        // these methods would throw no exceptions

        metaStore.setAzureSubscriptionDomain("athenz", "azure");
        metaStore.setGcpProjectDomain("athenz", "gcp");
        metaStore.setAWSAccountDomain("athenz", "aws");
        metaStore.setBusinessServiceDomain("athenz", "security");
        metaStore.setProductIdDomain("athenz", 42);
        metaStore.setProductIdDomain("athenz", "abcd-42");

        assertEquals(DomainMetaStore.META_ATTR_BUSINESS_SERVICE, 0);
        assertEquals(DomainMetaStore.META_ATTR_AWS_ACCOUNT, 1);
        assertEquals(DomainMetaStore.META_ATTR_AZURE_SUBSCRIPTION, 2);
        assertEquals(DomainMetaStore.META_ATTR_PRODUCT_NUMBER, 3);
        assertEquals(DomainMetaStore.META_ATTR_GCP_PROJECT, 4);
        assertEquals(DomainMetaStore.META_ATTR_PRODUCT_ID, 5);
    }
}
