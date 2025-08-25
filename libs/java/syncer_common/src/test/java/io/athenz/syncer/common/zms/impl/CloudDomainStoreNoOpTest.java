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
package io.athenz.syncer.common.zms.impl;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class CloudDomainStoreNoOpTest {

    private CloudDomainStoreNoOp cloudDomainStore;

    @BeforeMethod
    public void setUp() {
        cloudDomainStore = new CloudDomainStoreNoOp();
    }

    @Test
    public void testUploadDomain() {
        // Verify no exception is thrown
        cloudDomainStore.uploadDomain("test-domain", "{\"domain\":\"test-domain\"}");
    }

    @Test
    public void testDeleteDomain() {
        // Verify no exception is thrown
        cloudDomainStore.deleteDomain("test-domain");
    }

    @Test
    public void testUploadDomainWithNullValues() {
        // Verify no exception is thrown with null parameters
        cloudDomainStore.uploadDomain(null, null);
    }

    @Test
    public void testDeleteDomainWithNullValue() {
        // Verify no exception is thrown with null parameter
        cloudDomainStore.deleteDomain(null);
    }
}