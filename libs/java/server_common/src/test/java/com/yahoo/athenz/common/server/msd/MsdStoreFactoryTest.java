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

import com.yahoo.athenz.auth.PrivateKeyStore;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.testng.Assert.assertNotNull;

public class MsdStoreFactoryTest {
    @Test
    public void createTest() {
        MsdStore mockMsdStore = Mockito.mock(MsdStore.class);
        MsdStoreFactory factory = (PrivateKeyStore ks) -> mockMsdStore;

        PrivateKeyStore keyStore = new PrivateKeyStore() {};

        MsdStore msdStore = factory.create(keyStore);
        assertNotNull(msdStore);
    }
}
