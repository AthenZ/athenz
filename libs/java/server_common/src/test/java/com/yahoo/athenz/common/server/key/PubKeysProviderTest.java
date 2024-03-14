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

package com.yahoo.athenz.common.server.key;

import com.yahoo.athenz.zms.PublicKeyEntry;
import org.testng.annotations.Test;
import java.util.List;
import static org.testng.Assert.*;

public class PubKeysProviderTest {
    @Test
    public void testGetPubKeysByService() {
        PubKeysProvider pubKeysProvider = new PubKeysProvider() {
            @Override
            public List<PublicKeyEntry> getPubKeysByService(String domainName, String serviceName) {
                return List.of(new PublicKeyEntry().setKey("sample key").setId("0"));
            }
        };

        assertEquals(pubKeysProvider.getPubKeysByService("sports", "api").size(), 1);

        PubKeysProvider defaultPubKeysProvider = new PubKeysProvider() {};

        try {
            defaultPubKeysProvider.getPubKeysByService("sports", "api");
            fail();
        } catch (IllegalStateException e) {
        }
    }
}