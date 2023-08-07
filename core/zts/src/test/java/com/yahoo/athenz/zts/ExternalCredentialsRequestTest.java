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

import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.*;

public class ExternalCredentialsRequestTest {

    @Test
    public void testExternalCredentialsRequest() {

        Map<String, String> attributes = new HashMap<>();
        ExternalCredentialsRequest request1 = new ExternalCredentialsRequest()
                .setClientId("athenz.gcp").setAttributes(attributes).setExpiryTime(3600);

        assertEquals(request1.getClientId(), "athenz.gcp");
        assertEquals(request1.getExpiryTime(), 3600);
        assertEquals(request1.getAttributes(), attributes);

        ExternalCredentialsRequest request2 = new ExternalCredentialsRequest()
                .setClientId("athenz.gcp").setAttributes(attributes).setExpiryTime(3600);

        assertEquals(request2, request1);
        assertEquals(request2, request2);
        assertFalse(request2.equals(null));

        Map<String, String> attributes2 = new HashMap<>();
        attributes2.put("key", "value");
        request2.setAttributes(attributes2);
        assertNotEquals(request2, request1);
        request2.setAttributes(null);
        assertNotEquals(request2, request1);
        request2.setAttributes(attributes);
        assertEquals(request2, request1);

        request2.setExpiryTime(1800);
        assertNotEquals(request2, request1);
        request2.setExpiryTime(null);
        assertNotEquals(request2, request1);
        request2.setExpiryTime(3600);
        assertEquals(request2, request1);

        request2.setClientId("athenz.aws");
        assertNotEquals(request2, request1);
        request2.setClientId(null);
        assertNotEquals(request2, request1);
        request2.setClientId("athenz.gcp");
        assertEquals(request2, request1);
    }
}
