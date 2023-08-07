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

import com.yahoo.rdl.Timestamp;
import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.*;

public class ExternalCredentialsResponseTest {

    @Test
    public void testExternalCredentialsResponse() {

        Map<String, String> attributes = new HashMap<>();
        ExternalCredentialsResponse response1 = new ExternalCredentialsResponse()
                .setAttributes(attributes).setExpiration(Timestamp.fromMillis(100));

        assertEquals(response1.getExpiration(), Timestamp.fromMillis(100));
        assertEquals(response1.getAttributes(), attributes);

        ExternalCredentialsResponse response2 = new ExternalCredentialsResponse()
                .setAttributes(attributes).setExpiration(Timestamp.fromMillis(100));

        assertEquals(response2, response1);
        assertEquals(response2, response2);
        assertFalse(response2.equals(null));

        Map<String, String> attributes2 = new HashMap<>();
        attributes2.put("key", "value");
        response2.setAttributes(attributes2);
        assertNotEquals(response2, response1);
        response2.setAttributes(null);
        assertNotEquals(response2, response1);
        response2.setAttributes(attributes);
        assertEquals(response2, response1);

        response2.setExpiration(Timestamp.fromMillis(200));
        assertNotEquals(response2, response1);
        response2.setExpiration(null);
        assertNotEquals(response2, response1);
        response2.setExpiration(Timestamp.fromMillis(100));
        assertEquals(response2, response1);
    }
}
