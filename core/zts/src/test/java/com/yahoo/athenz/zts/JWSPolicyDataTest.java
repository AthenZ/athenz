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

public class JWSPolicyDataTest {

    @Test
    public void testJWSPolicyData() {

        Map<String, String> headers = new HashMap<>();
        JWSPolicyData jws1 = new JWSPolicyData()
                .setHeader(headers)
                .setPayload("payload")
                .setProtectedHeader("protectedHeader")
                .setSignature("signature");

        assertEquals(jws1.getHeader(), headers);
        assertEquals(jws1.getPayload(), "payload");
        assertEquals(jws1.getProtectedHeader(), "protectedHeader");
        assertEquals(jws1.getSignature(), "signature");

        JWSPolicyData jws2 = new JWSPolicyData()
                .setHeader(headers)
                .setPayload("payload")
                .setProtectedHeader("protectedHeader")
                .setSignature("signature");
        assertTrue(jws2.equals(jws1));
        assertTrue(jws2.equals(jws2));
        assertFalse(jws2.equals(null));

        jws2.setPayload("newpayload");
        assertFalse(jws2.equals(jws1));
        jws2.setPayload(null);
        assertFalse(jws2.equals(jws1));
        jws2.setPayload("payload");
        assertTrue(jws2.equals(jws1));

        jws2.setProtectedHeader("newprotectedHeader");
        assertFalse(jws2.equals(jws1));
        jws2.setProtectedHeader(null);
        assertFalse(jws2.equals(jws1));
        jws2.setProtectedHeader("protectedHeader");
        assertTrue(jws2.equals(jws1));

        jws2.setSignature("newsignature");
        assertFalse(jws2.equals(jws1));
        jws2.setSignature(null);
        assertFalse(jws2.equals(jws1));
        jws2.setSignature("signature");
        assertTrue(jws2.equals(jws1));

        Map<String, String> headers2 = new HashMap<>();
        headers2.put("key", "value");
        jws2.setHeader(headers2);
        assertFalse(jws2.equals(jws1));
        jws2.setHeader(null);
        assertFalse(jws2.equals(jws1));
        jws2.setHeader(headers);
        assertTrue(jws2.equals(jws1));
    }
}
