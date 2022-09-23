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
package com.yahoo.athenz.instance.provider;

import org.testng.annotations.Test;

import java.util.HashMap;

import static org.testng.Assert.*;

public class InstanceConfirmationTest {

    @SuppressWarnings("unlikely-arg-type")
    @Test
    public void testInstanceConfirmationEquals() {
        InstanceConfirmation confirm = new InstanceConfirmation();
        assertEquals(confirm, confirm);
        //noinspection ConstantConditions,ObjectEqualsNull,SimplifiedTestNGAssertion
        assertFalse(confirm.equals(null));
        assertNotEquals("invalid-class", confirm);

        InstanceConfirmation confirm2 = new InstanceConfirmation();
        assertEquals(confirm, confirm2);

        confirm.setAttestationData("data");
        assertNotEquals(confirm, confirm2);
        confirm2.setAttestationData("data-fail");
        assertNotEquals(confirm, confirm2);
        confirm2.setAttestationData("data");
        assertEquals(confirm, confirm2);

        confirm.setDomain("domain");
        assertNotEquals(confirm, confirm2);
        confirm2.setDomain("domain-fail");
        assertNotEquals(confirm, confirm2);
        confirm2.setDomain("domain");
        assertEquals(confirm, confirm2);

        confirm.setService("service");
        assertNotEquals(confirm, confirm2);
        confirm2.setService("service-fail");
        assertNotEquals(confirm, confirm2);
        confirm2.setService("service");
        assertEquals(confirm, confirm2);
        
        confirm.setProvider("provider");
        assertNotEquals(confirm, confirm2);
        confirm2.setProvider("provider-fail");
        assertNotEquals(confirm, confirm2);
        confirm2.setProvider("provider");
        assertEquals(confirm, confirm2);
        
        HashMap<String, String> attributes = new HashMap<>();
        confirm.setAttributes(attributes);
        assertNotEquals(confirm, confirm2);
        HashMap<String, String> attributes2 = new HashMap<>();
        attributes2.put("key", "value");
        confirm2.setAttributes(attributes2);
        assertNotEquals(confirm, confirm2);
        attributes.put("key", "value");
        assertEquals(confirm, confirm2);
    }
}
