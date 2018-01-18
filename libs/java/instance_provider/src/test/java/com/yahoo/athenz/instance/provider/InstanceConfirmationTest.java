/**
 * Copyright 2018 Yahoo Holdings, Inc.
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

import static org.testng.Assert.assertTrue;

import java.util.HashMap;

import static org.testng.Assert.assertFalse;

public class InstanceConfirmationTest {

    @SuppressWarnings("unlikely-arg-type")
    @Test
    public void testInstanceConfirmationEquals() {
        InstanceConfirmation confirm = new InstanceConfirmation();
        assertTrue(confirm.equals(confirm));
        assertFalse(confirm.equals(null));
        assertFalse(confirm.equals("invalid-class"));

        InstanceConfirmation confirm2 = new InstanceConfirmation();
        assertTrue(confirm.equals(confirm2));

        confirm.setAttestationData("data");
        assertFalse(confirm.equals(confirm2));
        confirm2.setAttestationData("data-fail");
        assertFalse(confirm.equals(confirm2));
        confirm2.setAttestationData("data");
        assertTrue(confirm.equals(confirm2));

        confirm.setDomain("domain");
        assertFalse(confirm.equals(confirm2));
        confirm2.setDomain("domain-fail");
        assertFalse(confirm.equals(confirm2));
        confirm2.setDomain("domain");
        assertTrue(confirm.equals(confirm2));

        confirm.setService("service");
        assertFalse(confirm.equals(confirm2));
        confirm2.setService("service-fail");
        assertFalse(confirm.equals(confirm2));
        confirm2.setService("service");
        assertTrue(confirm.equals(confirm2));
        
        confirm.setProvider("provider");
        assertFalse(confirm.equals(confirm2));
        confirm2.setProvider("provider-fail");
        assertFalse(confirm.equals(confirm2));
        confirm2.setProvider("provider");
        assertTrue(confirm.equals(confirm2));
        
        HashMap<String, String> attributes = new HashMap<>();
        confirm.setAttributes(attributes);
        assertFalse(confirm.equals(confirm2));
        HashMap<String, String> attributes2 = new HashMap<>();
        attributes2.put("key", "value");
        confirm2.setAttributes(attributes2);
        assertFalse(confirm.equals(confirm2));
        attributes.put("key", "value");
        assertTrue(confirm.equals(confirm2));
    }
}
