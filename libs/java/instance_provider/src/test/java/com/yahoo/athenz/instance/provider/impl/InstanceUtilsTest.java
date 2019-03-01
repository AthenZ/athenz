/*
 * Copyright 2018 Oath, Inc.
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
package com.yahoo.athenz.instance.provider.impl;

import org.testng.annotations.Test;

import java.util.HashMap;

import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;

public class InstanceUtilsTest {

    @Test
    public void testGetInstanceProperty() {

        assertNull(InstanceUtils.getInstanceProperty(null,  "cloudAccount"));

        HashMap<String, String> attributes = new HashMap<>();
        assertNull(InstanceUtils.getInstanceProperty(attributes,  "cloudAccount"));

        attributes.put("testAccount", "1235");
        assertNull(InstanceUtils.getInstanceProperty(attributes,  "cloudAccount"));

        attributes.put("cloudAccount", "1235");
        assertEquals(InstanceUtils.getInstanceProperty(attributes,  "cloudAccount"), "1235");
    }

    @Test
    public void testValidateCertRequestHostnamesNullSuffix() {
        assertFalse(InstanceUtils.validateCertRequestHostnames(null,  null,  null,  null, null));
    }

    @Test
    public void testValidateCertRequestHostnamesEmptySuffix() {
        assertFalse(InstanceUtils.validateCertRequestHostnames(null,  null,  null,  "", null));
    }

    @Test
    public void testValidateCertRequestHostnamesInvalidCount() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "service.athenz.athenz.cloud,service2.athenz.athenz.cloud,service3.athenz.athenz.cloud");

        assertFalse(InstanceUtils.validateCertRequestHostnames(attributes, "athenz", "api",  "athenz.cloud", null));
    }

    @Test
    public void testValidateCertRequestHostnamesInvalidInstanceId() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz2.cloud");

        StringBuilder id = new StringBuilder(256);
        assertFalse(InstanceUtils.validateCertRequestHostnames(attributes, "athenz", "api",  "athenz.cloud", id));
    }

    @Test
    public void testValidateCertRequestHostnamesInvalidHost() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "storage.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");

        StringBuilder id = new StringBuilder(256);
        assertFalse(InstanceUtils.validateCertRequestHostnames(attributes, "athenz", "api",  "athenz.cloud", id));
    }

    @Test
    public void testValidateCertRequestHostnamesMissingInstanceId() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz.athenz.cloud,api.athenz.athenz.cloud");

        StringBuilder id = new StringBuilder(256);
        assertFalse(InstanceUtils.validateCertRequestHostnames(attributes, "athenz", "api",  "athenz.cloud", id));
    }

    @Test
    public void testValidateCertRequestHostnamesMissingHost() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "i-1234.instanceid.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");

        StringBuilder id = new StringBuilder(256);
        assertFalse(InstanceUtils.validateCertRequestHostnames(attributes, "athenz", "api",  "athenz.cloud", id));
    }

    @Test
    public void testValidateCertRequestHostnames() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        StringBuilder id = new StringBuilder(256);
        assertTrue(InstanceUtils.validateCertRequestHostnames(attributes, "athenz", "api", "athenz.cloud", id));
        assertEquals(id.toString(), "i-1234");
    }

    @Test
    public void testValidateCertRequestHostnamesWithInstanceIdURI() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz.athenz.cloud");
        attributes.put("sanURI", "spiffe://athenz/sa/cloud,athenz://instanceid/zts/i-1234");
        StringBuilder id = new StringBuilder(256);
        assertTrue(InstanceUtils.validateCertRequestHostnames(attributes, "athenz", "api", "athenz.cloud", id));
        assertEquals(id.toString(), "i-1234");
    }

    @Test
    public void testValidateCertRequestHostnamesWithInvalidInstanceIdURI() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz.athenz.cloud");
        attributes.put("sanURI", "spiffe://athenz/sa/cloud,athenz://instanceid/zts");
        StringBuilder id = new StringBuilder(256);
        assertFalse(InstanceUtils.validateCertRequestHostnames(attributes, "athenz", "api", "athenz.cloud", id));
    }

    @Test
    public void testValidateCertRequestHostnamesNullHostnames() {
        HashMap<String, String> attributes = new HashMap<>();
        StringBuilder id = new StringBuilder(256);
        assertFalse(InstanceUtils.validateCertRequestHostnames(attributes, "athenz", "api", "athenz.cloud", id));
    }

    @Test
    public void testValidateCertRequestHostnamesEmptyHostnames() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "");
        StringBuilder id = new StringBuilder(256);
        assertFalse(InstanceUtils.validateCertRequestHostnames(attributes, "athenz", "api", "athenz.cloud", id));
    }

}
