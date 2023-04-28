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
package com.yahoo.athenz.instance.provider.impl;

import org.testng.annotations.Test;

import java.util.*;

import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;

public class InstanceUtilsTest {

    @Test
    public void testClassConstructor() {
        InstanceUtils utils = new InstanceUtils();
        assertNull(utils.getInstanceProperty(null,  "cloudAccount"));
    }

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
        assertFalse(InstanceUtils.validateCertRequestSanDnsNames(null,  null,  null,  null,
                null, null, false, new StringBuilder(256)));
    }

    @Test
    public void testValidateCertRequestHostnamesEmptySuffix() {
        assertFalse(InstanceUtils.validateCertRequestSanDnsNames(null,  null,  null,
                Collections.emptySet(), null, null, false, new StringBuilder(256)));
    }

    @Test
    public void testValidateCertRequestHostnamesInvalidCount() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "service.athenz.athenz.cloud,service2.athenz.athenz.cloud,service3.athenz.athenz.cloud");

        assertFalse(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, null, false, new StringBuilder(256)));
    }

    @Test
    public void testValidateCertRequestHostnamesInvalidInstanceId() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz2.cloud");

        assertFalse(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, null, false, new StringBuilder(256)));
    }

    @Test
    public void testValidateCertRequestHostnamesInvalidHost() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "storage.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");

        assertFalse(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, null, false, new StringBuilder(256)));
    }

    @Test
    public void testValidateCertRequestHostnamesMissingInstanceId() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz.athenz.cloud,api.athenz.athenz.cloud");

        assertFalse(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, null, false, new StringBuilder(256)));
    }

    @Test
    public void testValidateCertRequestHostnamesMissingHost() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "i-1234.instanceid.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");

        assertFalse(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, null, false, new StringBuilder(256)));
    }

    @Test
    public void testValidateCertRequestHostnames() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        StringBuilder id = new StringBuilder(256);
        assertTrue(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, null, false, id));
        assertEquals(id.toString(), "i-1234");
    }

    @Test
    public void testValidateCertRequestHostnamesWithInstanceIdURI() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz.athenz.cloud");
        attributes.put("sanURI", "spiffe://athenz/sa/cloud,athenz://instanceid/zts/i-1234");
        StringBuilder id = new StringBuilder(256);
        assertTrue(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, null, false, id));
        assertEquals(id.toString(), "i-1234");
    }

    @Test
    public void testValidateCertRequestHostnamesWithInvalidInstanceIdURI() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz.athenz.cloud");
        attributes.put("sanURI", "spiffe://athenz/sa/cloud,athenz://instanceid/zts");
        StringBuilder id = new StringBuilder(256);
        assertFalse(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, null, false, id));
    }

    @Test
    public void testValidateCertRequestHostnamesWithEmptyInstanceIdURI() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz.athenz.cloud");
        attributes.put("sanURI", "spiffe://athenz/sa/cloud,athenz://instanceid/zts/");
        StringBuilder id = new StringBuilder(256);
        assertFalse(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, null, false, id));
    }

    @Test
    public void testValidateCertRequestHostnamesNullHostnames() {
        HashMap<String, String> attributes = new HashMap<>();
        StringBuilder id = new StringBuilder(256);
        assertFalse(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, null, false, id));
    }

    @Test
    public void testValidateCertRequestHostnamesEmptyHostnames() {
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "");
        StringBuilder id = new StringBuilder(256);
        assertFalse(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, null, false, id));
    }

    @Test
    public void testValidateCertRequestHostnamesInvalidHostname() {

        // first without hostname in the attributes, the request is valid

        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        StringBuilder id = new StringBuilder(256);
        assertTrue(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, null, true, id));
        assertEquals(id.toString(), "i-1234");

        // now let's set the hostname to a valid value and verify

        id.setLength(0);
        attributes.put("sanDNS", "api.athenz.athenz.cloud,i-1234.api.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        attributes.put("hostname", "i-1234.api.athenz.athenz.cloud");
        assertTrue(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, null, true, id));
        assertEquals(id.toString(), "i-1234");

        // now let's set the hostname to a non-matching value

        id.setLength(0);
        attributes.put("hostname", "i-1235.api2.athenz.athenz.cloud");
        assertFalse(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, null, true, id));
    }

    @Test
    public void testValidateCertRequestHostnamesOnlyInstanceId() {

        // with only instance id dns name, we should get failure

        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "i-1234.instanceid.athenz.athenz.cloud");
        StringBuilder id = new StringBuilder(256);
        assertFalse(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, null, true, id));

        // now let's set the hostname to a valid value and verify

        id.setLength(0);
        attributes.put("sanDNS", "i-1234.api.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        attributes.put("hostname", "i-1234.api.athenz.athenz.cloud");
        assertTrue(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, null, true, id));
        assertEquals(id.toString(), "i-1234");
    }

    @Test
    public void testDnsSuffixMatchIndex() {
        List<String> dnsSuffixes = Arrays.asList(".athenz.cloud", ".athenz.us");
        assertEquals(InstanceUtils.dnsSuffixMatchIndex("abc.athenz.cloud", dnsSuffixes), 3);
        assertEquals(InstanceUtils.dnsSuffixMatchIndex("test.athenz.us", dnsSuffixes), 4);
        assertEquals(InstanceUtils.dnsSuffixMatchIndex("test.athenza.cloud", dnsSuffixes), -1);
    }

    @Test
    public void testValidateSanDnsName() {
        List<String> dnsSuffixes = Arrays.asList(".athenz.cloud", ".athenz.us");

        assertFalse(InstanceUtils.validateSanDnsName("test.athenza.cloud", "api", dnsSuffixes, null, null));
        assertFalse(InstanceUtils.validateSanDnsName("test.api2.athenz.cloud", "api", dnsSuffixes, null, null));
        assertFalse(InstanceUtils.validateSanDnsName("test.api2.athenz.us", "api", dnsSuffixes, null, null));
        assertFalse(InstanceUtils.validateSanDnsName("api2.athenz.us", "api", dnsSuffixes, null, null));
        assertFalse(InstanceUtils.validateSanDnsName("api2.test.athenz.cloud", "api", dnsSuffixes, null, null));

        assertTrue(InstanceUtils.validateSanDnsName("api.athenz.cloud", "api", dnsSuffixes, null, null));
        assertTrue(InstanceUtils.validateSanDnsName("test.api.athenz.cloud", "api", dnsSuffixes, null, null));
        assertTrue(InstanceUtils.validateSanDnsName("test.api.test2.athenz.cloud", "api", dnsSuffixes, null, null));
        assertTrue(InstanceUtils.validateSanDnsName("api.test3.test2.athenz.cloud", "api", dnsSuffixes, null, null));
        assertTrue(InstanceUtils.validateSanDnsName("test.api.test3.test4.athenz.cloud", "api", dnsSuffixes, null, null));

        assertTrue(InstanceUtils.validateSanDnsName("api.athenz.us", "api", dnsSuffixes, null, null));
        assertTrue(InstanceUtils.validateSanDnsName("test.api.athenz.us", "api", dnsSuffixes, null, null));
        assertTrue(InstanceUtils.validateSanDnsName("test.api.test2.athenz.us", "api", dnsSuffixes, null, null));
        assertTrue(InstanceUtils.validateSanDnsName("api.test3.test2.athenz.us", "api", dnsSuffixes, null, null));
        assertTrue(InstanceUtils.validateSanDnsName("test.api.test3.test4.athenz.us", "api", dnsSuffixes, null, null));
    }

    @Test
    public void testValidateSanDnsNameWithK8SList() {

        System.setProperty("test-key", "svc.cluster.local,.pod.cluster.local");
        List<String> k8sDnsSuffixes = InstanceUtils.processK8SDnsSuffixList("test-key");

        List<String> dnsSuffixes = Arrays.asList(".athenz.cloud", ".athenz.us");
        assertFalse(InstanceUtils.validateSanDnsName("test.athenza.cloud", "api", dnsSuffixes, k8sDnsSuffixes, null));

        // now valid values

        assertTrue(InstanceUtils.validateSanDnsName("api.athenz.us", "api", dnsSuffixes, k8sDnsSuffixes, null));
        assertTrue(InstanceUtils.validateSanDnsName("pod-1.default.pod.cluster.local", "api", dnsSuffixes,
                k8sDnsSuffixes, null));

        System.clearProperty("test-key");
    }

    @Test
    public void testValidateSanDnsNameWithK8SClusterList() {

        assertFalse(InstanceUtils.validateSanDnsName("test.athenz.cloud", "api", Collections.emptyList(),
                null, null));
        assertFalse(InstanceUtils.validateSanDnsName("test.athenz.cloud", "api", Collections.emptyList(),
                null, Collections.emptySet()));
        Set<String> clusterNames = new HashSet<>();
        clusterNames.add("test.athenz1.cloud");
        assertFalse(InstanceUtils.validateSanDnsName("test.athenz.cloud", "api", Collections.emptyList(),
                null, clusterNames));

        // now valid values

        clusterNames.add("test.athenz.cloud");
        assertTrue(InstanceUtils.validateSanDnsName("test.athenz.cloud", "api", Collections.emptyList(),
                null, clusterNames));
    }

    @Test
    public void testProcessK8SDnsSuffixList() {

        // with null key we get an empty set

        List<String> k8sDnsSuffixes = InstanceUtils.processK8SDnsSuffixList("test-key");
        assertTrue(k8sDnsSuffixes.isEmpty());

        // set an empty string as the key

        System.setProperty("test-key", "");
        k8sDnsSuffixes = InstanceUtils.processK8SDnsSuffixList("test-key");
        assertTrue(k8sDnsSuffixes.isEmpty());

        // set an empty component in the value

        System.setProperty("test-key", ",,svc.cluster.local,");
        k8sDnsSuffixes = InstanceUtils.processK8SDnsSuffixList("test-key");
        assertEquals(k8sDnsSuffixes.size(), 1);
        assertEquals(k8sDnsSuffixes.get(0), ".svc.cluster.local");

        // set a value starting both with . and without

        System.setProperty("test-key", "svc.cluster.local,.pod.cluster.local");
        k8sDnsSuffixes = InstanceUtils.processK8SDnsSuffixList("test-key");
        assertEquals(k8sDnsSuffixes.size(), 2);
        assertEquals(k8sDnsSuffixes.get(0), ".svc.cluster.local");
        assertEquals(k8sDnsSuffixes.get(1), ".pod.cluster.local");

        System.clearProperty("test-key");
    }

    @Test
    public void testK8sDnsSuffixCheck() {

        // null and empty sets return false

        assertFalse(InstanceUtils.k8sDnsSuffixCheck("pod1.namespace.svc.cluster.local", null));
        assertFalse(InstanceUtils.k8sDnsSuffixCheck("pod1.namespace.svc.cluster.local", Collections.emptyList()));

        // test with actual values

        System.setProperty("test-key", "svc.cluster.local,.pod.cluster.local");
        List<String> k8sDnsSuffixes = InstanceUtils.processK8SDnsSuffixList("test-key");

        // 2 or more components are valid

        assertTrue(InstanceUtils.k8sDnsSuffixCheck("pod1.namespace.pod.cluster.local", k8sDnsSuffixes));
        assertTrue(InstanceUtils.k8sDnsSuffixCheck("svc1.subdomain.namespace.svc.cluster.local", k8sDnsSuffixes));

        // 1 or fewer components are invalid

        assertFalse(InstanceUtils.k8sDnsSuffixCheck("pod1.pod.cluster.local", k8sDnsSuffixes));
        assertFalse(InstanceUtils.k8sDnsSuffixCheck("svc1.svc.cluster.local", k8sDnsSuffixes));

        // different suffixes

        assertFalse(InstanceUtils.k8sDnsSuffixCheck("pod1.namespace.example.cluster.local", k8sDnsSuffixes));

        System.clearProperty("test-key");
    }

    @Test
    public void testValidateCertRequestSanDnsNamesWithClusterNames() {

        // with only instance id dns name, we should get failure

        StringBuilder id = new StringBuilder(256);
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz.cluster-us-west-2.athenz.cloud");
        attributes.put("sanURI", "athenz://instanceid/aws/id-1");
        assertFalse(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.io"), null, null, true, id));
        assertFalse(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.io"), null, Collections.emptyList(), true, id));

        // let's include a cluster name list without our cluster

        List<String> clusterNames = new ArrayList<>();
        clusterNames.add("cluster-us-east-1");
        assertFalse(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, clusterNames, true, id));

        // now finally let's add our cluster name

        clusterNames.add("cluster-us-west-2");
        assertTrue(InstanceUtils.validateCertRequestSanDnsNames(attributes, "athenz", "api",
                Collections.singleton("athenz.cloud"), null, clusterNames, true, id));
    }
}
