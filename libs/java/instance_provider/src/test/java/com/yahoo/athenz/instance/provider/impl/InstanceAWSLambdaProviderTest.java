/*
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
package com.yahoo.athenz.instance.provider.impl;

import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;

import java.util.HashMap;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.instance.provider.InstanceConfirmation;

public class InstanceAWSLambdaProviderTest {
    
    @BeforeMethod
    public void setup() {
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz.cloud");
    }
    
    @AfterMethod
    public void shutdown() {
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
    }
    
    @Test
    public void testInitializeDefaults() {
        InstanceAWSLambdaProvider provider = new InstanceAWSLambdaProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSLambdaProvider", null);
        assertNull(provider.awsPublicKey);
        assertEquals(provider.bootTimeOffset, 300000);
        provider.close();
    }
    
    @Test
    public void testInitialize() {
        
        InstanceAWSLambdaProvider provider = new InstanceAWSLambdaProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        System.setProperty(InstanceAWSProvider.AWS_PROP_BOOT_TIME_OFFSET, "60");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSLambdaProvider", null);
        assertNotNull(provider.awsPublicKey);
        assertEquals(provider.bootTimeOffset, 60000);
        provider.close();
        System.clearProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT);
        System.clearProperty(InstanceAWSProvider.AWS_PROP_BOOT_TIME_OFFSET);
    }
    
    @Test
    public void testConfirmInstanceEmptyDocument() {
        
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz.cloud");
        MockInstanceAWSLambdaProvider provider = new MockInstanceAWSLambdaProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSLambdaProvider", null);
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"\",\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("cloudAccount", "1234");
        attributes.put("sanDNS", "service.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        confirmation.setAttributes(attributes);
        
        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertEquals(result.getAttributes().get("certUsage"), "client");
        assertEquals(result.getDomain(), "athenz");
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
    }
    
    @Test
    public void testConfirmInstanceNullDocument() {
        
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz.cloud");
        MockInstanceAWSLambdaProvider provider = new MockInstanceAWSLambdaProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSLambdaProvider", null);
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("cloudAccount", "1234");
        attributes.put("sanDNS", "service.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        confirmation.setAttributes(attributes);
        
        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertEquals(result.getAttributes().get("certUsage"), "client");
        assertEquals(result.getDomain(), "athenz");
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
    }
    
    @Test
    public void testValidateCertRequestHostnamesNullSuffix() {
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
        InstanceAWSLambdaProvider provider = new InstanceAWSLambdaProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSLambdaProvider", null);

        assertFalse(provider.validateCertRequestHostnames(null,  null,  null,  null));
        provider.close();
    }
    
    @Test
    public void testValidateCertRequestHostnamesEmptySuffix() {
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "");
        InstanceAWSLambdaProvider provider = new InstanceAWSLambdaProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSLambdaProvider", null);

        assertFalse(provider.validateCertRequestHostnames(null,  null,  null,  null));
        provider.close();
    }
    
    @Test
    public void testValidateCertRequestHostnamesNullHostnames() {
        InstanceAWSLambdaProvider provider = new InstanceAWSLambdaProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSLambdaProvider", null);
        
        HashMap<String, String> attributes = new HashMap<>();
        StringBuilder id = new StringBuilder(256);
        assertFalse(provider.validateCertRequestHostnames(attributes, "athenz", "api", id));
        provider.close();
    }
    
    @Test
    public void testValidateCertRequestHostnamesEmptyHostnames() {
        InstanceAWSLambdaProvider provider = new InstanceAWSLambdaProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSLambdaProvider", null);
        
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "");
        StringBuilder id = new StringBuilder(256);
        assertFalse(provider.validateCertRequestHostnames(attributes, "athenz", "api", id));
        provider.close();
    }
    
    @Test
    public void testValidateCertRequestHostnamesInvalidHost() {
        InstanceAWSLambdaProvider provider = new InstanceAWSLambdaProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSLambdaProvider", null);
        
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "storage.athenz.athenz.cloud");
        
        StringBuilder id = new StringBuilder(256);
        assertFalse(provider.validateCertRequestHostnames(attributes, "athenz", "api",  id));
        provider.close();
    }
    
    @Test
    public void testValidateCertRequestHostnames() {
        InstanceAWSLambdaProvider provider = new InstanceAWSLambdaProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSLambdaProvider", null);
        
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        StringBuilder id = new StringBuilder(256);
        assertTrue(provider.validateCertRequestHostnames(attributes, "athenz", "api", id));
        provider.close();
    }
    
    @Test
    public void testValidateCertRequestHostnamesSubdomain() {
        InstanceAWSLambdaProvider provider = new InstanceAWSLambdaProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSLambdaProvider", null);
        
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz-platforms.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        StringBuilder id = new StringBuilder(256);
        assertTrue(provider.validateCertRequestHostnames(attributes, "athenz.platforms", "api", id));
        provider.close();
    }
}
