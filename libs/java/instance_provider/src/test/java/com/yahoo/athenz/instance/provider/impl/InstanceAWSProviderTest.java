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

import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.util.HashMap;
import java.util.Map;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.instance.provider.AWSAttestationValidator;
import com.yahoo.athenz.instance.provider.AWSAttestationValidatorFactory;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.ProviderResourceException;

import com.yahoo.rdl.Timestamp;

import javax.net.ssl.SSLContext;

public class InstanceAWSProviderTest {
    
    @BeforeMethod
    public void setup() {
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz.cloud");
        System.setProperty(InstanceAWSProvider.AWS_PROP_REGION_NAME, "us-west-2");
    }
    
    @AfterMethod
    public void shutdown() {
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
        System.clearProperty(InstanceAWSProvider.AWS_PROP_REGION_NAME);
    }
    
    @Test
    public void testInitializeDefaults() {
        InstanceAWSProvider provider = new InstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        assertEquals(provider.getTimeOffsetInMilli(), 300000);
        provider.close();
    }
    
    @Test
    public void testInitialize() {
        
        InstanceAWSProvider provider = new InstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        System.setProperty(InstanceAWSProvider.AWS_PROP_BOOT_TIME_OFFSET, "60");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        assertEquals(provider.getTimeOffsetInMilli(), 60000);
        provider.close();
        System.clearProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT);
        System.clearProperty(InstanceAWSProvider.AWS_PROP_BOOT_TIME_OFFSET);
    }

    @Test
    public void testInitializeDNSSuffix() {
        InstanceAWSProvider provider = new InstanceAWSProvider();
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        assertTrue(provider.dnsSuffixes.isEmpty());
        provider.close();

        provider = new InstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        assertTrue(provider.dnsSuffixes.isEmpty());
        provider.close();

        provider = new InstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz1.cloud,athenz2.cloud");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        assertEquals(provider.dnsSuffixes.size(), 2);
        assertTrue(provider.dnsSuffixes.contains("athenz1.cloud"));
        assertTrue(provider.dnsSuffixes.contains("athenz2.cloud"));
        provider.close();
    }

    @Test
    public void testError() {
        
        InstanceAWSProvider provider = new InstanceAWSProvider();
        ProviderResourceException exc = InstanceUtils.error("unable to access");
        assertEquals(exc.getCode(), 403);
        assertEquals(exc.getMessage(), "ResourceException (403): unable to access");
        provider.close();
    }
    
    @Test
    public void testValidateAWSAccount() {

        StringBuilder errMsg = new StringBuilder(256);
        InstanceAWSProvider provider = new InstanceAWSProvider();
        assertTrue(provider.validateAWSAccount("1234", "1234", errMsg));
        assertFalse(provider.validateAWSAccount("1235", "1234", errMsg));
        provider.close();
    }

    @Test
    public void testValidateAWSAccountMultipleAccounts() {

        StringBuilder errMsg = new StringBuilder(256);
        InstanceAWSProvider provider = new InstanceAWSProvider();
        assertTrue(provider.validateAWSAccount("1234,5678", "5678", errMsg));
        assertTrue(provider.validateAWSAccount("1234,5678", "1234", errMsg));
        assertFalse(provider.validateAWSAccount("1234,5678", "9999", errMsg));
        provider.close();
    }
    
    @Test
    public void testValidateAWSDocumentInvalidSignature() {

        StringBuilder errMsg = new StringBuilder(256);
        StringBuilder privateIp = new StringBuilder(64);

        InstanceAWSProvider provider = new InstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        
        AWSAttestationData data = new AWSAttestationData();
        data.setDocument("document");
        data.setSignature(null);
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2", data, "1234", "i-1234",
                true, privateIp, errMsg));
    }
    
    @Test
    public void testConfirmInstanceInvalidDocument() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"document\",\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        attributes.put("sanDNS", "service.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        confirmation.setAttributes(attributes);
        
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ignored) {
        }
    }
    
    @Test
    public void testConfirmInstanceInvalidHostnames() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"document\",\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        confirmation.setAttributes(attributes);
        
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ignored) {
        }
    }
    
    @Test
    public void testConfirmInstanceNoAccountId() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"document\",\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ignored) {
        }
    }
    
    @Test
    public void testConfirmInstanceServiceMismatch() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"document\",\"signature\": \"signature\",\"role\": \"athenz2.service\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        confirmation.setAttributes(attributes);
        
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ignored) {
        }
    }
    
    @Test
    public void testValidateAWSDocumentInvalidProvider() {
        
        StringBuilder errMsg = new StringBuilder(256);
        StringBuilder privateIp = new StringBuilder(64);

        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        
        AWSAttestationData data = new AWSAttestationData();
        data.setDocument("{\"accountId\": \"1234\"}");
        data.setSignature("signature");
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2",
                data, "1235", "i-1234", true, privateIp, errMsg));
    }
    
    @Test
    public void testValidateAWSDocumentInvalidAccountId() {
        
        StringBuilder errMsg = new StringBuilder(256);
        StringBuilder privateIp = new StringBuilder(64);

        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        
        AWSAttestationData data = new AWSAttestationData();
        data.setDocument("{\"accountId\": \"1234\",\"region\": \"us-west-2\"}");
        data.setSignature("signature");
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2",
                data, "1235", "i-1234", true, privateIp, errMsg));
    }
    
    @Test
    public void testValidateAWSDocumentInvalidInstanceId() {
        
        StringBuilder errMsg = new StringBuilder(256);
        StringBuilder privateIp = new StringBuilder(64);

        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
       
        AWSAttestationData data = new AWSAttestationData();
        data.setDocument("{\"accountId\": \"1234\",\"region\": \"us-west-2\",\"instanceId\": \"i-234\"}");
        data.setSignature("signature");
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2",
                data, "1234", "i-1234", true, privateIp, errMsg));
    }
    
    @Test
    public void testValidateAWSDocumentInvalidBootTime() {
        
        StringBuilder errMsg = new StringBuilder(256);
        StringBuilder privateIp = new StringBuilder(64);

        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        
        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 1000000).toString();
        AWSAttestationData data = new AWSAttestationData();
        data.setDocument("{\"accountId\": \"1234\",\"pendingTime\": \""
                + bootTime + "\",\"region\": \"us-west-2\",\"instanceId\": \"i-1234\"}");
        data.setSignature("signature");
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2", data,
                "1234", "i-1234", true, privateIp, errMsg));
    }
    
    @Test
    public void testValidateAWSDocument() {
        
        StringBuilder errMsg = new StringBuilder(256);
        StringBuilder privateIp = new StringBuilder(64);

        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        
        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 100).toString();
        AWSAttestationData data = new AWSAttestationData();
        data.setDocument("{\"accountId\": \"1234\",\"pendingTime\": \""
                + bootTime + "\",\"region\":\"us-west-2\",\"instanceId\": \"i-1234\"}");
        data.setSignature("signature");
        assertTrue(provider.validateAWSDocument("athenz.aws.us-west-2", data,
                "1234", "i-1234", true, privateIp, errMsg));
    }
    
    @Test
    public void testConfirmInstanceInvalidVerifyIdentity() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        provider.setIdentityResult(false);
        
        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 100).toString();
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"{\\\"accountId\\\": \\\"1234\\\",\\\"pendingTime\\\": \\\""
                        + bootTime + "\\\",\\\"region\\\": \\\"us-west-2\\\",\\\"instanceId\\\": \\\"i-1234\\\"}\","
                        + "\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("athenz.aws.us-west-2").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        attributes.put("sanDNS", "service.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        confirmation.setAttributes(attributes);
        
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ignored) {
        }
    }

    @Test
    public void testConfirmInstance() throws ProviderResourceException {
        testConfirmInstance("athenz.service");
        testConfirmInstance("service");
    }

    private void testConfirmInstance(final String service) throws ProviderResourceException {
        
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz.cloud");
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        
        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 100).toString();
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"{\\\"accountId\\\": \\\"1234\\\",\\\"pendingTime\\\": \\\""
                        + bootTime + "\\\",\\\"region\\\": \\\"us-west-2\\\",\\\"instanceId\\\": \\\"i-1234\\\","
                        + "\\\"privateIp\\\": \\\"10.10.10.11\\\"}\","
                        + "\"signature\": \"signature\",\"role\": \"" + service + "\"}")
                .setDomain("athenz").setProvider("athenz.aws.us-west-2").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        attributes.put("sanDNS", "service.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        confirmation.setAttributes(attributes);
        
        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertEquals(result.getDomain(), "athenz");
        Map<String, String> attrs = result.getAttributes();
        assertNotNull(attrs);
        assertEquals(attrs.get("certSSH"), "true");
        assertEquals(attrs.get("instancePrivateIp"), "10.10.10.11");
        assertNull(attrs.get("certExpiryTime"));
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
    }

    @Test
    public void testConfirmInstanceMultipleSANDNSes() throws ProviderResourceException {

        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz1.cloud,athenz2.cloud");
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");

        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);

        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 100).toString();
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"{\\\"accountId\\\": \\\"1234\\\",\\\"pendingTime\\\": \\\""
                        + bootTime + "\\\",\\\"region\\\": \\\"us-west-2\\\",\\\"instanceId\\\": \\\"i-1234\\\","
                        + "\\\"privateIp\\\": \\\"10.10.10.11\\\"}\","
                        + "\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("athenz.aws.us-west-2").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        attributes.put("sanDNS", "service.athenz.athenz1.cloud,service.athenz.athenz2.cloud,i-1234.instanceid.athenz.athenz1.cloud");
        confirmation.setAttributes(attributes);

        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertEquals(result.getDomain(), "athenz");
        Map<String, String> attrs = result.getAttributes();
        assertNotNull(attrs);
        assertEquals(attrs.get("certSSH"), "true");
        assertEquals(attrs.get("instancePrivateIp"), "10.10.10.11");
        assertNull(attrs.get("certExpiryTime"));
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
    }

    @Test
    public void testConfirmInstanceMultipleSANDNSesURIInstance() throws ProviderResourceException {

        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz1.cloud,athenz2.cloud");
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");

        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);

        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 100).toString();
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"{\\\"accountId\\\": \\\"1234\\\",\\\"pendingTime\\\": \\\""
                        + bootTime + "\\\",\\\"region\\\": \\\"us-west-2\\\",\\\"instanceId\\\": \\\"i-1234\\\","
                        + "\\\"privateIp\\\": \\\"10.10.10.11\\\"}\","
                        + "\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("athenz.aws.us-west-2").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        attributes.put("sanDNS", "service.athenz.athenz1.cloud,service.athenz.athenz2.cloud");
        attributes.put("sanURI", "athenz://instanceid/athenz.aws.us-west-2/i-1234");
        confirmation.setAttributes(attributes);

        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertEquals(result.getDomain(), "athenz");
        Map<String, String> attrs = result.getAttributes();
        assertNotNull(attrs);
        assertEquals(attrs.get("certSSH"), "true");
        assertEquals(attrs.get("instancePrivateIp"), "10.10.10.11");
        assertNull(attrs.get("certExpiryTime"));
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
    }

    @Test
    public void testConfirmInstanceEmptyDocument() {
        
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz.cloud");
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"\",\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        attributes.put("sanDNS", "service.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        confirmation.setAttributes(attributes);
        
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
    }
    
    @Test
    public void testConfirmInstanceNullDocument() throws ProviderResourceException {
        
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz.cloud");
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        attributes.put("sanDNS", "service.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        confirmation.setAttributes(attributes);
        
        InstanceConfirmation result = provider.confirmInstance(confirmation);
        Map<String, String> attrs = result.getAttributes();
        assertNotNull(attrs);
        assertEquals(attrs.get("certSSH"), "false");
        assertEquals(attrs.get("certExpiryTime"), Long.toString(7 * 24 * 60));
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
    }

    @Test
    public void testConfirmInstanceWithIPValidation() throws ProviderResourceException {

        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz.cloud");
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        System.setProperty(InstanceAWSProvider.AWS_PROP_VALIDATE_IP_ADDRESS, "true");
        System.setProperty(InstanceAWSProvider.AWS_PROP_ALLOWED_IP_ADDRESSES, "10.0.0.0/8");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);

        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 100).toString();
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"{\\\"accountId\\\": \\\"1234\\\",\\\"pendingTime\\\": \\\""
                        + bootTime + "\\\",\\\"region\\\": \\\"us-west-2\\\",\\\"instanceId\\\": \\\"i-1234\\\","
                        + "\\\"privateIp\\\": \\\"10.10.10.11\\\"}\","
                        + "\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("athenz.aws.us-west-2").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        attributes.put("sanDNS", "service.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        attributes.put("sanIP", "10.10.10.11");
        confirmation.setAttributes(attributes);

        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertEquals(result.getDomain(), "athenz");
        Map<String, String> attrs = result.getAttributes();
        assertNotNull(attrs);
        assertEquals(attrs.get("certSSH"), "true");
        assertEquals(attrs.get("instancePrivateIp"), "10.10.10.11");
        assertNull(attrs.get("certExpiryTime"));
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
        System.clearProperty(InstanceAWSProvider.AWS_PROP_VALIDATE_IP_ADDRESS);
        System.clearProperty(InstanceAWSProvider.AWS_PROP_ALLOWED_IP_ADDRESSES);
    }

    @Test
    public void testConfirmInstanceWithIPValidationFailure() throws ProviderResourceException {

        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz.cloud");
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        System.setProperty(InstanceAWSProvider.AWS_PROP_VALIDATE_IP_ADDRESS, "true");
        System.setProperty(InstanceAWSProvider.AWS_PROP_ALLOWED_IP_ADDRESSES, "172.16.0.0/12");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);

        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 100).toString();
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"{\\\"accountId\\\": \\\"1234\\\",\\\"pendingTime\\\": \\\""
                        + bootTime + "\\\",\\\"region\\\": \\\"us-west-2\\\",\\\"instanceId\\\": \\\"i-1234\\\","
                        + "\\\"privateIp\\\": \\\"10.10.10.11\\\"}\","
                        + "\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("athenz.aws.us-west-2").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        attributes.put("sanDNS", "service.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        attributes.put("sanIP", "10.10.10.12");
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Certificate IP address validation failed for: 10.10.10.12"));
        }

        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
        System.clearProperty(InstanceAWSProvider.AWS_PROP_VALIDATE_IP_ADDRESS);
        System.clearProperty(InstanceAWSProvider.AWS_PROP_ALLOWED_IP_ADDRESSES);
    }

    @Test
    public void testProviderScheme() {
        InstanceAWSProvider provider = new InstanceAWSProvider();
        assertEquals(provider.getProviderScheme(), InstanceProvider.Scheme.CLASS);
        provider.close();
    }

    @Test
    public void testSetAuthorizer() {
        InstanceAWSProvider provider = new InstanceAWSProvider();
        Authorizer authorizer = (action, resource, principal, crossDomain) -> true;
        provider.setAuthorizer(authorizer);
        assertEquals(provider.authorizer, authorizer);
        provider.close();
    }

    @Test
    public void testDefaultAttestationValidatorFactory() {
        InstanceAWSProvider provider = new InstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        assertNotNull(provider.attestationValidator);
        assertTrue(provider.attestationValidator instanceof CompositeAWSAttestationValidator);
        provider.close();
    }

    @Test
    public void testCustomAttestationValidatorFactory() {
        System.setProperty(InstanceAWSProvider.AWS_PROP_ATTESTATION_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.InstanceAWSProviderTest$TestAttestationValidatorFactory");
        InstanceAWSProvider provider = new InstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        assertTrue(provider.attestationValidator instanceof TestAttestationValidator);
        provider.close();
        System.clearProperty(InstanceAWSProvider.AWS_PROP_ATTESTATION_VALIDATOR_FACTORY_CLASS);
    }

    @Test
    public void testInvalidAttestationValidatorFactory() {
        System.setProperty(InstanceAWSProvider.AWS_PROP_ATTESTATION_VALIDATOR_FACTORY_CLASS,
                "com.yahoo.athenz.instance.provider.impl.UnknownValidatorFactoryClass");
        InstanceAWSProvider provider = new InstanceAWSProvider();
        try {
            provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Invalid AWS attestation validator factory class"));
        }
        provider.close();
        System.clearProperty(InstanceAWSProvider.AWS_PROP_ATTESTATION_VALIDATOR_FACTORY_CLASS);
    }

    public static class TestAttestationValidator implements AWSAttestationValidator {
        @Override
        public void initialize(SSLContext sslContext, Authorizer authorizer) {
        }
        @Override
        public boolean validateIdentity(InstanceConfirmation confirmation, AWSAttestationData info,
                String awsAccount, StringBuilder errMsg) {
            return true;
        }
    }

    public static class TestAttestationValidatorFactory implements AWSAttestationValidatorFactory {
        @Override
        public AWSAttestationValidator create(SSLContext sslContext, Authorizer authorizer) {
            AWSAttestationValidator validator = new TestAttestationValidator();
            validator.initialize(sslContext, authorizer);
            return validator;
        }
    }

    @Test
    public void testValidateAWSDocumentFailures() {
        
        StringBuilder errMsg = new StringBuilder(256);
        StringBuilder privateIp = new StringBuilder(64);

        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);

        // no signature
        
        AWSAttestationData data = new AWSAttestationData();
        data.setDocument("document");
        data.setSignature(null);
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2", data,
                "awsAccount", "instanceId", true, privateIp, errMsg));
        
        // unable to parse
        
        data.setDocument("document");
        data.setSignature("signature");
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2", data,
                "awsAccount", "instanceId", true, privateIp, errMsg));
    }
    
    @Test
    public void testValidateAWSInstanceId() {
        
        StringBuilder errMsg = new StringBuilder(256);

        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        assertFalse(provider.validateAWSInstanceId("1234", "12345", errMsg));
        assertFalse(provider.validateAWSInstanceId("1234", null, errMsg));
        assertTrue(provider.validateAWSInstanceId("1234", "1234", errMsg));
    }
    
    @Test
    public void testValidateAWSProvider() {

        StringBuilder errMsg = new StringBuilder(256);

        InstanceAWSProvider provider = new InstanceAWSProvider();
        assertFalse(provider.validateAWSProvider("provider", null, errMsg));
        assertFalse(provider.validateAWSProvider("athenz.aws.us-east-1", "", errMsg));
        assertFalse(provider.validateAWSProvider("athenz.aws.us-east-1", "us-west-2", errMsg));
        assertFalse(provider.validateAWSProvider("athenz.awsus-west-2", "us-west-2", errMsg));
        assertTrue(provider.validateAWSProvider("athenz.aws.us-west-2", "us-west-2", errMsg));
    }

    @Test
    public void testEmptyRefreshAttestationData() {
        InstanceAWSProvider provider = new InstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        try {
            provider.refreshInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.NOT_FOUND);
        }

        confirmation.setAttestationData("");
        try {
            provider.refreshInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.NOT_FOUND);
        }
    }

    @Test
    public void testRefreshInstance() throws ProviderResourceException {
        testRefreshInstance("athenz.service");
        testRefreshInstance("service");
    }

    private void testRefreshInstance(final String serviceName) throws ProviderResourceException {
        
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz.cloud");
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        
        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 100).toString();
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"{\\\"accountId\\\": \\\"1234\\\",\\\"pendingTime\\\": \\\""
                        + bootTime + "\\\",\\\"region\\\": \\\"us-west-2\\\",\\\"instanceId\\\": \\\"i-1234\\\"}\","
                        + "\"signature\": \"signature\",\"role\": \"" + serviceName + "\"}")
                .setDomain("athenz").setProvider("athenz.aws.us-west-2").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        attributes.put("sanDNS", "service.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        attributes.put("instanceId", "i-1234");
        confirmation.setAttributes(attributes);
        
        InstanceConfirmation result = provider.refreshInstance(confirmation);
        assertEquals(result.getDomain(), "athenz");
        assertNull(result.getAttributes().get("certExpiryTime"));
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
    }

    @Test
    public void testRefreshInstanceInvalidSignature() {

        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz.cloud");
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        provider.setSignatureResult(false);

        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 100).toString();
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"{\\\"accountId\\\": \\\"1234\\\",\\\"pendingTime\\\": \\\""
                        + bootTime + "\\\",\\\"region\\\": \\\"us-west-2\\\",\\\"instanceId\\\": \\\"i-1234\\\"}\","
                        + "\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("athenz.aws.us-west-2").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        attributes.put("sanDNS", "service.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        attributes.put("instanceId", "i-1234");
        confirmation.setAttributes(attributes);

        try {
            provider.refreshInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
    }

    @Test
    public void testRefreshInstanceNoDocument() throws ProviderResourceException {

        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz.cloud");
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");

        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        provider.setSignatureResult(false);

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("athenz.aws.us-west-2").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        attributes.put("sanDNS", "service.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        attributes.put("instanceId", "i-1234");
        confirmation.setAttributes(attributes);

        InstanceConfirmation result = provider.refreshInstance(confirmation);
        assertEquals(result.getDomain(), "athenz");
        assertEquals(result.getAttributes().get("certExpiryTime"), Long.toString(7 * 24 * 60));
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
    }

    @Test
    public void testRefreshInstanceNoAccountId() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"document\",\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        
        try {
            provider.refreshInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }
    
    @Test
    public void testRefreshInstanceServiceMismatch() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"document\",\"signature\": \"signature\",\"role\": \"athenz2.service\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        attributes.put("instanceId", "i-1234");
        confirmation.setAttributes(attributes);
        
        try {
            provider.refreshInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testRefreshInstanceMissingInstanceId() {

        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);

        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 100).toString();
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"{\\\"accountId\\\": \\\"1234\\\",\\\"pendingTime\\\": \\\""
                        + bootTime + "\\\",\\\"region\\\": \\\"us-west-2\\\",\\\"instanceId\\\": \\\"i-1234\\\"}\","
                        + "\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("athenz.aws.us-west-2").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        attributes.put("sanDNS", "service.athenz.athenz.cloud");
        confirmation.setAttributes(attributes);

        try {
            provider.refreshInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testRefreshInstanceInvalidVerifyIdentity() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider", null, null);
        provider.setIdentityResult(false);
        
        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 100).toString();
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"{\\\"accountId\\\": \\\"1234\\\",\\\"pendingTime\\\": \\\""
                        + bootTime + "\\\",\\\"region\\\": \\\"us-west-2\\\",\\\"instanceId\\\": \\\"i-1234\\\"}\","
                        + "\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("athenz.aws.us-west-2").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        attributes.put("instanceId", "i-1234");
        attributes.put("sanDNS", "service.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        confirmation.setAttributes(attributes);
        
        try {
            provider.refreshInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }
}
