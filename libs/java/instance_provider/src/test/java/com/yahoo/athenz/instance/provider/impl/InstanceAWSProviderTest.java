/**
 * Copyright 2017 Yahoo Holdings, Inc.
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

import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.ResourceException;

import com.yahoo.rdl.Timestamp;

public class InstanceAWSProviderTest {
    
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
        InstanceAWSProvider provider = new InstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        assertNull(provider.awsPublicKey);
        assertEquals(provider.bootTimeOffset, 300000);
        provider.close();
    }
    
    @Test
    public void testInitialize() {
        
        InstanceAWSProvider provider = new InstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        System.setProperty(InstanceAWSProvider.AWS_PROP_BOOT_TIME_OFFSET, "60");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        assertNotNull(provider.awsPublicKey);
        assertEquals(provider.bootTimeOffset, 60000);
        provider.close();
        System.clearProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT);
        System.clearProperty(InstanceAWSProvider.AWS_PROP_BOOT_TIME_OFFSET);
    }
    
    @Test
    public void testError() {
        
        InstanceAWSProvider provider = new InstanceAWSProvider();
        ResourceException exc = provider.error("unable to access");
        assertEquals(exc.getCode(), 403);
        assertEquals(exc.getMessage(), "ResourceException (403): unable to access");
    }
    
    @Test
    public void testValidateAWSAccount() {
        
        StringBuilder errMsg = new StringBuilder(256);
        InstanceAWSProvider provider = new InstanceAWSProvider();
        assertTrue(provider.validateAWSAccount("1234", "1234", errMsg));
        assertFalse(provider.validateAWSAccount("1235", "1234", errMsg));
    }

    @Test
    public void testValidateAWSSignatureFailure() {
        
        StringBuilder errMsg = new StringBuilder(256);

        InstanceAWSProvider provider = new InstanceAWSProvider();
        assertFalse(provider.validateAWSSignature("document", null, errMsg));
        assertFalse(provider.validateAWSSignature("document", "", errMsg));
        
        // aws public key is null
        assertFalse(provider.validateAWSSignature("document", "signature", errMsg));
        
        provider = new InstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        assertFalse(provider.validateAWSSignature("document", "invalid-signature", errMsg));

        provider.close();
        System.clearProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT);
    }
    
    @Test
    public void testValidateAWSDocumentInvalidSignature() {
        
        StringBuilder errMsg = new StringBuilder(256);

        InstanceAWSProvider provider = new InstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2", "document", null, "1234", "i-1234", errMsg));
    }
    
    @Test
    public void testConfirmInstanceInvalidDocument() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
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
        } catch (ResourceException ex) {
        }
    }
    
    @Test
    public void testConfirmInstanceInvalidHostnames() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"document\",\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        confirmation.setAttributes(attributes);
        
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
        }
    }
    
    @Test
    public void testConfirmInstanceNoAccountId() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"document\",\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
        }
    }
    
    @Test
    public void testConfirmInstanceServiceMismatch() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"document\",\"signature\": \"signature\",\"role\": \"athenz2.service\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        confirmation.setAttributes(attributes);
        
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
        }
    }
    
    @Test
    public void testValidateAWSDocumentInvalidProvider() {
        
        StringBuilder errMsg = new StringBuilder(256);

        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2", "{\"accountId\": \"1234\"}",
                "signature", "1235", "i-1234", errMsg));
    }
    
    @Test
    public void testValidateAWSDocumentInvalidAccountId() {
        
        StringBuilder errMsg = new StringBuilder(256);

        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2",
                "{\"accountId\": \"1234\",\"region\": \"us-west-2\"}", "signature", "1235", "i-1234", errMsg));
    }
    
    @Test
    public void testValidateAWSDocumentInvalidInstanceId() {
        
        StringBuilder errMsg = new StringBuilder(256);

        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2",
                "{\"accountId\": \"1234\",\"region\": \"us-west-2\",\"instanceId\": \"i-234\"}",
                "signature", "1234", "i-1234", errMsg));
    }
    
    @Test
    public void testValidateAWSDocumentInvalidBootTime() {
        
        StringBuilder errMsg = new StringBuilder(256);

        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 1000000).toString();
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2", "{\"accountId\": \"1234\",\"pendingTime\": \""
                + bootTime + "\",\"region\": \"us-west-2\",\"instanceId\": \"i-1234\"}",
                "signature", "1234", "i-1234", errMsg));
    }
    
    @Test
    public void testValidateAWSDocument() {
        
        StringBuilder errMsg = new StringBuilder(256);

        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 100).toString();
        assertTrue(provider.validateAWSDocument("athenz.aws.us-west-2", "{\"accountId\": \"1234\",\"pendingTime\": \""
                + bootTime + "\",\"region\":\"us-west-2\",\"instanceId\": \"i-1234\"}",
                "signature", "1234", "i-1234", errMsg));
    }
    
    @Test
    public void testConfirmInstanceInvalidVerifyIdentity() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
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
        } catch (ResourceException ex) {
        }
    }
    
    @Test
    public void testConfirmInstance() {
        
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz.cloud");
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
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
        
        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertEquals(result.getDomain(), "athenz");
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
    }
    
    @Test
    public void testConfirmInstanceLambdaEmptyDocument() {
        
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz.cloud");
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"\",\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        attributes.put("sanDNS", "service.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        confirmation.setAttributes(attributes);
        
        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertEquals(result.getAttributes().get("certUsage"), "client");
        assertEquals(result.getDomain(), "athenz");
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
    }
    
    @Test
    public void testConfirmInstanceLambdaNullDocument() {
        
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "athenz.cloud");
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        attributes.put("sanDNS", "service.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        confirmation.setAttributes(attributes);
        
        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertEquals(result.getAttributes().get("certUsage"), "client");
        assertEquals(result.getDomain(), "athenz");
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
    }
    
    @Test
    public void testInstanceClient() {
        
        InstanceAWSProvider provider = new InstanceAWSProvider();
        AWSAttestationData data = new AWSAttestationData();
        
        // first with null and empty access point
        
        data.setAccess(null);
        assertNull(provider.getInstanceClient(data));
        
        data.setAccess("");
        assertNull(provider.getInstanceClient(data));

        // null and empty secret
        
        data.setAccess("access");
        
        data.setSecret(null);
        assertNull(provider.getInstanceClient(data));
        
        data.setSecret("");
        assertNull(provider.getInstanceClient(data));
        
        // null and empty token
        
        data.setSecret("secret");
        
        data.setToken(null);
        assertNull(provider.getInstanceClient(data));
        
        data.setToken("");
        assertNull(provider.getInstanceClient(data));
        
        data.setToken("valid");
        assertNotNull(provider.getInstanceClient(data));
    }
    
    @Test
    public void testGetInstanceProperty() {
        
        InstanceAWSProvider provider = new InstanceAWSProvider();
        assertNull(provider.getInstanceProperty(null,  "awsAccount"));
        
        HashMap<String, String> attributes = new HashMap<>();
        assertNull(provider.getInstanceProperty(attributes,  "awsAccount"));

        attributes.put("testAccount", "1235");
        assertNull(provider.getInstanceProperty(attributes,  "awsAccount"));

        attributes.put("awsAccount", "1235");
        assertEquals(provider.getInstanceProperty(attributes,  "awsAccount"), "1235");
    }
    
    @Test
    public void testValidateAWSDocumentFailures() {
        
        StringBuilder errMsg = new StringBuilder(256);

        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        
        // no signature
        
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2", "document",
                null, "awsAccount", "instanceId", errMsg));
        
        // unable to parse
        
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2", "document",
                "signature", "awsAccount", "instanceId", errMsg));
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
    public void testVerifyInstanceIdentityNullClient() {
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        provider.setIdentitySuper(true);
        AWSAttestationData info = new AWSAttestationData();
        assertFalse(provider.verifyInstanceIdentity(info, "1234"));
    }
    
    @Test
    public void testVerifyInstanceIdentityNullIdentity() {
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        provider.setIdentitySuper(true);
        AWSSecurityTokenServiceClient mockClient = Mockito.mock(AWSSecurityTokenServiceClient.class);
        Mockito.when(mockClient.getCallerIdentity(ArgumentMatchers.any())).thenReturn(null);
        provider.setStsClient(mockClient);
        
        AWSAttestationData info = new AWSAttestationData();
        assertFalse(provider.verifyInstanceIdentity(info, "1234"));
    }
    
    @Test
    public void testVerifyInstanceIdentityException() {
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        provider.setIdentitySuper(true);
        AWSSecurityTokenServiceClient mockClient = Mockito.mock(AWSSecurityTokenServiceClient.class);
        Mockito.when(mockClient.getCallerIdentity(ArgumentMatchers.any())).thenThrow(new ResourceException(101));
        provider.setStsClient(mockClient);
        
        AWSAttestationData info = new AWSAttestationData();
        assertFalse(provider.verifyInstanceIdentity(info, "1234"));
    }
    
    @Test
    public void testVerifyInstanceIdentityARNMismatch() {
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        provider.setIdentitySuper(true);
        AWSSecurityTokenServiceClient mockClient = Mockito.mock(AWSSecurityTokenServiceClient.class);
        GetCallerIdentityResult result = Mockito.mock(GetCallerIdentityResult.class);
        Mockito.when(result.getArn()).thenReturn("arn:aws:sts::1235:assumed-role/athenz.service/athenz.service");
        Mockito.when(mockClient.getCallerIdentity(ArgumentMatchers.any())).thenReturn(result);
        provider.setStsClient(mockClient);
        
        AWSAttestationData info = new AWSAttestationData();
        info.setRole("athenz.service");
        assertFalse(provider.verifyInstanceIdentity(info, "1234"));
    }
    
    @Test
    public void testVerifyInstanceIdentity() {
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        provider.setIdentitySuper(true);
        AWSSecurityTokenServiceClient mockClient = Mockito.mock(AWSSecurityTokenServiceClient.class);
        GetCallerIdentityResult result = Mockito.mock(GetCallerIdentityResult.class);
        Mockito.when(result.getArn()).thenReturn("arn:aws:sts::1234:assumed-role/athenz.service/athenz.service");
        Mockito.when(mockClient.getCallerIdentity(ArgumentMatchers.any())).thenReturn(result);
        provider.setStsClient(mockClient);
        
        AWSAttestationData info = new AWSAttestationData();
        info.setRole("athenz.service");
        assertTrue(provider.verifyInstanceIdentity(info, "1234"));
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
    public void testValidateCertRequestHostnamesNullSuffix() {
        System.clearProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX);
        InstanceAWSProvider provider = new InstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");

        assertFalse(provider.validateCertRequestHostnames(null,  null,  null,  null));
        provider.close();
    }
    
    @Test
    public void testValidateCertRequestHostnamesEmptySuffix() {
        System.setProperty(InstanceAWSProvider.AWS_PROP_DNS_SUFFIX, "");
        InstanceAWSProvider provider = new InstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");

        assertFalse(provider.validateCertRequestHostnames(null,  null,  null,  null));
        provider.close();
    }
    
    @Test
    public void testValidateCertRequestHostnamesInvalidCount() {
        InstanceAWSProvider provider = new InstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "service.athenz.athenz.cloud");
        
        assertFalse(provider.validateCertRequestHostnames(attributes, "athenz", "api",  null));
        provider.close();
    }
    
    @Test
    public void testValidateCertRequestHostnamesInvalidInstanceId() {
        InstanceAWSProvider provider = new InstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz2.cloud");
        
        StringBuilder id = new StringBuilder(256);
        assertFalse(provider.validateCertRequestHostnames(attributes, "athenz", "api",  id));
        provider.close();
    }
    
    @Test
    public void testValidateCertRequestHostnamesInvalidHost() {
        InstanceAWSProvider provider = new InstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "storage.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        
        StringBuilder id = new StringBuilder(256);
        assertFalse(provider.validateCertRequestHostnames(attributes, "athenz", "api",  id));
        provider.close();
    }
    
    @Test
    public void testValidateCertRequestHostnamesMissingInstanceId() {
        InstanceAWSProvider provider = new InstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz.athenz.cloud,api.athenz.athenz.cloud");
        
        StringBuilder id = new StringBuilder(256);
        assertFalse(provider.validateCertRequestHostnames(attributes, "athenz", "api",  id));
        provider.close();
    }
    
    @Test
    public void testValidateCertRequestHostnamesMissingHost() {
        InstanceAWSProvider provider = new InstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "i-1234.instanceid.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        
        StringBuilder id = new StringBuilder(256);
        assertFalse(provider.validateCertRequestHostnames(attributes, "athenz", "api",  id));
        provider.close();
    }
    
    @Test
    public void testValidateCertRequestHostnames() {
        InstanceAWSProvider provider = new InstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "api.athenz.athenz.cloud,i-1234.instanceid.athenz.athenz.cloud");
        StringBuilder id = new StringBuilder(256);
        assertTrue(provider.validateCertRequestHostnames(attributes, "athenz", "api", id));
        assertEquals(id.toString(), "i-1234");
        provider.close();
    }
    
    @Test
    public void testValidateCertRequestHostnamesNullHostnames() {
        InstanceAWSProvider provider = new InstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        HashMap<String, String> attributes = new HashMap<>();
        StringBuilder id = new StringBuilder(256);
        assertFalse(provider.validateCertRequestHostnames(attributes, "athenz", "api", id));
        provider.close();
    }
    
    @Test
    public void testValidateCertRequestHostnamesEmptyHostnames() {
        InstanceAWSProvider provider = new InstanceAWSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("sanDNS", "");
        StringBuilder id = new StringBuilder(256);
        assertFalse(provider.validateCertRequestHostnames(attributes, "athenz", "api", id));
        provider.close();
    }
}
