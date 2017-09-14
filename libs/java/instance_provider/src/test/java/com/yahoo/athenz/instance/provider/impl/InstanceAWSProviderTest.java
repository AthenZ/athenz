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

import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.ResourceException;

import com.yahoo.rdl.Timestamp;

public class InstanceAWSProviderTest {
    
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
        
        InstanceAWSProvider provider = new InstanceAWSProvider();
        assertTrue(provider.validateAWSAccount("1234", "1234"));
        assertFalse(provider.validateAWSAccount("1235", "1234"));
    }

    @Test
    public void testValidateAWSSignatureFailure() {
        
        InstanceAWSProvider provider = new InstanceAWSProvider();
        assertFalse(provider.validateAWSSignature("document", null));
        assertFalse(provider.validateAWSSignature("document", ""));
        
        // aws public key is null
        assertFalse(provider.validateAWSSignature("document", "signature"));
        
        provider = new InstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        assertFalse(provider.validateAWSSignature("document", "invalid-signature"));

        provider.close();
        System.clearProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT);
    }
    
    @Test
    public void testValidateAWSDocumentInvalidSignature() {
        
        InstanceAWSProvider provider = new InstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2", "document", null, "1234"));
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
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2", "{\"accountId\": \"1234\"}", "signature", "1235"));
    }
    
    @Test
    public void testValidateAWSDocumentInvalidAccountId() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2", "{\"accountId\": \"1234\",\"region\": \"us-west-2\"}", "signature", "1235"));
    }
    
    @Test
    public void testValidateAWSDocumentInvalidBootTime() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 1000000).toString();
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2", "{\"accountId\": \"1234\",\"pendingTime\": \""
                + bootTime + "\",\"region\": \"us-west-2\"}", "signature", "1234"));
    }
    
    @Test
    public void testValidateAWSDocument() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 100).toString();
        assertTrue(provider.validateAWSDocument("athenz.aws.us-west-2", "{\"accountId\": \"1234\",\"pendingTime\": \""
                        + bootTime + "\",\"region\":\"us-west-2\"}", "signature", "1234"));
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
                        + bootTime + "\\\",\\\"region\\\": \\\"us-west-2\\\"}\","
                        + "\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("athenz.aws.us-west-2").setService("service");
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
    public void testConfirmInstance() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 100).toString();
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"{\\\"accountId\\\": \\\"1234\\\",\\\"pendingTime\\\": \\\""
                        + bootTime + "\\\",\\\"region\\\": \\\"us-west-2\\\"}\","
                        + "\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("athenz.aws.us-west-2").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        confirmation.setAttributes(attributes);
        
        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertEquals(result.getDomain(), "athenz");
    }
    
    @Test
    public void testConfirmInstanceLambdaEmptyDocument() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"\",\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        confirmation.setAttributes(attributes);
        
        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertEquals(result.getAttributes().get("certUsage"), "client");
        assertEquals(result.getDomain(), "athenz");
    }
    
    @Test
    public void testConfirmInstanceLambdaNullDocument() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"signature\": \"signature\",\"role\": \"athenz.service\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        confirmation.setAttributes(attributes);
        
        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertEquals(result.getAttributes().get("certUsage"), "client");
        assertEquals(result.getDomain(), "athenz");
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
    public void testGetAWSAccount() {
        
        InstanceAWSProvider provider = new InstanceAWSProvider();
        assertNull(provider.getAWSAccount(null));
        
        HashMap<String, String> attributes = new HashMap<>();
        assertNull(provider.getAWSAccount(attributes));

        attributes.put("testAccount", "1235");
        assertNull(provider.getAWSAccount(attributes));

        attributes.put("awsAccount", "1235");
        assertEquals(provider.getAWSAccount(attributes), "1235");
    }
    
    @Test
    public void testValidateAWSDocumentFailures() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        
        // no signature
        
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2", "document", null, "awsAccount"));
        
        // unable to parse
        
        assertFalse(provider.validateAWSDocument("athenz.aws.us-west-2", "document", "signature", "awsAccount"));
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
        Mockito.when(mockClient.getCallerIdentity(Mockito.anyObject())).thenReturn(null);
        provider.setStsClient(mockClient);
        
        AWSAttestationData info = new AWSAttestationData();
        assertFalse(provider.verifyInstanceIdentity(info, "1234"));
    }
    
    @Test
    public void testVerifyInstanceIdentityException() {
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        provider.setIdentitySuper(true);
        AWSSecurityTokenServiceClient mockClient = Mockito.mock(AWSSecurityTokenServiceClient.class);
        Mockito.when(mockClient.getCallerIdentity(Mockito.anyObject())).thenThrow(new ResourceException(101));
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
        Mockito.when(mockClient.getCallerIdentity(Mockito.anyObject())).thenReturn(result);
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
        Mockito.when(mockClient.getCallerIdentity(Mockito.anyObject())).thenReturn(result);
        provider.setStsClient(mockClient);
        
        AWSAttestationData info = new AWSAttestationData();
        info.setRole("athenz.service");
        assertTrue(provider.verifyInstanceIdentity(info, "1234"));
    }
    
    @Test
    public void testValidateAWSProvider() {
        InstanceAWSProvider provider = new InstanceAWSProvider();
        assertFalse(provider.validateAWSProvider("provider", null));
        assertFalse(provider.validateAWSProvider("athenz.aws.us-east-1", ""));
        assertFalse(provider.validateAWSProvider("athenz.aws.us-east-1", "us-west-2"));
        assertFalse(provider.validateAWSProvider("athenz.awsus-west-2", "us-west-2"));
        assertTrue(provider.validateAWSProvider("athenz.aws.us-west-2", "us-west-2"));
    }
}
