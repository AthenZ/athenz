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

import java.util.HashMap;
import org.testng.annotations.Test;

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
        assertFalse(provider.validateAWSAccount(null, "1234"));
        
        HashMap<String, String> attributes = new HashMap<>();
        assertFalse(provider.validateAWSAccount(attributes, "1234"));
        
        attributes.put("testAccount", "1234");
        assertFalse(provider.validateAWSAccount(attributes, "1234"));

        attributes.put("awsAccount", "1235");
        assertFalse(provider.validateAWSAccount(attributes, "1234"));

        attributes.put("awsAccount", "1234");
        assertTrue(provider.validateAWSAccount(attributes, "1234"));
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
    public void testConfirmInstanceEmptyDocument() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"signature\": \"signature\"}")
                .setDomain("athenz").setProvider("provider").setService("service");

        // empty document must fail
        
        try {
            provider.confirmInstance(confirmation);
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("AWS instance document is empty"));
        }
        
        confirmation.setAttestationData("{\"document\": \"\",\"signature\": \"signature\"}");
        
        //  empty document must fail
        
        try {
            provider.confirmInstance(confirmation);
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("AWS instance document is empty"));
        }
    }
    
    @Test
    public void testConfirmInstanceInvalidSignature() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"document\",\"signature\": \"signature\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        provider.setSignatureResult(false);
        
        try {
            provider.confirmInstance(confirmation);
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("AWS Instance document signature mismatch"));
        }
    }
    
    @Test
    public void testConfirmInstanceInvalidDocument() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"document\",\"signature\": \"signature\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        
        try {
            provider.confirmInstance(confirmation);
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Unable to parse instance document"));
        }
    }
    
    @Test
    public void testConfirmInstanceInvalidAccountId() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"{\\\"accountId\\\": \\\"1234\\\"}\", \"signature\": \"signature\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1235");
        confirmation.setAttributes(attributes);
        
        try {
            provider.confirmInstance(confirmation);
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Unable to validate registered AWS account id in Athenz"));
        }
    }
    
    @Test
    public void testConfirmInstanceInvalidBootTime() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        long bootTime = Timestamp.fromCurrentTime().millis() - 1000000;
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"{\\\"accountId\\\": \\\"1234\\\",\\\"pendingTime\\\": \\\""
                        + bootTime + "\\\"}\",\"signature\": \"signature\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        confirmation.setAttributes(attributes);
        
        try {
            provider.confirmInstance(confirmation);
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Instance boot time is not recent enough"));
        }
    }
    
    @Test
    public void testConfirmInstanceInvalidVerifyIdentity() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        provider.setIdentityResult(false);
        
        long bootTime = Timestamp.fromCurrentTime().millis() - 100;
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"{\\\"accountId\\\": \\\"1234\\\",\\\"pendingTime\\\": \\\""
                        + bootTime + "\\\"}\",\"signature\": \"signature\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        confirmation.setAttributes(attributes);
        
        try {
            provider.confirmInstance(confirmation);
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Unable to verify instance identity"));
        }
    }
    
    @Test
    public void testConfirmInstance() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        long bootTime = Timestamp.fromCurrentTime().millis() - 100;
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"{\\\"accountId\\\": \\\"1234\\\",\\\"pendingTime\\\": \\\""
                        + bootTime + "\\\"}\",\"signature\": \"signature\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("awsAccount", "1234");
        confirmation.setAttributes(attributes);
        
        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertEquals(result.getDomain(), "athenz");
    }
    
    @Test
    public void testConfirmInstanceLambda() {
        
        MockInstanceAWSProvider provider = new MockInstanceAWSProvider();
        System.setProperty(InstanceAWSProvider.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("{\"document\": \"lambda\",\"signature\": \"signature\"}")
                .setDomain("athenz").setProvider("provider").setService("service");
        
        InstanceConfirmation result = provider.confirmInstance(confirmation);
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
}
