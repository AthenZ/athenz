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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.ResourceException;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;

public class InstanceAWSECSProviderTest {
    
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
        InstanceAWSECSProvider provider = new InstanceAWSECSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSECSProvider", null, null);
        assertEquals((long)provider.bootTimeOffsetSeconds.get(), 0);
        provider.close();
    }
    
    @Test
    public void testValidateAWSDocumentInvalidBootTime() {
        
        StringBuilder errMsg = new StringBuilder(256);
        StringBuilder privateIp = new StringBuilder(64);

        MockInstanceAWSECSProvider provider = new MockInstanceAWSECSProvider();
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        provider.initialize("athenz.aws-ecs.us-west-2", "com.yahoo.athenz.instance.provider.impl.InstanceAWSECSProvider", null, null);
        
        String bootTime = Timestamp.fromMillis(System.currentTimeMillis() - 1000000).toString();
        AWSAttestationData data = new AWSAttestationData();
        data.setDocument("{\"accountId\": \"1234\",\"pendingTime\": \""
                + bootTime + "\",\"region\": \"us-west-2\",\"instanceId\": \"i-1234\"}");
        data.setSignature("signature");
        assertTrue(provider.validateAWSDocument("athenz.aws-ecs.us-west-2", data,
                "1234", "i-1234", true, privateIp, errMsg));
    }
    
    @Test
    public void testEmptyRefreshAttestationData() {
        InstanceAWSECSProvider provider = new InstanceAWSECSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSECSProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        try {
            provider.refreshInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
        }
        
        confirmation.setAttestationData("");
        try {
            provider.refreshInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
        }
    }
    
    @Test
    public void testGetInstanceId() {
        InstanceAWSECSProvider provider = new InstanceAWSECSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAWSECSProvider", null, null);

        AWSAttestationData data = new AWSAttestationData();
        data.setTaskid("task1234");
        assertEquals(provider.getInstanceId(data, null, "id-1234"), "task1234");
        
        data.setTaskid(null);
        Struct doc = new Struct();
        doc.put(InstanceAWSProvider.ATTR_INSTANCE_ID, "data1234");
        assertEquals(provider.getInstanceId(data, doc, "data1234"), "data1234");

        data.setTaskid("");
        assertEquals(provider.getInstanceId(data, doc, "id-1234"), "id-1234");
        
        data.setTaskid("task1234");
        assertEquals(provider.getInstanceId(data, doc, "id-1234"), "task1234");
    }
}
