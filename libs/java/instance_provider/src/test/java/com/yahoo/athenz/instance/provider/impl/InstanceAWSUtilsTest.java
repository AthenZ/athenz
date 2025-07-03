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

import com.yahoo.athenz.auth.util.Crypto;
import org.mockito.MockedStatic;
import org.testng.annotations.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.*;

public class InstanceAWSUtilsTest {
    
    @Test
    public void testInitializeDefaults() {
        System.clearProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT);
        InstanceAWSUtils utils = new InstanceAWSUtils();
        assertNull(utils.awsPublicKey);
    }
    
    @Test
    public void testInitialize() {
        
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT_PER_REGION,
                "us-east-1:src/test/resources/aws_public_us_east_1.cert,us-east-2:src/test/resources/aws_public_us_east_2_invalid.cert,us-central-1");
        InstanceAWSUtils utils = new InstanceAWSUtils();
        assertNotNull(utils.awsPublicKey);
        assertNotNull(utils.awsPublicKeyRegionMap.get("us-east-1"));
        assertNull(utils.awsPublicKeyRegionMap.get("us-east-2"));
        assertNull(utils.awsPublicKeyRegionMap.get("us-central-1"));
        System.clearProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT);
        System.clearProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT_PER_REGION);
    }

    @Test
    public void testValidateAWSSignatureFailure() {
        
        StringBuilder errMsg = new StringBuilder(256);

        InstanceAWSUtils utils = new InstanceAWSUtils();
        assertFalse(utils.validateAWSSignature("document", null, "us-west-2", errMsg));
        assertFalse(utils.validateAWSSignature("document", "", "us-west-2", errMsg));
        
        // aws public key is null
        assertFalse(utils.validateAWSSignature("document", "signature", "us-west-2", errMsg));

        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        utils = new InstanceAWSUtils();

        assertFalse(utils.validateAWSSignature("document", "invalid-signature", "us-west-2", errMsg));
        System.clearProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT);
    }

    @Test
    public void testValidateAWSSignatureValid() {
        StringBuilder errMsg = new StringBuilder(256);
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT, "src/test/resources/aws_public.cert");
        System.setProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT_PER_REGION, "us-east-1:src/test/resources/aws_public_us_east_1.cert");
        InstanceAWSUtils utils = new InstanceAWSUtils();
        try(MockedStatic<Crypto> crypto = mockStatic(Crypto.class)) {
            crypto.when(() -> Crypto.validatePKCS7Signature(any(), any(), any()))
                    .thenReturn(true);
            assertTrue(utils.validateAWSSignature("document", "aaa", "us-west-2", errMsg));
            assertTrue(utils.validateAWSSignature("document", "aaa", "us-east-1", errMsg));
        }
        System.clearProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT);
        System.clearProperty(InstanceAWSUtils.AWS_PROP_PUBLIC_CERT_PER_REGION);
    }
}
