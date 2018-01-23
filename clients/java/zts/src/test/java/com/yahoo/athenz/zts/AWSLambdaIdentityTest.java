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
package com.yahoo.athenz.zts;

import java.io.File;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.testng.annotations.Test;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

import com.yahoo.athenz.auth.util.Crypto;

public class AWSLambdaIdentityTest {

    @Test
    public void testAWSLambdaIdentity() {
        
        AWSLambdaIdentity identity = new AWSLambdaIdentity();
        assertNull(identity.getPrivateKey());
        assertNull(identity.getX509Certificate());
        
        File privkey = new File("./src/test/resources/test_private_k0.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(privkey);
        identity.setPrivateKey(privateKey);
        assertNotNull(identity.getPrivateKey());
        
        File pubCert = new File("./src/test/resources/test_cert.pem");
        X509Certificate cert = Crypto.loadX509Certificate(pubCert);
        identity.setX509Certificate(cert);
        assertNotNull(identity.getX509Certificate());
    }
}
