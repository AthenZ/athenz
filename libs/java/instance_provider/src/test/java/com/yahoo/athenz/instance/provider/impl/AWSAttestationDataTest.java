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

import org.testng.annotations.Test;

public class AWSAttestationDataTest {

    @Test
    public void testAWSAttestationData() {
        AWSAttestationData data = new AWSAttestationData();
        data.setAccess("access");
        data.setDocument("document");
        data.setRole("role");
        data.setSecret("secret");
        data.setSignature("signature");
        data.setToken("token");
        
        assertEquals(data.getAccess(), "access");
        assertEquals(data.getDocument(), "document");
        assertEquals(data.getRole(), "role");
        assertEquals(data.getSecret(), "secret");
        assertEquals(data.getSignature(), "signature");
        assertEquals(data.getToken(), "token");
    }
}
