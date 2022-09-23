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
package com.yahoo.athenz.zts.cert;

import static org.testng.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.testng.annotations.Test;

import com.yahoo.rdl.JSON;

public class X509CertSignObjectTest {

    @Test
    public void testX509CertSignObject() {

        X509CertSignObject cert = new X509CertSignObject();
        assertNull(cert.getPem());
        
        cert.setPem("pem-value");
        assertEquals(cert.getPem(), "pem-value");
        
        cert.setExpiryTime(30);
        assertEquals(cert.getExpiryTime().intValue(), 30);
        
        List<Integer> extKeyUsage = new ArrayList<>();
        extKeyUsage.add(1);
        extKeyUsage.add(2);
        cert.setX509ExtKeyUsage(extKeyUsage);
        assertEquals(cert.getX509ExtKeyUsage(), extKeyUsage);
    }
    
    @Test
    public void testX509CertSignObjectStruct() {

        X509CertSignObject cert = JSON.fromString("{\"pem\":\"pem-value\"}", X509CertSignObject.class);
        assertEquals(cert.getPem(), "pem-value");
        assertNull(cert.getX509ExtKeyUsage());
        assertNull(cert.getExpiryTime());
        
        cert = JSON.fromString("{\"pem\":\"pem-value\",\"x509ExtKeyUsage\":[1,2],\"expiryTime\":10}", X509CertSignObject.class);
        assertEquals(cert.getPem(), "pem-value");
        List<Integer> keyExtUsage = cert.getX509ExtKeyUsage();
        assertNotNull(keyExtUsage);
        assertEquals(keyExtUsage.size(), 2);
        assertTrue(keyExtUsage.contains(1));
        assertTrue(keyExtUsage.contains(2));
        assertEquals(cert.getExpiryTime().intValue(), 10);
    }
}
