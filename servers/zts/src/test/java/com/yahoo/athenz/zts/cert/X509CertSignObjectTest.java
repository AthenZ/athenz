/**
 * Copyright 2016 Yahoo Inc.
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

import org.testng.annotations.Test;

import com.yahoo.rdl.JSON;

public class X509CertSignObjectTest {

    @Test
    public void testX509CertSignObject() {

        X509CertSignObject cert = new X509CertSignObject();
        assertNull(cert.getPem());
        
        cert.setPem("pem-value");
        assertEquals(cert.getPem(), "pem-value");
        
        cert.setExpire(30);
        assertEquals(cert.getExpire(), 30);
        
        cert.setExtusage("1,2");
        assertEquals(cert.getExtusage(), "1,2");
    }
    
    @Test
    public void testX509CertSignObjectStruct() {

        X509CertSignObject cert = JSON.fromString("{\"pem\":\"pem-value\"}", X509CertSignObject.class);
        assertEquals(cert.getPem(), "pem-value");
        assertNull(cert.getExtusage());
        assertEquals(cert.getExpire(), 0);
        
        cert = JSON.fromString("{\"pem\":\"pem-value\",\"extusage\":\"1,2\",\"expire\":10}", X509CertSignObject.class);
        assertEquals(cert.getPem(), "pem-value");
        assertEquals(cert.getExtusage(), "1,2");
        assertEquals(cert.getExpire(), 10);
    }
}
