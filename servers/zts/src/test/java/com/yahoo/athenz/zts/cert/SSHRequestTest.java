/*
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
package com.yahoo.athenz.zts.cert;

import static org.testng.Assert.*;

import org.testng.annotations.Test;

public class SSHRequestTest {

    @Test
    public void testGetSshKeyReqTypeInvalidCsr() {
        
        SSHRequest req = new SSHRequest("csr", null);
        assertNull(req.getSshKeyReqType());
    }

    @Test
    public void testGetSshKeyReqTypeNoCertType() {
        
        SSHRequest req = new SSHRequest("{\"csr\":\"csr\"}", null);
        assertNull(req.getSshKeyReqType());
    }
    
    @Test
    public void testGetSshKeyReqType() {
        
        SSHRequest req = new SSHRequest("{\"csr\":\"csr\",\"certtype\":\"host\"}", null);
        assertEquals(req.getSshKeyReqType(), "host");
    }
    
    @Test
    public void testValidateTypeNoCertType() {
        
        SSHRequest req = new SSHRequest("{\"csr\":\"csr\"}", null);
        assertFalse(req.validateType());
    }
    
    @Test
    public void testValidateTypeCertTypeNull() {
        
        SSHRequest req = new SSHRequest("{\"csr\":\"csr\",\"certtype\":\"type\"}", null);
        assertTrue(req.validateType());
        assertEquals(req.getSshReqType(), "type");
    }
    
    @Test
    public void testValidateTypeCertType() {
        
        SSHRequest req = new SSHRequest("{\"csr\":\"csr\",\"certtype\":\"host\"}", "host");
        assertTrue(req.validateType());
        assertEquals(req.getSshReqType(), "host");
        
        req = new SSHRequest("{\"csr\":\"csr\",\"certtype\":\"type\"}", "host");
        assertFalse(req.validateType());
    }
}
