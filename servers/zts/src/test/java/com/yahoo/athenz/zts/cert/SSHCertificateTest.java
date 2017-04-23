/**
 * Copyright 2017 Yahoo Inc.
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

import org.testng.annotations.Test;
import static org.testng.Assert.*;

public class SSHCertificateTest {

    @Test
    public void testSSHCertificate() {
        
        SSHCertificate cert = new SSHCertificate();
        assertNotNull(cert);
        assertNull(cert.getCn());
        assertNull(cert.getPem());
        assertNull(cert.getType());
        
        SSHCertificate cert2 = new SSHCertificate().setCn("cn")
                .setPem("pem").setType("type");
        assertEquals(cert2.getCn(), "cn");
        assertEquals(cert2.getPem(), "pem");
        assertEquals(cert2.getType(), "type");
    }
}