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
package com.yahoo.athenz.zts.token;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class HostIssuerMappingTest {

    @Test
    public void testHostIssuerMapping() {
        HostIssuerMapping mapping = new HostIssuerMapping();
        
        assertNull(mapping.getHost());
        assertNull(mapping.getIssuer());
        
        mapping.setHost("example.com");
        mapping.setIssuer("https://example.com/issuer");
        
        assertEquals(mapping.getHost(), "example.com");
        assertEquals(mapping.getIssuer(), "https://example.com/issuer");
    }

    @Test
    public void testHostIssuerMappingWithNullValues() {
        HostIssuerMapping mapping = new HostIssuerMapping();
        
        mapping.setHost(null);
        mapping.setIssuer(null);
        
        assertNull(mapping.getHost());
        assertNull(mapping.getIssuer());
    }

    @Test
    public void testHostIssuerMappingWithEmptyValues() {
        HostIssuerMapping mapping = new HostIssuerMapping();
        
        mapping.setHost("");
        mapping.setIssuer("");
        
        assertEquals(mapping.getHost(), "");
        assertEquals(mapping.getIssuer(), "");
    }

    @Test
    public void testHostIssuerMappingUpdateValues() {
        HostIssuerMapping mapping = new HostIssuerMapping();
        
        mapping.setHost("host1.com");
        mapping.setIssuer("issuer1");
        
        assertEquals(mapping.getHost(), "host1.com");
        assertEquals(mapping.getIssuer(), "issuer1");
        
        mapping.setHost("host2.com");
        mapping.setIssuer("issuer2");
        
        assertEquals(mapping.getHost(), "host2.com");
        assertEquals(mapping.getIssuer(), "issuer2");
    }
}
