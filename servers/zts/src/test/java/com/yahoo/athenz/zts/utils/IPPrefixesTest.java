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
package com.yahoo.athenz.zts.utils;

import org.testng.annotations.Test;

import com.yahoo.rdl.JSON;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertEquals;

public class IPPrefixesTest {

    @Test
    public void testIPPrefixes() throws IOException {
        
        File ipFile = new File("src/test/resources/cert_refresh_ipblocks.txt");
        IPPrefixes prefixes = JSON.fromBytes(Files.readAllBytes(Paths.get(ipFile.toURI())), IPPrefixes.class);
        
        List<IPPrefix> prefixList = prefixes.getPrefixes();
        assertEquals(prefixList.size(), 8);
        
        assertEquals(prefixes.getCreateDate(), "2018-03-17-01-16-14");
        assertEquals(prefixes.getSyncToken(), "123456");
        
        IPPrefix ipPrefix = prefixList.get(0);
        assertEquals(ipPrefix.getIpv4Prefix(), "10.0.0.1/32");
        assertEquals(ipPrefix.getRegion(), "GLOBAL");
        assertEquals(ipPrefix.getService(), "ATHENZ");
        assertNull(ipPrefix.getIpv6Prefix());

        ipPrefix = prefixList.get(1);
        assertEquals(ipPrefix.getIpv4Prefix(), "20.1.0.0/16");
        assertEquals(ipPrefix.getIpv6Prefix(), "2a05:d07f:8000::/40");
        assertEquals(ipPrefix.getRegion(), "us-west-2");
        assertEquals(ipPrefix.getService(), "ATHENZ");
    }
}
