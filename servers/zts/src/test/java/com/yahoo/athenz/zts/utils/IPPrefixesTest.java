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
        assertEquals(prefixList.size(), 7);
        
        assertEquals(prefixes.getCreateDate(), "2018-03-17-01-16-14");
        assertEquals(prefixes.getSyncToken(), "123456");
        
        IPPrefix ipPrefix = prefixList.get(0);
        assertEquals(ipPrefix.getIpv4Prefix(), "10.0.0.1/32");
        assertEquals(ipPrefix.getRegion(), "GLOBAL");
        assertEquals(ipPrefix.getService(), "ATHENZ");
        assertNull(ipPrefix.getIpv6Prefix());
    }
}
