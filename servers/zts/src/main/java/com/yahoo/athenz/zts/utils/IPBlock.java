package com.yahoo.athenz.zts.utils;

import java.net.InetAddress;

import com.google.common.net.InetAddresses;

public class IPBlock {

    long subnet;
    long mask;
    public IPBlock(final String ipBlock) {
        
        // the expected format is subnet/mask e.g. 192.1.0.0/255.255.255.255
        
        int idx = ipBlock.indexOf('/');
        if (idx == -1) {
            throw new IllegalArgumentException("Invalid ipblock line - missing / separator");
        }
        subnet = convertToLong(ipBlock.substring(0, idx).trim());
        mask = convertToLong(ipBlock.substring(idx + 1).trim());
    }

    public boolean ipCheck(long addr) {
        return ((addr & mask) == subnet);
    }
    
    public static long convertToLong(String ipAddress) {
        InetAddress addr = InetAddresses.forString(ipAddress);
        byte[] bytes = addr.getAddress();
        long ipValue = 0;
        for (byte b : bytes) {
            ipValue = ipValue << 8 | (b & 0xFF);
        }
        return ipValue;
    }
}
