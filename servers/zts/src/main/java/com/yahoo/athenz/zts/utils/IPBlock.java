package com.yahoo.athenz.zts.utils;

import java.net.InetAddress;

import com.google.common.net.InetAddresses;

public class IPBlock {

    long subnet;
    long mask;
    
    public IPBlock(final String ipBlock) {
        
        // the expected format is subnet/mask e.g. 192.1.0.0/20
        
        int idx = ipBlock.indexOf('/');
        if (idx == -1) {
            throw new IllegalArgumentException("Invalid ipblock line - missing / separator");
        }
        subnet = convertIPToLong(ipBlock.substring(0, idx).trim());
        
        // valid mask is 1..32
        
        int val = Integer.parseInt(ipBlock.substring(idx + 1).trim());
        if (val < 1 || val > 32) {
            throw new IllegalArgumentException("Invalid ipblock line - invalid mask: " + val);
        }
        mask = convertMaskToLong(val);
    }

    public boolean ipCheck(long addr) {
        return ((addr & mask) == subnet);
    }
    
    public static long convertIPToLong(final String ipAddress) {
        InetAddress addr = InetAddresses.forString(ipAddress);
        byte[] bytes = addr.getAddress();
        long ipValue = 0;
        for (byte b : bytes) {
            ipValue = ipValue << 8 | (b & 0xFF);
        }
        return ipValue;
    }
    
    public static long convertMaskToLong(int value) {
        return Math.round(Math.pow(2, 32) - Math.pow(2, (32 - value)));
    }
}
