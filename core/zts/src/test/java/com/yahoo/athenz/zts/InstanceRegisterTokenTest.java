package com.yahoo.athenz.zts;

import org.testng.annotations.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class InstanceRegisterTokenTest {

    @Test
    public void testInstanceRegisterToken() {

        InstanceRegisterToken token1 = new InstanceRegisterToken();
        InstanceRegisterToken token2 = new InstanceRegisterToken();

        token1.setAttestationData("attestdata");
        token1.setDomain("domain");
        token1.setService("service");
        token1.setProvider("provider");
        token1.setAttributes(Collections.emptyMap());

        token2.setAttestationData("attestdata");
        token2.setDomain("domain");
        token2.setService("service");
        token2.setProvider("provider");
        token2.setAttributes(Collections.emptyMap());

        assertEquals(token1, token2);
        assertEquals(token1, token1);
        assertNotEquals(null, token1);
        assertNotEquals("instnaceregistertoken", token1);

        assertEquals(token1.getAttestationData(), "attestdata");
        assertEquals(token1.getDomain(), "domain");
        assertEquals(token1.getService(), "service");
        assertEquals(token1.getProvider(), "provider");
        assertEquals(token1.getAttributes(), Collections.emptyMap());

        token2.setAttestationData("attestdata2");
        assertNotEquals(token1, token2);
        token2.setAttestationData(null);
        assertNotEquals(token1, token2);
        token2.setAttestationData("attestdata");

        token2.setDomain("domain2");
        assertNotEquals(token1, token2);
        token2.setDomain(null);
        assertNotEquals(token1, token2);
        token2.setDomain("domain");

        token2.setService("service2");
        assertNotEquals(token1, token2);
        token2.setService(null);
        assertNotEquals(token1, token2);
        token2.setService("service");

        token2.setProvider("provider2");
        assertNotEquals(token1, token2);
        token2.setProvider(null);
        assertNotEquals(token1, token2);
        token2.setProvider("provider");

        Map<String, String> attrs = new HashMap<>();
        attrs.put("key", "value");
        token2.setAttributes(attrs);
        assertNotEquals(token1, token2);
        token2.setAttributes(null);
        assertNotEquals(token1, token2);
        token2.setAttributes(Collections.emptyMap());
    }
}
