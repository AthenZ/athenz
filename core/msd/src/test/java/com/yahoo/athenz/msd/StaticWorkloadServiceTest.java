package com.yahoo.athenz.msd;

import org.testng.annotations.Test;

import static com.yahoo.athenz.msd.StaticWorkloadType.EXTERNAL_APPLIANCE;
import static com.yahoo.athenz.msd.StaticWorkloadType.VIP;
import static org.testng.Assert.*;
import static org.testng.Assert.assertNotEquals;

public class StaticWorkloadServiceTest {

    @Test
    public void testStaticWorkloadServiceFields() {
        StaticWorkloadService sws1 = new StaticWorkloadService();
        sws1.setServiceName("s1").setInstance("i1").setType(VIP);
        assertNotNull(sws1);
        assertEquals(sws1.getServiceName(), "s1");
        assertEquals(sws1.getInstance(), "i1");
        assertEquals(sws1.getType(), StaticWorkloadType.VIP);
        assertEquals(sws1, sws1);

        StaticWorkloadService sws2 = new StaticWorkloadService();
        sws2.setServiceName("s1").setInstance("i1").setType(VIP);
        assertEquals(sws1, sws2);

        sws2.setServiceName("sports");
        assertNotEquals(sws1, sws2);
        sws2.setServiceName(null);
        assertNotEquals(sws1, sws2);
        sws2.setServiceName("s1");

        sws2.setType(EXTERNAL_APPLIANCE);
        assertNotEquals(sws1, sws2);
        sws2.setType(null);
        assertNotEquals(sws1, sws2);
        sws2.setType(VIP);
        
        sws2.setInstance("instance");
        assertNotEquals(sws1, sws2);
        sws2.setInstance(null);
        assertNotEquals(sws1, sws2);
        sws2.setInstance("i1");
        assertEquals(sws1, sws2);

        assertNotEquals(sws1, null);
        // for code coverage
        assertFalse(sws1.equals("mystring"));
        assertNotEquals(sws1, "mystring");

        assertEquals(sws1, sws1);
    }
}