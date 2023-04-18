package com.yahoo.athenz.msd;

import org.testng.annotations.Test;

import java.util.Collections;

import static org.testng.Assert.*;

public class StaticWorkloadServicesTest {

    @Test
    public void testStaticWorkloadServicesFields() {
        StaticWorkloadService sws = new StaticWorkloadService();
        StaticWorkloadServices sws1 = new StaticWorkloadServices();
        sws1.setStaticWorkloadServices(Collections.singletonList(sws));
        assertNotNull(sws1);
        assertEquals(sws1.getStaticWorkloadServices().get(0), sws);
        assertEquals(sws1, sws1);

        StaticWorkloadServices sws2 = new StaticWorkloadServices();
        sws2.setStaticWorkloadServices(Collections.singletonList(sws));
        assertEquals(sws1, sws2);

        sws2.setStaticWorkloadServices(Collections.singletonList(new StaticWorkloadService().setServiceName("s1")));
        assertNotEquals(sws1, sws2);
        sws2.setStaticWorkloadServices(null);
        assertNotEquals(sws1, sws2);
        sws2.setStaticWorkloadServices(Collections.singletonList(sws));
        
        assertNotEquals(sws1, null);
        // for code coverage
        assertFalse(sws1.equals("mystring"));
        assertNotEquals(sws1, "mystring");

        assertEquals(sws1, sws1);
    }
}