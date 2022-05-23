package com.yahoo.athenz.zts;

import com.yahoo.rdl.Timestamp;
import org.testng.annotations.Test;

import java.util.ArrayList;

import static org.testng.Assert.*;

public class AthenzJWKConfigTest {

    @Test
    public void testAthenzJWKConfig() {
        AthenzJWKConfig conf = new AthenzJWKConfig();
        AthenzJWKConfig confOther = new AthenzJWKConfig();

        long now = System.currentTimeMillis();
        conf.setModified(Timestamp.fromMillis(now));
        confOther.setModified(Timestamp.fromMillis(now));
        assertEquals(now, conf.getModified().millis());

        assertEquals(conf, conf);
        assertEquals(conf, confOther);

        assertNotEquals(null, conf);
        assertNotEquals("AthenzJWKConfig", conf);

        conf.setZms(new JWKList());
        assertNotNull(conf.getZms());
        assertNotEquals(conf, confOther);
        assertNotEquals(confOther, conf);

        confOther.setZms(new JWKList().setKeys(new ArrayList<>()));
        assertNotEquals(conf, confOther);
        assertNotEquals(confOther, conf);

        conf.setZts(new JWKList());
        confOther.setZms(new JWKList());
        confOther.setZts(null);
        assertNull(confOther.getZts());
        assertNotEquals(conf, confOther);
        assertNotEquals(confOther, conf);
    }
}