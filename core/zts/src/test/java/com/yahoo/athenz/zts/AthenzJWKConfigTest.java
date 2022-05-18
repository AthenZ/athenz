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

        conf.setZmsJWK(new JWKList());
        assertNotNull(conf.getZmsJWK());
        assertNotEquals(conf, confOther);
        assertNotEquals(confOther, conf);

        confOther.setZmsJWK(new JWKList().setKeys(new ArrayList<>()));
        assertNotEquals(conf, confOther);
        assertNotEquals(confOther, conf);

        conf.setZtsJWK(new JWKList());
        confOther.setZmsJWK(new JWKList());
        confOther.setZtsJWK(null);
        assertNull(confOther.getZtsJWK());
        assertNotEquals(conf, confOther);
        assertNotEquals(confOther, conf);
    }
}