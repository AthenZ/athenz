package com.yahoo.athenz.container;

import com.oath.auth.Utils;
import org.testng.annotations.Test;

import javax.net.ssl.TrustManager;
import java.security.KeyStore;

import static org.testng.AssertJUnit.assertEquals;

public class AthenzSslContextFactoryTest {
    
    @Test
    public void testGetSslContext() throws Exception {
        AthenzSslContextFactory athenzSslContextFactory = new AthenzSslContextFactory();
        KeyStore keyStore = Utils.createKeyStore("rsa_public_x509.cert", "unit_test_rsa_private.key");
        TrustManager[] tm = athenzSslContextFactory.getTrustManagers(keyStore, null);
        assertEquals(tm.length, 1);
        assertEquals(tm[0].getClass().getSimpleName(), AthenzTrustManagerProxy.class.getSimpleName());
    }

}