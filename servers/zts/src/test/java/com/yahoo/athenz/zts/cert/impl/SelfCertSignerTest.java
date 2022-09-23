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
package com.yahoo.athenz.zts.cert.impl;

import static org.testng.Assert.*;

import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.zts.ZTSConsts;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class SelfCertSignerTest {

    @BeforeClass
    public void setup() {
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME,
                "src/test/resources/unit_test_private_encrypted.key");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD, "athenz");
    }

    @Test
    public void testSelfCertSignerFactory() {
        SelfCertSignerFactory certFactory = new SelfCertSignerFactory();
        assertNotNull(certFactory);

        CertSigner certSigner = certFactory.create();
        assertNotNull(certSigner);

        certSigner.close();
    }

    @Test
    public void testGetMaxCertExpiryTime() {
        
        System.clearProperty(ZTSConsts.ZTS_PROP_CERTSIGN_MAX_EXPIRY_TIME);
        
        SelfCertSignerFactory certFactory = new SelfCertSignerFactory();
        
        KeyStoreCertSigner certSigner = (KeyStoreCertSigner) certFactory.create();
        assertEquals(certSigner.getMaxCertExpiryTimeMins(), 43200);
        certSigner.close();
        
        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_MAX_EXPIRY_TIME, "1200");
        certSigner = (KeyStoreCertSigner) certFactory.create();
        assertEquals(certSigner.getMaxCertExpiryTimeMins(), 1200);
        certSigner.close();

        System.clearProperty(ZTSConsts.ZTS_PROP_CERTSIGN_MAX_EXPIRY_TIME);
    }

    @Test
    public void testSelfCertSignerFactoryInvalidKey() {
        System.clearProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME);
        SelfCertSignerFactory certFactory = new SelfCertSignerFactory();
        assertNotNull(certFactory);

        CertSigner certSigner = certFactory.create();
        assertNull(certSigner);
    }

    @Test
    public void testSelfCertSignerFactoryInvalidDN() {

        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_CERT_DN, "invalid-dn");
        SelfCertSignerFactory certFactory = new SelfCertSignerFactory();
        assertNotNull(certFactory);

        CertSigner certSigner = certFactory.create();
        assertNull(certSigner);
        System.clearProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_CERT_DN);
    }
}
