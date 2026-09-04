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
package com.yahoo.athenz.crypki;

import com.yahoo.athenz.common.server.cert.Priority;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertSame;

public class CrypkiCertSignerTest {

    @Test
    public void testDelegatesToSigner() {
        CrypkiSigner signer = new CrypkiSigner() {
            @Override
            public String sign(X509SignRequest request) {
                return "CERT:" + request.getCsrPem() + ":" + request.getKeyId();
            }

            @Override
            public String getCACertificate(String keyId) {
                return "CA:" + keyId;
            }

            @Override
            public int getMaxCertExpiryTimeMins() {
                return 10;
            }
        };
        CrypkiCertSigner certSigner = new CrypkiCertSigner(signer);
        assertEquals(certSigner.generateX509Certificate("p", null, "csr", "client", 5,
                Priority.High, "kid"), "CERT:csr:kid");
        assertEquals(certSigner.getCACertificate("p", "kid"), "CA:kid");
        assertEquals(certSigner.getMaxCertExpiryTimeMins(), 10);
        assertSame(certSigner.getSigner(), signer);
        assertSame(certSigner.getRequestFactory().resolveKeyId(null, null), "x509-key");
        certSigner.close();
    }

    @Test
    public void testDefaultCloseAndMaxExpiry() {
        CrypkiSigner signer = new CrypkiSigner() {
            @Override
            public String sign(X509SignRequest request) {
                return "ok";
            }

            @Override
            public String getCACertificate(String keyId) {
                return "ca";
            }
        };
        assertEquals(signer.getMaxCertExpiryTimeMins(), 43200);
        signer.close();
        new CrypkiCertSigner(signer).close();
    }
}
