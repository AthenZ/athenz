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
package com.yahoo.athenz.auth.util;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.testng.annotations.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

public class CryptoExceptionTest {

    @Test
    public void testCryptoExceptions() {

        CryptoException ex = new CryptoException();
        assertNotNull(ex);
        assertEquals(ex.getCode(), CryptoException.CRYPTO_ERROR);

        assertNotNull(new CryptoException(new NoSuchAlgorithmException()));
        assertNotNull(new CryptoException(new InvalidKeyException()));
        assertNotNull(new CryptoException(new NoSuchProviderException()));
        assertNotNull(new CryptoException(new SignatureException()));
        assertNotNull(new CryptoException(new FileNotFoundException()));
        assertNotNull(new CryptoException(new IOException()));
        assertNotNull(new CryptoException(new CertificateException()));
        assertNotNull(new CryptoException(new InvalidKeySpecException()));
        assertNotNull(new CryptoException(new OperatorCreationException("unit-test")));
        assertNotNull(new CryptoException(new PKCSException("unit-test")));
        assertNotNull(new CryptoException(new CMSException("unit-test")));

        ex = new CryptoException(CryptoException.CERT_HASH_MISMATCH, "X.509 Certificate hash mismatch");
        assertEquals(ex.getCode(), CryptoException.CERT_HASH_MISMATCH);
    }
}
