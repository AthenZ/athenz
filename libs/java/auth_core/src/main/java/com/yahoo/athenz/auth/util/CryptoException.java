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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;

public class CryptoException extends RuntimeException {

    public static final int CRYPTO_ERROR = 1;
    public static final int CERT_HASH_MISMATCH = 2;

    private static final long serialVersionUID = -4194687652165603898L;
    private int code = CRYPTO_ERROR;

    public CryptoException() {
        super();
    }

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(int code, final String message) {
        super(message);
        this.code = code;
    }

    public CryptoException(NoSuchAlgorithmException e) {
        super(e);
    }

    public CryptoException(InvalidKeyException e) {
        super(e);
    }

    public CryptoException(NoSuchProviderException e) {
        super(e);
    }

    public CryptoException(SignatureException e) {
        super(e);
    }

    public CryptoException(FileNotFoundException e) {
        super(e);
    }

    public CryptoException(IOException e) {
        super(e);
    }

    public CryptoException(CertificateException e) {
        super(e);
    }

    public CryptoException(InvalidKeySpecException e) {
        super(e);
    }

    public CryptoException(OperatorCreationException e) {
        super(e);
    }

    public CryptoException(PKCSException e) {
        super(e);
    }

    public CryptoException(CMSException e) {
        super(e);
    }

    public int getCode() {
        return code;
    }
}
