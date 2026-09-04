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
package com.amazonaws.cloudhsm.jce.provider;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreSpi;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;

public class StubKeyStoreSpi extends KeyStoreSpi {

    public static Key key;

    @Override
    public Key engineGetKey(String alias, char[] password) {
        return key;
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        return null;
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        return null;
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        return null;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) {
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) {
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) {
    }

    @Override
    public void engineDeleteEntry(String alias) {
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.emptyEnumeration();
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return false;
    }

    @Override
    public int engineSize() {
        return 0;
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return false;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        return false;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        return null;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) {
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) {
    }
}
