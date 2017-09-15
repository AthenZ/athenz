package com.oath.auth;

/**
 * Copyright 2017 Yahoo Holdings, Inc.
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

import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * This class creates a key manager that wraps the existing X509KeyManager.  The goal is that it watches
 * the 'key' files and when they are updated, it upates the KeyManager under the covers.  This may
 * cause connections that are in the middle of a handshake to fail, but must NOT cause any already
 * established connections to fail.  This allow the changing of the SSL context on the fly without creating
 * new server / httpClient objects
 */
public class KeyManagerProxy implements X509KeyManager {

    private volatile X509KeyManager keyManager;

    public KeyManagerProxy(KeyManager[] keyManagers) {
        this.setKeyManager(keyManagers);
    }

    /**
     * overwrites the existing key manager.
     * @param keyManagers only the first element will be used, and MUST be a X509KeyManager
     */
    public void setKeyManager(final KeyManager[] keyManagers) {
        keyManager = (X509KeyManager) keyManagers[0];
    }

    @Override
    public String[] getClientAliases(String s, Principal[] principals) {
        return keyManager.getClientAliases(s, principals);
    }

    @Override
    public String chooseClientAlias(String[] strings, Principal[] principals, Socket socket) {
        return keyManager.chooseClientAlias(strings, principals, socket);
    }

    @Override
    public String[] getServerAliases(String s, Principal[] principals) {
        return keyManager.getServerAliases(s, principals);
    }

    @Override
    public String chooseServerAlias(String s, Principal[] principals, Socket socket) {
        return keyManager.chooseServerAlias(s, principals, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String s) {
        return keyManager.getCertificateChain(s);
    }

    @Override
    public PrivateKey getPrivateKey(String s) {
        return keyManager.getPrivateKey(s);
    }
}
