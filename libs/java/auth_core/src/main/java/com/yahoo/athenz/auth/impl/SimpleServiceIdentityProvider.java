/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.auth.impl;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.ServiceIdentityProvider;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;

import java.io.File;
import java.net.InetAddress;
import java.security.PrivateKey;

/**
 * The SimpleServiceIdentityProvider does proper signing of an NToken, but
 * doesn't do anything to verify that the caller *should* have the private
 * key. For stand-alone services, a stronger guarantee is recommended. This class
 * could be used as a base class, to sign the credentials
 */
public class SimpleServiceIdentityProvider implements ServiceIdentityProvider {

    private PrivateKey key = null;
    private Authority authority = null;
    private long tokenTimeout = 3600;
    private String keyId = "0";
    private String host = null;

    public SimpleServiceIdentityProvider(Authority authority, File privateKeyFile) throws CryptoException {
        this(authority, Crypto.loadPrivateKey(privateKeyFile), "0", 3600);
    }

    public SimpleServiceIdentityProvider(Authority authority, String privateKey) throws CryptoException {
        this(authority, Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privateKey)), "0", 3600);
    }

    public SimpleServiceIdentityProvider(Authority authority, PrivateKey privateKey) {
        this(authority, privateKey, "0", 3600);
    }

    public SimpleServiceIdentityProvider(Authority authority, PrivateKey privateKey, long tokenTimeout) {
        this(authority, privateKey, "0", tokenTimeout);
    }

    public SimpleServiceIdentityProvider(Authority authority, PrivateKey privateKey, 
            String keyId, long tokenTimeout) {
        this.authority = authority;
        this.key = privateKey;
        this.tokenTimeout = tokenTimeout;
        this.keyId = keyId.toLowerCase();
        this.setHost(getServerHostName());
    }
    
    public Principal getIdentity(String domainName, String serviceName) {
        
        // all the role members in Athenz are normalized to lower case so we need to make
        // sure our principal's name and domain are created with lower case as well
        
        domainName = domainName.toLowerCase();
        serviceName = serviceName.toLowerCase();
        
        PrincipalToken token = new PrincipalToken.Builder("S1", domainName, serviceName)
            .expirationWindow(tokenTimeout).host(host).keyId(keyId).build();
        token.sign(key);
        
        SimplePrincipal princ = (SimplePrincipal) SimplePrincipal.create(domainName,
                serviceName, token.getSignedToken(), System.currentTimeMillis() / 1000, authority);
        princ.setUnsignedCreds(token.getUnsignedToken());
        return princ;
    }
    
    String getServerHostName() {
        
        String urlhost = null;
        try {
            InetAddress localhost = java.net.InetAddress.getLocalHost();
            urlhost = localhost.getCanonicalHostName();
        } catch (java.net.UnknownHostException e) {
            urlhost = "localhost";
        }
        
        return urlhost;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }
}
