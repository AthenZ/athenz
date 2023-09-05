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
package com.yahoo.athenz.auth.impl;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.ServiceIdentityProvider;
import com.yahoo.athenz.auth.token.PrincipalToken;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.PrivateKey;

/**
 * The SimpleServiceIdentityProvider does proper signing of an NToken, but
 * doesn't do anything to verify that the caller *should* have the private
 * key. For stand-alone services, a stronger guarantee is recommended. This class
 * could be used as a base class, to sign the credentials
 */
public class SimpleServiceIdentityProvider implements ServiceIdentityProvider {

    private static final Authority PRINCIPAL_AUTHORITY = new PrincipalAuthority();

    private final String domain;
    private final String service;
    private final PrivateKey key;
    private long tokenTimeout;
    private final String keyId;
    private String host = null;
    private Authority authority;
    
    /**
     * A simple implementation of the ServiceIdentityProvider interface.
     * The caller specifies the domain and service name along with the
     * private key for the given service
     * @param domainName Name of the domain
     * @param serviceName Name of the service
     * @param privateKey the private key for the service
     * @param keyId the registered key id in ZMS for this private key
     */
    public SimpleServiceIdentityProvider(String domainName, String serviceName,
            PrivateKey privateKey, String keyId) {
        this(PRINCIPAL_AUTHORITY, domainName, serviceName, privateKey, keyId, 3600);
    }
    
    /**
     * A simple implementation of the ServiceIdentityProvider interface.
     * The caller specifies the domain and service name along with the
     * private key for the given service
     * @param domainName Name of the domain
     * @param serviceName Name of the service
     * @param privateKey the private key for the service
     * @param keyId the registered key id in ZMS for this private key
     * @param tokenTimeout how long in seconds the generated ntoken is valid for
     */
    public SimpleServiceIdentityProvider(String domainName, String serviceName,
            PrivateKey privateKey, String keyId, long tokenTimeout) {
        this(PRINCIPAL_AUTHORITY, domainName, serviceName, privateKey, keyId, tokenTimeout);
    }
    
    /**
     * A simple implementation of the ServiceIdentityProvider interface.
     * The caller specifies the domain and service name along with the
     * private key for the given service and the authority to be used
     * @param authority Authority object for the generated principal
     * @param domainName Name of the domain
     * @param serviceName Name of the service
     * @param privateKey the private key for the service
     * @param keyId the registered key id in ZMS for this private key
     * @param tokenTimeout how long in seconds the generated ntoken is valid for
     */
    public SimpleServiceIdentityProvider(Authority authority, String domainName,
            String serviceName, PrivateKey privateKey, String keyId, long tokenTimeout) {

        this.authority = authority;
        this.domain = domainName.toLowerCase();
        this.service = serviceName.toLowerCase();
        this.key = privateKey;
        this.keyId = keyId.toLowerCase();
        this.tokenTimeout = tokenTimeout;
        this.setHost(getServerHostName());
    }
    
    public Principal getIdentity(String domainName, String serviceName) {
        
        // all the role members in Athenz are normalized to lower case so we need to make
        // sure our principal's name and domain are created with lower case as well
        
        domainName = domainName.toLowerCase();
        serviceName = serviceName.toLowerCase();
        
        // make sure we're handling correct domain and service
        
        if (!domainName.equals(domain) || !serviceName.equals(service)) {
            return null;
        }
        
        PrincipalToken token = new PrincipalToken.Builder("S1", domainName, serviceName)
            .expirationWindow(tokenTimeout).host(host).keyId(keyId).build();
        token.sign(key);
        
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create(domainName,
                serviceName, token.getSignedToken(), System.currentTimeMillis() / 1000,
                authority);
        principal.setUnsignedCreds(token.getUnsignedToken());
        return principal;
    }
    
    String getServerHostName() {
        
        String urlhost;
        try {
            InetAddress localhost = getLocalHost();
            urlhost = localhost.getCanonicalHostName();
        } catch (java.net.UnknownHostException e) {
            urlhost = "localhost";
        }
        return urlhost;
    }

    InetAddress getLocalHost() throws UnknownHostException {
        return java.net.InetAddress.getLocalHost();
    }




    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }
    
    public void setTokenTimeout(long tokenTimeout) {
        this.tokenTimeout = tokenTimeout;
    }

    public Authority getAuthority() {
        return authority;
    }

    public void setAuthority(Authority authority) {
        this.authority = authority;
    }
}
