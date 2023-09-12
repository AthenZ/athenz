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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;

import javax.naming.AuthenticationException;
import javax.naming.AuthenticationNotSupportedException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Base64;
import java.util.Hashtable;

public class LDAPAuthority implements Authority {

    private static final Logger LOG = LoggerFactory.getLogger(LDAPAuthority.class);
    static final String ATHENZ_PROP_LDAP_BASE_DN = "athenz.auth.ldap.base_dn";
    static final String ATHENZ_PROP_LDAP_PORT = "athenz.auth.ldap.port";
    static final String ATHENZ_AUTH_CHALLENGE = "LDAPAuthentication realm=\"athenz\"";
    static final String ATHENZ_PROP_HOSTNAME = "athenz.auth.ldap.hostname";
    private String baseDN;
    private String providerURL;

    @Override
    public void initialize() {
        baseDN = System.getProperty(ATHENZ_PROP_LDAP_BASE_DN, "o=Athenz");
        final String portNumber = System.getProperty(ATHENZ_PROP_LDAP_PORT, "389");
        final String hostName = System.getProperty(ATHENZ_PROP_HOSTNAME, "localhost");
        providerURL = "ldap://" + hostName + ":" + portNumber;
    }

    @Override
    public String getID() {
        return "Auth-LDAP";
    }

    @Override
    public String getDomain() {
        return "user";
    }

    @Override
    public String getHeader() {
        return "Authorization";
    }

    @Override
    public String getAuthenticateChallenge() {
        return ATHENZ_AUTH_CHALLENGE;
    }

    @Override
    public boolean allowAuthorization() {
        return false;
    }

    @Override
    public Principal authenticate(String creds, String remoteAddr, String httpMethod, StringBuilder errMsg) {

        if (!creds.startsWith("Basic ")) {
            errMsg.append("LDAPAuthority: authenticate: credentials do not start with 'Basic '");
            LOG.error(errMsg.toString());
            return null;
        }

        final String encodedCreds = creds.substring(6);

        String decodedCreds;
        try {
            decodedCreds = new String(Base64.getDecoder().decode(encodedCreds));
        } catch (Exception e) {
            errMsg.append("LDAPAuthority: authenticate: factory exc=").append(e.getMessage());
            LOG.error(errMsg.toString());
            return null;
        }

        int idx = decodedCreds.indexOf(':');
        if (idx == -1) {
            errMsg.append("LDAPAuthority: authenticate: no password specified");
            LOG.error(errMsg.toString());
            return null;
        }

        final String username = decodedCreds.substring(0, idx);
        final String password = decodedCreds.substring(idx + 1);
        final String finalDN = "cn=" + username + "," + baseDN;

        try {
            DirContext ctx = getDirContext(finalDN, password);
            ctx.close();
        }   catch (AuthenticationException e) {
            errMsg.append("LDAPAuthority: failed: Wrong credentials");
            LOG.error(errMsg.toString());
            return null;
        }   catch (AuthenticationNotSupportedException e) {
            errMsg.append("LDAPAuthority: failed: Authentication method not supported");
            LOG.error(errMsg.toString());
            return null;
        }   catch (NamingException e) {
            errMsg.append("LDAPAuthority: failed: ").append(e.getMessage());
            LOG.error(errMsg.toString());
            return null;
        }

        SimplePrincipal simplePrincipal = getSimplePrincipal(creds, username);
        if (simplePrincipal == null) {
            errMsg.append("LDAPAuthority:authenticate: failed to create principal: user=").append(username);
            LOG.error(errMsg.toString());
            return null;
        }
        simplePrincipal.setUnsignedCreds(username);
        return simplePrincipal;
    }

    DirContext getDirContext(String finalDN, String password) throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, providerURL);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, finalDN);
        env.put(Context.SECURITY_CREDENTIALS, password);
        return new InitialDirContext(env);
    }

    SimplePrincipal getSimplePrincipal(String creds, String username) {
        return (SimplePrincipal) SimplePrincipal.create(getDomain(),
                username.toLowerCase(), creds, this);
    }
}
