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
import com.yahoo.athenz.auth.AuthorityKeyStore;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.RoleToken;
import com.yahoo.athenz.auth.token.Token;

public class RoleAuthority implements Authority, AuthorityKeyStore {
    
    private static final Logger LOG = LoggerFactory.getLogger(RoleAuthority.class);

    public final static String SYS_AUTH_DOMAIN = "sys.auth";
    public final static String ZTS_SERVICE_NAME = "zts";
    private static final String USER_DOMAIN = "user";
    
    static final String ATHENZ_PROP_TOKEN_OFFSET = "athenz.auth.role.token_allowed_offset";
    static final String ATHENZ_PROP_USER_DOMAIN = "athenz.user_domain";
    
    public static final String HTTP_HEADER = "Athenz-Role-Auth";
    public static final String ATHENZ_AUTH_CHALLENGE = "AthenzRoleToken realm=\"athenz\"";
    public static final String ATHENZ_PROP_ROLE_HEADER = "athenz.auth.role.header";
    
    private int allowedOffset;

    private KeyStore keyStore = null;
    String userDomain;
    String headerName;
    
    public RoleAuthority() {
        allowedOffset = Integer.parseInt(System.getProperty(ATHENZ_PROP_TOKEN_OFFSET, "300"));
        userDomain = System.getProperty(ATHENZ_PROP_USER_DOMAIN, USER_DOMAIN);
        headerName = System.getProperty(ATHENZ_PROP_ROLE_HEADER, HTTP_HEADER);

        // case of invalid value, we'll default back to 5 minutes
        
        if (allowedOffset < 0) {
            allowedOffset = 300;
        }
    }

    @Override
    public String getID() {
        return "Auth-ROLE";
    }

    @Override
    public void initialize() {
    }

    @Override
    public String getDomain() {
        return SYS_AUTH_DOMAIN;
    }

    @Override
    public String getHeader() {
        return headerName;
    }

    @Override
    public String getAuthenticateChallenge() {
        return ATHENZ_AUTH_CHALLENGE;
    }

    @Override
    public Principal authenticate(String signedToken, String remoteAddr, String httpMethod, StringBuilder errMsg) {

        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;
        if (LOG.isDebugEnabled()) {
            LOG.debug("Authenticating RoleToken: {}", signedToken);
        }

        RoleToken roleToken;
        try {
             roleToken = new RoleToken(signedToken);
        } catch (IllegalArgumentException ex) {
            errMsg.append("RoleAuthority:authenticate failed: Invalid token: exc=").
                   append(ex.getMessage()).append(" : credential=").
                   append(Token.getUnsignedToken(signedToken));
            LOG.error(errMsg.toString());
            return null;
        }

        /* if the token's domain is user then we need to check to see if this is a write
         * operation (PUT/POST/DELETE) and in that case we must validate the IP
         * address of the incoming request to make sure it matches to IP address
         * that's stored in the RoleToken */
        
        if (!remoteAddr.equals(roleToken.getIP()) && isWriteOperation(httpMethod)) {
            
            String tokenPrincipal = roleToken.getPrincipal();
            int idx = tokenPrincipal.lastIndexOf('.');
            if (idx <= 0 || idx == tokenPrincipal.length() - 1) {
                errMsg.append("RoleAuthority:authenticate failed: Invalid principal specified: ").
                       append(tokenPrincipal).append(" : credential=").
                       append(Token.getUnsignedToken(signedToken));
                LOG.error(errMsg.toString());
                return null;
            }
            
            if (tokenPrincipal.substring(0, idx).equalsIgnoreCase(userDomain)) {
                errMsg.append("RoleAuthority:authenticate failed: IP Mismatch - token-ip(").
                       append(roleToken.getIP()).append(") request-addr(").
                       append(remoteAddr).append(") : credential=").
                       append(Token.getUnsignedToken(signedToken));
                if (LOG.isWarnEnabled()) {
                    LOG.warn(errMsg.toString());
                }
                
                return null;
            }
        }
        
        String publicKey = keyStore.getPublicKey(SYS_AUTH_DOMAIN, ZTS_SERVICE_NAME, roleToken.getKeyId());

        if (!roleToken.validate(publicKey, allowedOffset, false)) {
            errMsg.append("RoleAuthority:authenticate failed: validation was not successful: credential=").
                    append(Token.getUnsignedToken(signedToken));
            if (LOG.isWarnEnabled()) {
                LOG.warn(errMsg.toString());
            }
            return null;
        }

        // all the role members in Athenz are normalized to lower case so we need to make
        // sure our principal's name and domain are created with lower case as well
        // we have verified that our token already includes valid roles
        
        SimplePrincipal princ = (SimplePrincipal) SimplePrincipal.create(roleToken.getDomain().toLowerCase(),
                signedToken, roleToken.getRoles(), roleToken.getPrincipal(), this);
        if (princ == null) {
            errMsg.append("RoleAuthority:authenticate failed: unable to create principal object");
            if (LOG.isWarnEnabled()) {
                LOG.warn(errMsg.toString());
            }
            return null;
        }
        princ.setUnsignedCreds(roleToken.getUnsignedToken());
        return princ;
    }

    boolean isWriteOperation(String httpMethod) {
        if (httpMethod == null) {
            return false;
        }
        return httpMethod.equalsIgnoreCase("PUT") || httpMethod.equalsIgnoreCase("POST")
                || httpMethod.equalsIgnoreCase("DELETE");
    }
    
    @Override
    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

}
