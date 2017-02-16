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

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.Validate;

public class SimplePrincipal implements Principal {

    private static final Logger LOG = LoggerFactory.getLogger(SimplePrincipal.class);
    
    String domain = null;
    String name = null;
    String fullName  = null;
    String creds = null;
    String unsignedCreds = null;
    String ip = null;
    long issueTime = 0;
    List<String> roles = null; 
    Authority authority = null;
    String authorizedService = null;
    String originalRequestor = null;
    String keyService = null;
    String keyId = null;
    
    public static Principal create(String domain, String name, String creds) {
        return create(domain, name, creds, 0, null);
    }

    /**
     * Create a Principal based on a given RoleToken
     * @param domain Domain name that the RoleToken was issued for
     * @param creds Credentials of the principal (RoleToken)
     * @param roles List of roles defined in the token
     * @param authority authority responsible for the credentials (RoleAuthority)
     * @return a Principal for the given set of roles in a domain
     */
    public static Principal create(String domain, String creds, List<String> roles, Authority authority) {
        if (!Validate.domainName(domain)) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("WARNING: domain name doesn't validate: " + creds);
            }
        }
        if (roles == null || roles.size() == 0) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("WARNING: zero roles: " + creds);
            }
        }
        return new SimplePrincipal(domain, creds, roles, authority);
    }

    /** 
     * Create a Principal for the given identity
     * @param domain Domain name for the identity
     * @param name Name of the identity
     * @param creds Credentials of the principal (PrincipalToken which could be either UserToken or ServiceToken)
     * @param authority authority responsible for the credentials (e.g. PrincipalAuthority)
     * @return a Principal for the identity
     */
    public static Principal create(String domain, String name, String creds, Authority authority) {
        return create(domain, name, creds, 0, authority);
    }

    /** 
     * Create a Principal for the given user identity
     * @param domain Domain name for the identity (For users this will always be user)
     * @param name Name of the identity
     * @param creds Credentials of the principal (e.g. Cookie.User)
     * @param issueTime when the User Cookie/Credentials was issued
     * @param authority authority responsible for the credentials (e.g. UserAuthority)
     * @return a Principal for the identity
     */
    public static Principal create(String domain, String name, String creds, long issueTime, Authority authority) {
        
        if (!Validate.principalName(name)) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("WARNING: principal name doesn't validate: " + name);
            }
        }
        
        if (domain != null) {
            String matchDomain = (authority == null) ? null : authority.getDomain();
            if (matchDomain != null && !domain.equals(matchDomain)) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("FAIL: domain mismatch for user " + name + " in authority + " + authority);
                }
                return null;
            }
        } else if (authority != null) {
            if (authority.getDomain() != null) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("FAIL: domain mismatch for user " + name + " in authority + " + authority);
                }
                return null;
            }
        }
        return new SimplePrincipal(domain, name, creds, issueTime, authority);
    }

    /** 
     * Create a Principal for the given host identity
     * @param appId Application identifer
     * @param creds Credentials of the principal
     * @param authority authority responsible for the credentials (e.g. HostAuthority)
     * @return a Principal for the host identity
     */
    public static Principal create(String appId, String creds, Authority authority) {
        return new SimplePrincipal(null, appId, creds, 0, authority);
    }
    
    private SimplePrincipal(String domain, String name, String creds, long issueTime, Authority authority) {
        this.domain = domain;
        this.name = name;
        this.creds = creds;
        this.authority = authority;
        this.issueTime = issueTime;
    }

    private SimplePrincipal(String domain, String creds, List<String> roles, Authority authority) {
        this.domain = domain;
        this.creds = creds;
        this.roles = roles;
        this.authority = authority;
    }

    public void setUnsignedCreds(String unsignedCreds) {
        this.unsignedCreds = unsignedCreds;
    }
    
    public void setAuthorizedService(String authorizedService) {
        this.authorizedService = authorizedService;
    }
    
    public void setIP(String ip) {
        this.ip = ip;
    }
    
    public void setOriginalRequestor(String originalRequestor) {
        this.originalRequestor = originalRequestor;
    }
    
    public void setKeyService(String keyService) {
        this.keyService = keyService;
    }
    
    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }
    
    public String getIP() {
        return ip;
    }
    
    public String getUnsignedCredentials() {
        return unsignedCreds;
    }
    
    public Authority getAuthority() {
        return authority;
    }

    public String getDomain() {
        return domain;
    }

    public String getName() {
        return name;
    }

    public String getOriginalRequestor() {
        return originalRequestor;
    }
    
    public String getFullName() {
        
        if (fullName == null) {
            if (domain != null && name != null) {
                fullName = domain + "." + name;
            } else if (domain != null) {
                fullName = domain;
            } else if (name != null) {
                fullName = name;
            }
        }
        
        return fullName;
    }
    public String getCredentials() {
        return creds;
    }
    
    public List<String> getRoles() {
        return roles;
    }

    public long getIssueTime() {
        return issueTime;
    }
    
    public String toString() {
        if (roles == null) {
            return domain + "." + name;
        } else {
            return "ZToken_" + domain + "~" + roles.toString().replace("[", "").replace("]", "");
        }
    }

    public String getAuthorizedService() {
        return authorizedService;
    }
    
    public String getKeyService() {
        return keyService;
    }
    
    public String getKeyId() {
        return keyId;
    }
}
