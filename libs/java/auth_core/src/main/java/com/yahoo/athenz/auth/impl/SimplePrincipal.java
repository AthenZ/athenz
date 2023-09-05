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

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;

public class SimplePrincipal implements Principal {

    private static final Logger LOG = LoggerFactory.getLogger(SimplePrincipal.class);
    
    String domain;
    String name = null;
    String fullName  = null;
    String creds;
    String unsignedCreds = null;
    String ip = null;
    long issueTime = 0;
    List<String> roles = null; 
    Authority authority;
    String authorizedService = null;
    String originalRequestor = null;
    String keyService = null;
    String keyId = null;
    X509Certificate x509Certificate = null;
    String applicationId = null;
    private boolean mtlsRestricted = false;
    String rolePrincipalName = null;

    // defaulting to ACTIVE state
    private Principal.State state = State.ACTIVE;

    public static Principal create(String domain, String name, String creds) {
        return create(domain, name, creds, 0, null);
    }

    /**
     * Create a Principal based on a given Access/Role Token or role certificate
     * @param domain Domain name that the RoleToken was issued for
     * @param creds Credentials of the principal (RoleToken)
     * @param roles List of roles defined in the token
     * @param authority authority responsible for the credentials (e.g. RoleAuthority)
     * @return a Principal for the given set of roles in a domain
     */
    public static Principal create(String domain, String creds, List<String> roles, Authority authority) {
        return create(domain, creds, roles, null, authority);
    }

    /**
     * Create a Principal based on a given Access/Role Token or role certificate
     * @param domain Domain name that the RoleToken was issued for
     * @param creds Credentials of the principal (RoleToken)
     * @param roles List of roles defined in the token
     * @param rolePrincipalName principal who requested the given access token or role certificate
     * @param authority authority responsible for the credentials (e.g. RoleAuthority)
     * @return a Principal for the given set of roles in a domain
     */
    public static Principal create(String domain, String creds, List<String> roles, String rolePrincipalName, Authority authority) {
        if (roles == null || roles.isEmpty()) {
            LOG.error("createRolePrincipal: zero roles");
            return null;
        }
        return new SimplePrincipal(domain, creds, roles, rolePrincipalName, authority);
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
        String matchDomain = (authority == null) ? null : authority.getDomain();
        if (matchDomain != null && !domain.equals(matchDomain)) {
            LOG.error("createPrincipal: domain mismatch for user {} in authority {}", name, authority);
            return null;
        }
        return new SimplePrincipal(domain, name, creds, issueTime, authority);
    }

    /** 
     * Create a Principal for the given host identity
     * @param appId Application identifier
     * @param creds Credentials of the principal
     * @param authority authority responsible for the credentials (e.g. HostAuthority)
     * @return a Principal for the host identity
     */
    public static Principal create(String appId, String creds, Authority authority) {
        if (appId == null) {
            LOG.error("createAppIdPrincipal: null appId");
            return null;
        }
        return new SimplePrincipal(null, appId, creds, 0, authority);
    }
    
    private SimplePrincipal(String domain, String name, String creds, long issueTime, Authority authority) {
        this.domain = domain;
        this.name = name;
        this.creds = creds;
        this.authority = authority;
        this.issueTime = issueTime;
    }

    private SimplePrincipal(String domain, String creds, List<String> roles, String rolePrincipalName, Authority authority) {
        this.domain = domain;
        this.creds = creds;
        this.roles = roles;
        this.authority = authority;
        this.rolePrincipalName = rolePrincipalName;
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
    
    public void setX509Certificate(X509Certificate x509Certificate) {
        this.x509Certificate = x509Certificate;
    }
    
    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }
    
    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public void setMtlsRestricted(boolean isMtlsRestricted) {
        this.mtlsRestricted = isMtlsRestricted;
    }

    public void setState(State state) {
        this.state = state;
    }

    public void setRolePrincipalName(String rolePrincipalName) {
        this.rolePrincipalName = rolePrincipalName;
    }

    @Override
    public String getIP() {
        return ip;
    }
    
    @Override
    public String getUnsignedCredentials() {
        return unsignedCreds;
    }
    
    @Override
    public Authority getAuthority() {
        return authority;
    }

    @Override
    public String getDomain() {
        return domain;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getOriginalRequestor() {
        return originalRequestor;
    }
    
    @Override
    public String getFullName() {
        
        if (fullName == null) {
            if (domain != null && name != null) {
                fullName = domain + "." + name;
            } else {
                fullName = (name != null) ? name : domain;
            }
        }
        
        return fullName;
    }
    
    @Override
    public String getCredentials() {
        return creds;
    }
    
    @Override
    public List<String> getRoles() {
        return roles;
    }

    @Override
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

    @Override
    public String getAuthorizedService() {
        return authorizedService;
    }
    
    @Override
    public String getKeyService() {
        return keyService;
    }
    
    @Override
    public String getKeyId() {
        return keyId;
    }

    @Override
    public X509Certificate getX509Certificate() {
        return x509Certificate;
    }
    
    @Override
    public String getApplicationId() {
        return this.applicationId;
    }

    @Override
    public boolean getMtlsRestricted() {
        return this.mtlsRestricted;
    }

    @Override
    public Principal.State getState() {
        return this.state;
    }

    @Override
    public String getRolePrincipalName() {
        return this.rolePrincipalName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        SimplePrincipal that = (SimplePrincipal) o;
        return getFullName().equals(that.getFullName());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getFullName());
    }
}
