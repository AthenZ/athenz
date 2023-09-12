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
package com.yahoo.athenz.auth.token;

import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.util.Crypto;

public class RoleToken extends Token {

    protected List<String> roles;
    private String principal = null;
    private String proxyUser = null;
    private boolean domainCompleteRoleSet = false;
    
    private static final Logger LOG = LoggerFactory.getLogger(RoleToken.class);

    public static class Builder {

        // required attributes
        private final String domain;
        private final List<String> roles;
        private final String version;
        private String principal = null;
        private String proxyUser = null;
        private boolean domainCompleteRoleSet = false;
        
        // optional attributes with default values
        private String salt = Crypto.randomSalt();
        private String host = null;
        private String ip = null;
        private String keyId = "0";
        private long expirationWindow = 3600;
        private long issueTime = 0;
        
        // Note that it is expected that the Strings in roles should already be lowercased. 
        public Builder(String version, String domain, List<String> roles) {
            
            if (version == null || domain == null || roles == null) {
                throw new IllegalArgumentException("version, domain and roles parameters must not be null.");
            }
            
            if (version.isEmpty() || domain.isEmpty() || roles.isEmpty()) {
                throw new IllegalArgumentException("version, domain and roles parameters must have values.");
            }
            
            this.version = version;
            this.domain = domain;
            this.roles = roles;
        }
        
        public Builder principal(String value) {
            this.principal = value;
            return this;
        }
        
        public Builder host(String value) {
            this.host = value;
            return this;
        }
        
        public Builder salt(String value) {
            this.salt = value;
            return this;
        }
        
        public Builder ip(String value) {
            this.ip = value;
            return this;
        }
        
        public Builder keyId(String value) {
            this.keyId = value;
            return this;
        }
        
        public Builder proxyUser(String value) {
            this.proxyUser = value;
            return this;
        }
        
        public Builder issueTime(long value) {
            this.issueTime = value;
            return this;
        }
        
        public Builder expirationWindow(long value) {
            this.expirationWindow = value;
            return this;
        }
        
        public Builder domainCompleteRoleSet(boolean value) {
            this.domainCompleteRoleSet = value;
            return this;
        }
        
        public RoleToken build() {
            return new RoleToken(this);
        }
    }
    
    private RoleToken(Builder builder) {

        this.version = builder.version;
        this.domain = builder.domain;
        this.roles = builder.roles;
        this.host = builder.host;
        this.salt = builder.salt;
        this.keyId = builder.keyId;
        this.ip = builder.ip;
        this.principal = builder.principal;
        this.proxyUser = builder.proxyUser;
        this.domainCompleteRoleSet = builder.domainCompleteRoleSet;
        
        super.setTimeStamp(builder.issueTime, builder.expirationWindow);
        
        StringBuilder strBuilder = new StringBuilder(defaultBuilderBufSize);
        
        strBuilder.append("v=");
        strBuilder.append(version);
        strBuilder.append(";d=");
        strBuilder.append(domain);
        strBuilder.append(";r=");

        int i = 0;
        for (String role : roles) {
            strBuilder.append(role);
            if (++i != roles.size()) {
                strBuilder.append(",");
            }
        }
        
        if (domainCompleteRoleSet) {
            strBuilder.append(";c=1");
        }
        
        if (principal != null && !principal.isEmpty()) {
            strBuilder.append(";p=");
            strBuilder.append(principal);
        }
        
        if (host != null && !host.isEmpty()) {
            strBuilder.append(";h=");
            strBuilder.append(host);
        }
        
        if (proxyUser != null && !proxyUser.isEmpty()) {
            strBuilder.append(";proxy=");
            strBuilder.append(proxyUser);
        }
        
        strBuilder.append(";a=");
        strBuilder.append(salt);
        strBuilder.append(";t=");
        strBuilder.append(timestamp);
        strBuilder.append(";e=");
        strBuilder.append(expiryTime);
        strBuilder.append(";k=");
        strBuilder.append(keyId);
        if (ip != null && !ip.isEmpty()) {
            strBuilder.append(";i=");
            strBuilder.append(ip);
        }
        
        unsignedToken = strBuilder.toString();
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("RoleToken created: {}", unsignedToken);
        }
    }

    public RoleToken(String signedToken) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Constructing RoleToken with input string: {}", signedToken);
        }
        
        if (signedToken == null || signedToken.isEmpty()) {
            throw new IllegalArgumentException("Input String signedToken must not be empty");
        }
        
        /*
         * first we need to extract data and signature parts
         * the signature is always at the end of the token.
         * The format for the Token is as follows:
         * 
         * v=Z1;d=sports;r=role1,role2;a=salt;t=tstamp;e=expiry;k=1;s=sig
         *
         * v: version number Z1 (string)
         * d: domain name where the roles are valid for
         * r: list of comma separated roles
         * c: the list of roles is complete in domain
         * p: principal that got the token issued for
         * a: random 8 byte salt value hex encoded
         * t: timestamp when the token was generated
         * h: host that issued this role token
         * e: expiry timestamp based on SIA configuration
         * k: identifier - either version or zone name
         * s: signature generated over the "v=Z1;a=salt;...;e=expiry" string 
         *    using Service's private Key and y64 encoded
         * proxy: request was done by this authorized proxy user
         */

        int idx = signedToken.indexOf(";s=");
        if (idx != -1) {
            unsignedToken = signedToken.substring(0, idx);
            signature = signedToken.substring(idx + 3);
        }

        final String parseToken = unsignedToken != null ? unsignedToken : signedToken;
        String roleNames = null;
        for (String item : parseToken.split(";")) {
            String [] kv = item.split("=");
            if (kv.length == 2) {
                switch (kv[0]) {
                case "a":
                    salt = kv[1];
                    break;
                case "c":
                    if (Integer.parseInt(kv[1]) == 1) {
                        domainCompleteRoleSet = true;
                    }
                    break;
                case "d":
                    domain = kv[1];
                    break;
                case "e":
                    expiryTime = Long.parseLong(kv[1]);
                    break;
                case "h":
                    host = kv[1];
                    break;
                case "i":
                    ip = kv[1];
                    break;
                case "k":
                    keyId = kv[1];
                    break;
                case "p":
                    principal = kv[1];
                    break;
                case "r":
                    roleNames = kv[1];
                    break;
                case "t":
                    timestamp = Long.parseLong(kv[1]);
                    break;
                case "proxy":
                    proxyUser = kv[1];
                    break;
                case "v":
                    version = kv[1];
                    break;
                }
            }
        }

        /* the required attributes for the token are
         * domain and roles. The signature will be verified
         * during the authenticate phase but now we'll make
         * sure that domain and roles are present
         */
        
        if (domain == null || domain.isEmpty()) {
            throw new IllegalArgumentException("SignedToken does not contain required domain component");
        }
        
        if (roleNames == null || roleNames.isEmpty()) {
            throw new IllegalArgumentException("SignedToken does not contain required roles component");
        }
        
        roles = Arrays.asList(roleNames.split(","));

        this.signedToken = signedToken;

        if (LOG.isDebugEnabled()) {
            LOG.debug("Values extracted from token version:{} domain:{} roles:{} principal:{}" +
                    " host:{} salt:{} timestamp:{} expiryTime:{} domainCompleteRoleSet:{}" +
                    " keyId:{} ip:{} proxyUser:{} signature:{}", version, domain, roleNames,
                    principal, host, salt, timestamp, expiryTime, domainCompleteRoleSet, keyId,
                    ip, proxyUser, signature);
        }
    }
    
    public String getPrincipal() {
        return principal;
    }
    
    public List<String> getRoles() {
        return roles;
    }
    
    public String getProxyUser() {
        return proxyUser;
    }
    
    public boolean getDomainCompleteRoleSet() {
        return domainCompleteRoleSet;
    }
}
