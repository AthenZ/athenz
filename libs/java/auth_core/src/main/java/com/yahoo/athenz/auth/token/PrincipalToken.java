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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;

public class PrincipalToken extends Token {

    private String name = null;
    private String originalRequestor = null;
    protected String keyService = null;
    private List<String> authorizedServices = null;
    private String authorizedServiceName = null;
    private String authorizedServiceKeyId = "0";
    private String authorizedServiceSignature = null;
    
    private static final Logger LOG = LoggerFactory.getLogger(PrincipalToken.class);

    public static class Builder {

        // required attributes
        private final String domain;
        private final String name;
        private final String version;
        
        // optional attributes with default values
        private String salt = Crypto.randomSalt();
        private String host = null;
        private String ip = null;
        private String keyId = "0";
        private long expirationWindow = 3600;
        private long issueTime = 0;
        private List<String> authorizedServices = null;
        private String keyService = null;
        private String originalRequestor = null;
        
        public Builder(String version, String domain, String name) {
            
            if (version == null || domain == null || name == null) {
                throw new IllegalArgumentException("version, domain and name parameters must not be null.");
            }
            
            if (version.isEmpty() || domain.isEmpty() || name.isEmpty()) {
                throw new IllegalArgumentException("version, domain and name parameters must have values.");
            }
            
            this.version = version;
            this.domain = domain;
            this.name = name;
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
        
        public Builder issueTime(long value) {
            this.issueTime = value;
            return this;
        }
        
        public Builder expirationWindow(long value) {
            this.expirationWindow = value;
            return this;
        }
        
        public Builder authorizedServices(List<String> authorizedServices) {
            this.authorizedServices = authorizedServices;
            return this;
        }
        
        public Builder keyService(String value) {
            this.keyService = value;
            return this;
        }
        
        public Builder originalRequestor(String value) {
            this.originalRequestor = value;
            return this;
        }
        
        public PrincipalToken build() {
            return new PrincipalToken(this);
        }
    }
    
    private PrincipalToken(Builder builder) {

        this.version = builder.version;
        this.domain = builder.domain;
        this.name = builder.name;
        this.host = builder.host;
        this.salt = builder.salt;
        this.keyId = builder.keyId;
        this.ip = builder.ip;
        this.authorizedServices = builder.authorizedServices;
        this.keyService = builder.keyService;
        this.originalRequestor = builder.originalRequestor;
        
        super.setTimeStamp(builder.issueTime, builder.expirationWindow);
        
        StringBuilder strBuilder = new StringBuilder(defaultBuilderBufSize);
        
        strBuilder.append("v=");
        strBuilder.append(version);
        strBuilder.append(";d=");
        strBuilder.append(domain);
        strBuilder.append(";n=");
        strBuilder.append(name);
        
        if (host != null && !host.isEmpty()) {
            strBuilder.append(";h=");
            strBuilder.append(host);
        }
        
        strBuilder.append(";a=");
        strBuilder.append(salt);
        strBuilder.append(";t=");
        strBuilder.append(timestamp);
        strBuilder.append(";e=");
        strBuilder.append(expiryTime);
        strBuilder.append(";k=");
        strBuilder.append(keyId);
        if (keyService != null && !keyService.isEmpty()) {
            strBuilder.append(";z=");
            strBuilder.append(keyService);
        }
        if (originalRequestor != null && !originalRequestor.isEmpty()) {
            strBuilder.append(";o=");
            strBuilder.append(originalRequestor);
        }
        if (ip != null && !ip.isEmpty()) {
            strBuilder.append(";i=");
            strBuilder.append(ip);
        }
        if (authorizedServices != null && !authorizedServices.isEmpty()) {
            strBuilder.append(";b=");
            strBuilder.append(String.join(",", authorizedServices));
        }
        
        unsignedToken = strBuilder.toString();
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("PrincipalToken created: {}", unsignedToken);
        }
    }

    public PrincipalToken(String signedToken) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Constructing PrincipalToken with input string: {}", signedToken);
        }
        
        if (signedToken == null || signedToken.isEmpty()) {
            throw new IllegalArgumentException("Input String signedToken must not be empty");
        }
        
        /*
         * first we need to extract data and signature parts
         * the signature is always at the end of the token. The principal
         * token can represent 2 types - service or user. The version
         * string identifies the type by using S or U. Here are two sample
         * tokens:
         * 
         * User:
         * v=U1;d=user;n=john;a=salt;t=tstamp;e=expiry;s=sig
         * 
         * Service:
         * v=S1;d=sports;n=storage;h=host.somecompany.com;a=salt;t=tstamp;e=expiry;s=sig
         *
         * v: version number U1 or S1 (string)
         * d: domain name (as passed by the client) or user for users
         * n: service name (as passed by the client) or username
         * h: hostname or IP address (string)
         * a: random 8 byte salt value hex encoded
         * t: timestamp when the token was generated
         * e: expiry timestamp based on SIA configuration
         * s: signature generated over the "v=U1;a=salt;...;e=expiry" string 
         *    using Service's private Key for service tokens and ZMS service's
         *    private key for user tokens and y64 encoded
         */

        String authzSvcToken = null;
        int idx = signedToken.indexOf(";s=");
        if (idx != -1) {
            unsignedToken = signedToken.substring(0, idx);

            // we might have authorized service token details after the signature
            // so we're going to extract our signature component.

            int authzIdx = signedToken.indexOf(';', idx + 3);
            if (authzIdx != -1 && signedToken.indexOf(";bs=", idx + 3) != -1) {
                signature = signedToken.substring(idx + 3, authzIdx);
                authzSvcToken = signedToken.substring(authzIdx);
            } else {
                signature = signedToken.substring(idx + 3);
            }
        }

        final String parseToken = unsignedToken != null ? unsignedToken : signedToken;
        for (String item : parseToken.split(";")) {
            String [] kv = item.split("=");
            if (kv.length == 2) {
                switch (kv[0]) {
                case "a":
                    salt = kv[1];
                    break;
                case "b":
                    authorizedServices = Arrays.asList(kv[1].split(","));
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
                case "n":
                    name = kv[1];
                    break;
                case "o":
                    originalRequestor = kv[1];
                    break;
                case "t":
                    timestamp = Long.parseLong(kv[1]);
                    break;
                case "v":
                    version = kv[1];
                    break;
                case "z":
                    keyService = kv[1];
                    break;
                }
            }
        }

        // now process the authorized service token part

        if (authzSvcToken != null && !authzSvcToken.isEmpty()) {
            idx = authzSvcToken.indexOf(";bs=");
            if (idx != -1) {
                authorizedServiceSignature = authzSvcToken.substring(idx + 4);

                for (String item : authzSvcToken.substring(0, idx).split(";")) {
                    String[] kv = item.split("=");
                    if (kv.length == 2) {
                        switch (kv[0]) {
                            case "bk":
                                authorizedServiceKeyId = kv[1];
                                break;
                            case "bn":
                                authorizedServiceName = kv[1];
                                break;
                        }
                    }
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
        
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("SignedToken does not contain required name component");
        }

        this.signedToken = signedToken;
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Values extracted from token version:{} domain:{} service:{} host:{}" +
                    " ip:{} id:{} keyService:{} originalRequestor:{} salt:{} timestamp:{}" +
                    " expiryTime:{} signature:{}", version, domain, name, host, ip, keyId,
                    keyService, originalRequestor, salt, timestamp, expiryTime, signature);
            if (authorizedServices != null) {
                LOG.debug("Authorized service details from token authorizedServices:{}" +
                        " authorizedServiceName:{} authorizedServiceKeyId:{} authorizedServiceSignature:{}",
                        String.join(",", authorizedServices), authorizedServiceName, authorizedServiceKeyId,
                        authorizedServiceSignature);
            }
        }
    }
    
    public void signForAuthorizedService(String authorizedServiceName, String authorizedServiceKeyId,
            String privKey) throws CryptoException {
        signForAuthorizedService(authorizedServiceName, authorizedServiceKeyId, Crypto.loadPrivateKey(privKey));
    }

    public void signForAuthorizedService(String authorizedServiceName, String authorizedServiceKeyId,
            PrivateKey key) throws CryptoException {
        
        /* first let's make sure the authorized service is one of the
         * listed service names in the PrincipalToken */
        
        if (authorizedServices == null || !authorizedServices.contains(authorizedServiceName)) {
            throw new IllegalArgumentException("Authorized Service is not valid for this token");
        }
        
        this.authorizedServiceKeyId = authorizedServiceKeyId;
        StringBuilder tokenToSign = new StringBuilder(512);
        tokenToSign.append(signedToken);
        tokenToSign.append(";bk=");
        tokenToSign.append(authorizedServiceKeyId);
        
        if (authorizedServices.size() > 1) {
            
            /* if the user has allowed multiple authorized services then we need
             * to keep track of which one is re-signing this token and as such
             * we'll store the service name as the value for the bn field */

            this.authorizedServiceName = authorizedServiceName;
            tokenToSign.append(";bn=");
            tokenToSign.append(authorizedServiceName);
        }
        
        authorizedServiceSignature = Crypto.sign(tokenToSign.toString(), key);
        
        /* now append our new signature to the token we just signed */
        
        tokenToSign.append(";bs=");
        tokenToSign.append(authorizedServiceSignature);
        signedToken = tokenToSign.toString();
    }
    
    public boolean validateForAuthorizedService(String pubKey, StringBuilder errMsg) {
        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;
        if (authorizedServiceSignature == null) {
            errMsg.append("PrincipalToken:validateForAuthorizedService: token=").
                   append(unsignedToken).
                   append(" : missing data/signature component: public key=").
                   append(pubKey);
            LOG.error(errMsg.toString());
            return false;
        }

        // since at this point authorizedServiceSignature is not null
        // our signed token has the ";bs=" component

        int idx = signedToken.indexOf(";bs=");
        String unsignedAuthorizedServiceToken = signedToken.substring(0, idx);
        
        if (pubKey == null) {
            errMsg.append("PrincipalToken:validateForAuthorizedService: token=").
                   append(unsignedToken).append(" : No public key provided");
            LOG.error(errMsg.toString());
            return false;
        }
        
        PublicKey pub;
        boolean verified = false; // fail safe
        try {
            pub = Crypto.loadPublicKey(pubKey);
            verified = Crypto.verify(unsignedAuthorizedServiceToken, pub, authorizedServiceSignature);
            if (!verified) {
                errMsg.append("PrincipalToken:validateForAuthorizedService: token=").
                       append(unsignedToken).append(" : authentication failed: public key=").
                       append(pubKey);
                LOG.error(errMsg.toString());
            } else if (LOG.isDebugEnabled()) {
                LOG.debug("validateForAuthorizedService: Token: {} -  successfully authenticated", unsignedToken);
            }
        } catch (Exception e) {
            errMsg.append("PrincipalToken:validateForAuthorizedService: token=").
                   append(unsignedToken).
                   append(" : authentication failed verifying signature: exc=").
                   append(e.getMessage()).append(" : public key=").append(pubKey);
            LOG.error(errMsg.toString());
        }

        return verified;
    }
    
    public boolean isValidAuthorizedServiceToken(StringBuilder errMsg) {
        
        /* we start our by checking if this is an authorized service token */
        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;
        if (authorizedServices == null) {
            
            /* if both the service name list and signature are not present
             * then we have a standard principal token */
            
            if (authorizedServiceSignature == null) {
                return true;
            }
            
            /* otherwise we have an invalid token without the signature */
            errMsg.append("PrincipalToken:isValidAuthorizedServiceToken: Invalid Token=").
                   append(unsignedToken).
                   append(" : Authorized Service Signature available without service name"); 
            LOG.error(errMsg.toString());
            return false;
        }
        
        /* if we have an authorized service name then we must have a corresponding
         * signature available in the token */
        
        if (authorizedServiceSignature == null) {
            errMsg.append("PrincipalToken:isValidAuthorizedServiceToken: Invalid Token=").
                   append(unsignedToken).
                   append(" : Missing signature for specified authorized service"); 
            LOG.error(errMsg.toString());
            return false;
        }
        
        /* if we have a specific authorized service name specified then
         * it must be present in our service list otherwise we must
         * have a single entry in our list */
        
        if (authorizedServiceName != null) {
            if (!authorizedServices.contains(authorizedServiceName)) {
                errMsg.append("PrincipalToken:isValidAuthorizedServiceToken: Invalid Token=").
                       append(unsignedToken).
                       append(" : Authorized service name=").append(authorizedServiceName).
                       append(" is not listed in the service list"); 
                LOG.error(errMsg.toString());
                return false;
            }
        } else if (authorizedServices.size() != 1) {
            errMsg.append("PrincipalToken:isValidAuthorizedServiceToken: Invalid Token=").
                   append(unsignedToken).
                   append(" : No service name and Authorized service list contains multiple entries"); 
            LOG.error(errMsg.toString());
            return false;
        }
        
        return true;
    }
    
    public String getName() {
        return name;
    }

    public String getKeyService() {
        return keyService;
    }
    
    public String getOriginalRequestor() {
        return originalRequestor;
    }
    
    public List<String> getAuthorizedServices() {
        return authorizedServices;
    }

    public String getAuthorizedServiceName() {
        return authorizedServiceName;
    }

    public String getAuthorizedServiceKeyId() {
        return authorizedServiceKeyId;
    }

    public String getAuthorizedServiceSignature() {
        return authorizedServiceSignature;
    }
}
