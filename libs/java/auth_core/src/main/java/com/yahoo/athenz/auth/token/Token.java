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
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;

public class Token {
    private static final Logger LOG = LoggerFactory.getLogger(Token.class);

    protected final int defaultBuilderBufSize = 512;
    
    protected String unsignedToken = null;
    protected String signedToken   = null;
    protected String version = null;
    protected String salt = null;
    protected String host = null;
    protected String ip = null;
    protected String domain = null;
    protected String signature = null;
    protected String keyId = "0";
    protected long expiryTime = 0;
    protected long timestamp = 0;
    protected String digestAlgorithm = Crypto.SHA256;
    
    private static final String ATHENZ_PROP_TOKEN_MAX_EXPIRY = "athenz.token_max_expiry";
    private static final long ATHENZ_TOKEN_MAX_EXPIRY = Long.parseLong(
            System.getProperty(ATHENZ_PROP_TOKEN_MAX_EXPIRY, Long.toString(TimeUnit.SECONDS.convert(30, TimeUnit.DAYS))));
    private static final String ATHENZ_PROP_TOKEN_NO_EXPIRY = "athenz.token_no_expiry";
    static Boolean ATHENZ_TOKEN_NO_EXPIRY = Boolean.parseBoolean(
            System.getProperty(ATHENZ_PROP_TOKEN_NO_EXPIRY, "false"));

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }
    public void sign(String privKey) throws CryptoException {
        sign(Crypto.loadPrivateKey(privKey));
    }

    public void sign(PrivateKey key) throws CryptoException {
        signature = Crypto.sign(unsignedToken, key, getDigestAlgorithm());
        signedToken = unsignedToken + ";s=" + signature;
    }
    
    public void setTimeStamp(long issueTime, long expirationWindow) {
        timestamp = (issueTime > 0) ? issueTime : System.currentTimeMillis() / 1000;
        expiryTime = timestamp + expirationWindow;
    }

    public boolean validate(String pubKey, int allowedOffset) {
        return validate(pubKey, allowedOffset, false, null);
    }
    
    public boolean validate(String pubKey, int allowedOffset, boolean allowNoExpiry) {
        return validate(pubKey, allowedOffset, allowNoExpiry, null);
    }

    public boolean validate(String pubKey, int allowedOffset, boolean allowNoExpiry,
            StringBuilder errMsg) {

        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;
        if (pubKey == null) {
            errMsg.append("Token:validate: token=").append(unsignedToken).
                   append(" : No public key provided");
            LOG.error(errMsg.toString());
            return false;
        }

        PublicKey publicKey;
        try {
            publicKey = Crypto.loadPublicKey(pubKey);
        } catch (Exception e) {
            errMsg.append("Token:validate: token=").append(unsignedToken).
                   append(" : unable to load public key due to Exception=").
                   append(e.getMessage());
            LOG.error(errMsg.toString());
            return false;
        }
        
        return validate(publicKey, allowedOffset, allowNoExpiry, errMsg);
    }
    
    public boolean validate(PublicKey publicKey, int allowedOffset, boolean allowNoExpiry,
            StringBuilder errMsg) {
        
        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;
        if (unsignedToken == null || signature == null) {
            errMsg.append("Token:validate: token=").append(unsignedToken).
                   append(" : missing data/signature component");
            LOG.error(errMsg.toString());
            return false;
        }
        
        if (publicKey == null) {
            errMsg.append("Token:validate: token=").append(unsignedToken).
                   append(" : No public key provided");
            LOG.error(errMsg.toString());
            return false;
        }
        
        long now = System.currentTimeMillis() / 1000;

        // make sure the token does not have a timestamp in the future
        // we'll allow the configured offset between servers

        if (timestamp != 0 && timestamp - allowedOffset > now) {
            errMsg.append("Token:validate: token=").append(unsignedToken).
                   append(" : has future timestamp=").append(timestamp).
                   append(" : current time=").append(now).
                   append(" : allowed offset=").append(allowedOffset);
            LOG.error(errMsg.toString());
            return false;
        }

        // make sure we don't have unlimited tokens unless we have
        // explicitly enabled that option for our system. by default
        // they should have an expiration date of less than 30 days
        
        if (expiryTime != 0 || !ATHENZ_TOKEN_NO_EXPIRY || !allowNoExpiry) {
            if (expiryTime < now) {
                errMsg.append("Token:validate: token=").append(unsignedToken).
                       append(" : has expired time=").append(expiryTime).
                       append(" : current time=").append(now);
                LOG.error(errMsg.toString());
                return false;
            }
    
            if (expiryTime > now + ATHENZ_TOKEN_MAX_EXPIRY + allowedOffset) {
                errMsg.append("Token:validate: token=").append(unsignedToken).
                    append(" : expires too far in the future=").append(expiryTime).
                    append(" : current time=").append(now).
                    append(" : max expiry=").append(ATHENZ_TOKEN_MAX_EXPIRY).
                    append(" : allowed offset=").append(allowedOffset);
                LOG.error(errMsg.toString());
                return false;
            }
        }
        
        boolean verified = false; // fail safe
        try {
            verified = Crypto.verify(unsignedToken, publicKey, signature, getDigestAlgorithm());
            if (!verified) {
                errMsg.append("Token:validate: token=").append(unsignedToken).
                       append(" : authentication failed");
                LOG.error(errMsg.toString());
            } else if (LOG.isDebugEnabled()) {
                LOG.debug("validate: Token successfully authenticated");
            }
        } catch (Exception e) {
            errMsg.append("Token:validate: token=").append(unsignedToken).
                   append(" : verify signature failed due to Exception=").
                   append(e.getMessage());
            LOG.error(errMsg.toString());
        }

        return verified;
    }

    public String getVersion() {
        return version;
    }

    public String getSalt() {
        return salt;
    }

    public String getHost() {
        return host;
    }

    public String getDomain() {
        return domain;
    }

    public String getSignature() {
        return signature;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public long getExpiryTime() {
        return expiryTime;
    }

    public String getSignedToken() {
        return signedToken;
    }
    
    public String getKeyId() {
        return keyId;
    }
    
    public String getIP() {
        return ip;
    }
    
    public String getUnsignedToken() {
        return unsignedToken;
    }

    /**
     * Helper method to parse a credential to remove the signature from the
     * raw credential string. Returning the unsigned credential.
     * @param credential full token credentials including signature
     * @return credentials without the signature
    **/
    public static String getUnsignedToken(String credential) {
        int idx = credential.indexOf(";s=");
        if (idx != -1) {
            credential = credential.substring(0, idx);
        }

        return credential;
    }
}
