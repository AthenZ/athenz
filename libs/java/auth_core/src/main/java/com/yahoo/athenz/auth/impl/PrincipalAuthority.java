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

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.AuthorityKeyStore;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.auth.token.Token;

public class PrincipalAuthority implements Authority, AuthorityKeyStore {
    
    private static final String USER_DOMAIN = "user";
    private static final String SYS_AUTH_DOMAIN = "sys.auth";
    private static final String ZMS_SERVICE = "zms";
    private static final String ZTS_SERVICE = "zts";
    
    static final String ATHENZ_PROP_TOKEN_OFFSET = "athenz.auth.principal.token_allowed_offset";
    private static final String ATHENZ_PROP_IP_CHECK_MODE = "athenz.auth.principal.remote_ip_check_mode";
    private static final String ATHENZ_PROP_USER_DOMAIN = "athenz.user_domain";
    
    public static final String HTTP_HEADER = "Athenz-Principal-Auth";
    public static final String ATHENZ_AUTH_CHALLENGE = "AthenzPrincipalToken realm=\"athenz\"";
    public static final String ATHENZ_PROP_PRINCIPAL_HEADER = "athenz.auth.principal.header";
    
    private static final Logger LOG = LoggerFactory.getLogger(PrincipalAuthority.class);

    enum IpCheckMode {
        OPS_ALL,
        OPS_WRITE,
        OPS_NONE
    }
    
    private KeyStore keyStore = null;
    private int allowedOffset;
    IpCheckMode ipCheckMode;
    final String userDomain;
    private final String headerName;
    
    public PrincipalAuthority() {
        allowedOffset = Integer.parseInt(System.getProperty(ATHENZ_PROP_TOKEN_OFFSET, "300"));
        ipCheckMode = IpCheckMode.valueOf(System.getProperty(ATHENZ_PROP_IP_CHECK_MODE,
                IpCheckMode.OPS_WRITE.toString()));
        userDomain = System.getProperty(ATHENZ_PROP_USER_DOMAIN, USER_DOMAIN);
        headerName = System.getProperty(ATHENZ_PROP_PRINCIPAL_HEADER, HTTP_HEADER);
        
        // case of invalid value, we'll default back to 5 minutes
        
        if (allowedOffset < 0) {
            allowedOffset = 300;
        }
    }

    @Override
    public String getID() {
        return "Auth-NTOKEN";
    }

    @Override
    public void initialize() {
    }

    @Override
    public String getDomain() {
        return null; //services *are* a domain
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
    public Principal authenticate(String signedToken, String remoteAddr, String httpMethod,
            StringBuilder errMsg) {

        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;
        if (LOG.isDebugEnabled()) {
            LOG.debug("Authenticating PrincipalToken: {}", signedToken);
        }

        PrincipalToken serviceToken;
        try {
            serviceToken = new PrincipalToken(signedToken);
        } catch (IllegalArgumentException ex) {
            errMsg.append("PrincipalAuthority:authenticate: Invalid token: exc=").
                   append(ex.getMessage()).append(" : credential=").
                   append(Token.getUnsignedToken(signedToken));
            LOG.error(errMsg.toString());
            return null;
        }

        /* before authenticating verify that if this is a valid
         * authorized service token or not and if required
         * components are provided (the method already logs
         * all error messages) */
        
        StringBuilder errDetail = new StringBuilder(512);
        if (!serviceToken.isValidAuthorizedServiceToken(errDetail)) {
            errMsg.append("PrincipalAuthority:authenticate: Invalid authorized service token: ");
            errMsg.append(errDetail).append(" : credential=").
                   append(Token.getUnsignedToken(signedToken));
            return null;
        }
        
        String tokenDomain = serviceToken.getDomain().toLowerCase();
        String tokenName = serviceToken.getName().toLowerCase();
        String keyService = serviceToken.getKeyService();
        boolean userToken = tokenDomain.equals(userDomain);
        
        /* get the public key for this token to validate signature */
        
        String publicKey = getPublicKey(tokenDomain, tokenName, keyService,
                serviceToken.getKeyId(), userToken);

        /* the validate method logs all error messages */
        
        boolean writeOp = isWriteOperation(httpMethod);
        if (!serviceToken.validate(publicKey, allowedOffset, !writeOp, errDetail)) {
            errMsg.append("PrincipalAuthority:authenticate: service token validation failure: ");
            errMsg.append(errDetail).append(" : credential=").
                   append(Token.getUnsignedToken(signedToken));
            return null;
        }

        /* if an authorized service signature is available then we're going to validate
         * that signature as well to support token chaining in Athenz and, if necessary,
         * bypass IP address mismatch for users */
        
        String authorizedServiceName = null;
        if (serviceToken.getAuthorizedServiceSignature() != null) {
            authorizedServiceName = validateAuthorizeService(serviceToken, errDetail);
            if (authorizedServiceName == null) {
                errMsg.append("PrincipalAuthority:authenticate: validation of authorized service failure: ").
                       append(errDetail).append(" : credential=").
                       append(Token.getUnsignedToken(signedToken));
                return null;
            }
        }
        
        /* if we have a usertoken and our remote ip check enabled, verify that the IP address
         * matches before allowing the operation go through */
        
        if (userToken && !remoteIpCheck(remoteAddr, writeOp, serviceToken, authorizedServiceName)) {
            errMsg.append("PrincipalAuthority:authenticate: IP Mismatch - token (").
                append(serviceToken.getIP()).append(") request (").
                append(remoteAddr).append(")");
            LOG.error(errMsg.toString());
            return null;
        }
        
        /* all the role members in Athenz are normalized to lower case so we need to make
         * sure our principal's name and domain are created with lower case as well */
        
        SimplePrincipal princ = (SimplePrincipal) SimplePrincipal.create(tokenDomain,
                tokenName, signedToken, serviceToken.getTimestamp(), this);
        princ.setUnsignedCreds(serviceToken.getUnsignedToken());
        princ.setAuthorizedService(authorizedServiceName);
        princ.setOriginalRequestor(serviceToken.getOriginalRequestor());
        princ.setKeyService(keyService);
        princ.setIP(serviceToken.getIP());
        princ.setKeyId(serviceToken.getKeyId());
        return princ;
    }

    boolean remoteIpCheck(String remoteAddr, boolean writeOp, PrincipalToken serviceToken,
            String authorizedServiceName) {
        
        boolean checkResult = true;
        switch (ipCheckMode) {
            case OPS_ALL:
                if (!remoteAddr.equals(serviceToken.getIP())) {
                    checkResult = false;
                }
                break;
            case OPS_WRITE:
                /* if we have a user token for a write operation and we have an IP address
                 * mismatch then we'll allow this authenticate request to proceed only if it's
                 * been configured with authorized user only. */
                
                if (writeOp && !remoteAddr.equals(serviceToken.getIP())) {
                    
                    if (authorizedServiceName == null) {
                        checkResult = false;
                    }
                }
                break;
            default:
                break;
        }
        
        return checkResult;
    }
    
    String getPublicKey(String tokenDomain, String tokenName, String keyService,
            String keyId, boolean userToken) {
        
        /* by default we're going to look for the public key for the domain
         * and service defined in the token */
        
        String publicKeyDomain = tokenDomain;
        String publicKeyService = tokenName;
        
        /* now let's handle the exceptions:
         * 1) if the token has a key service field set then only supported values are
         * either zms or zts, so we use sys.auth.zms or sys.auth.zts services
         * 2) if the token's domain is user then it's a user token or if it's sd then
         * it's our special project token so for those cases we are going to ask for
         * zms's own public key. */
    
        if (keyService != null && !keyService.isEmpty()) {
            if (keyService.equals(ZMS_SERVICE)) {
                publicKeyDomain = SYS_AUTH_DOMAIN;
                publicKeyService = ZMS_SERVICE;
            } else if (keyService.equals(ZTS_SERVICE)) {
                publicKeyDomain = SYS_AUTH_DOMAIN;
                publicKeyService = ZTS_SERVICE;
            }
        } else if (userToken) {
            publicKeyDomain = SYS_AUTH_DOMAIN;
            publicKeyService = ZMS_SERVICE;
        }

        return keyStore.getPublicKey(publicKeyDomain, publicKeyService, keyId);
    }
    
    boolean isWriteOperation(String httpMethod) {
        if (httpMethod == null) {
            return false;
        }
        return httpMethod.equalsIgnoreCase("PUT") || httpMethod.equalsIgnoreCase("POST")
                || httpMethod.equalsIgnoreCase("DELETE");
    }

    String getAuthorizedServiceName(List<String> authorizedServices, String authorizedServiceName) {
        
        /* if we have an authorized service name specified then it must be
         * present in the authorized services list or if it's null then the
         * list must contain a single element only */

        String serviceName = authorizedServiceName;
        if (serviceName == null) {
            if (authorizedServices.size() != 1) {
                LOG.error("getAuthorizedServiceName() failed: No authorized service name specified");
                return null;
            }
            serviceName = authorizedServices.get(0);
        } else {
            if (!authorizedServices.contains(serviceName)) {
                LOG.error("getAuthorizedServiceName() failed: Invalid authorized service name specified:"
                        + serviceName);
                return null;
            }
        }
        return serviceName;
    }
    
    String validateAuthorizeService(PrincipalToken userToken, StringBuilder errMsg) {
        
        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;
        
        /* if we have an authorized service name specified then it must be
         * present in the authorized services list or if it's null then the
         * list must contain a single element only */

        String authorizedServiceName = userToken.getAuthorizedServiceName();
        if (authorizedServiceName == null) {
            List<String> authorizedServices = userToken.getAuthorizedServices();
            if (authorizedServices == null || authorizedServices.size() != 1) {
                errMsg.append("PrincipalAuthority:validateAuthorizeService: ").
                       append("No service name and services list empty OR contains multiple entries: token=").
                       append(userToken.getUnsignedToken());
                return null;
            } else {
                authorizedServiceName = authorizedServices.get(0);
            }
        }
        
        /* need to extract domain and service name from our full service name value */
        
        int idx = authorizedServiceName.lastIndexOf('.');
        if (idx <= 0 || idx == authorizedServiceName.length() - 1) {
            errMsg.append("PrincipalAuthority:validateAuthorizeService: ").
                   append("failed: token=").append(userToken.getUnsignedToken()).
                   append(" : Invalid authorized service name specified=").
                   append(authorizedServiceName);
            LOG.error(errMsg.toString());
            return null;
        }
        
        String publicKey = keyStore.getPublicKey(authorizedServiceName.substring(0, idx),
                authorizedServiceName.substring(idx + 1), userToken.getAuthorizedServiceKeyId());
        
        /* the token method reports all error messages */
        StringBuilder errDetail = new StringBuilder(512);
        if (!userToken.validateForAuthorizedService(publicKey, errDetail)) {
            errMsg.append("PrincipalAuthority:validateAuthorizeService: token validation for authorized service failed: ").
                   append(errDetail);
            return null;
        }
        
        return authorizedServiceName;
    }
    
    @Override
    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }
}
