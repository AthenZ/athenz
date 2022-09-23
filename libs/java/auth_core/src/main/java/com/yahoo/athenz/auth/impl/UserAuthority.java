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

import java.nio.charset.StandardCharsets;

import org.bouncycastle.util.encoders.Base64;
import org.jvnet.libpam.PAM;
import org.jvnet.libpam.PAMException;
import org.jvnet.libpam.UnixUser;

/**
 * Implementation that performs validation of PAM.
 */
public class UserAuthority implements Authority {

    private static final Logger LOG = LoggerFactory.getLogger(UserAuthority.class);
    static final String ATHENZ_PROP_PAM_SERVICE_NAME = "athenz.auth.user.pam_service_name";
    public static final String ATHENZ_AUTH_CHALLENGE = "Basic realm=\"athenz\"";

    String serviceName;
    private PAM pam = null;
    
    public UserAuthority() {
        serviceName = System.getProperty(ATHENZ_PROP_PAM_SERVICE_NAME, "login");
    }

    @Override
    public void initialize() {
    }

    @Override
    public String getID() {
        return "Auth-UNIX";
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

    /*
     * we don't want the user to keep specifying their username and
     * password as part of the request. instead, the user must first
     * request a usertoken and then use that usertoken for all other
     * requests against ZMS and ZTS servers.
     * @see com.yahoo.athenz.auth.Authority#allowAuthorization()
     */
    @Override
    public boolean allowAuthorization() {
        return false;
    }
    
    void setPAM(PAM pam) {
        this.pam = pam;
    }
    
    PAM getPAM() throws PAMException {
        if (pam != null) {
            return pam;
        }
        return new PAM(serviceName);
    }
    
    @Override
    public Principal authenticate(String creds, String remoteAddr, String httpMethod, StringBuilder errMsg) {
        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;

        // the HTTP Basic authorization format is: Basic base64(<username>:<password>)
        
        if (!creds.startsWith("Basic ")) {
            errMsg.append("UserAuthority:authenticate: credentials do not start with 'Basic '");
            LOG.error(errMsg.toString());
            return null;
        }

        final String encodedPassword = creds.substring(6);
        if (encodedPassword.isEmpty()) {
            errMsg.append("UserAuthority:authenticate: no credentials after 'Basic '");
            LOG.error(errMsg.toString());
            return null;
        }

        // decode - need to skip the first 6 bytes for 'Basic '
        
        String decodedCreds;
        try {
            decodedCreds = new String(Base64.decode(encodedPassword.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            errMsg.append("UserAuthority:authenticate: factory exc=").append(e.getMessage());
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

        // we need to catch all exceptions here and just return
        // failure to allow other authorities to handle authentication
        // if necessary
        
        UnixUser user;
        try {
            user = getPAM().authenticate(username, password);
        } catch (Throwable ex) {
            errMsg.append("UserAuthority:authenticate: failed: user=").append(username).
                append(" exc=").append(ex.getMessage());
            LOG.error(errMsg.toString());
            return null;
        }
        
        if (user == null) {
            errMsg.append("UserAuthority:authenticate: failed: user=").append(username);
            LOG.error(errMsg.toString());
            return null;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("UserAuthority.authenticate: valid user={}", username);
        }

        // all the role members in Athenz are normalized to lower case so we need to make
        // sure our principal's name and domain are created with lower case as well

        long issueTime = 0;
        SimplePrincipal princ = getSimplePrincipal(username.toLowerCase(), creds, issueTime);
        if (princ == null) {
            errMsg.append("UserAuthority:authenticate: failed to create principal: user=")
                .append(username);
            LOG.error(errMsg.toString());
            return null;
        }
        princ.setUnsignedCreds(username);
        return princ;
    }

    SimplePrincipal getSimplePrincipal(String name, String creds, long issueTime) {
        return (SimplePrincipal) SimplePrincipal.create(getDomain(),
                name, creds, issueTime, this);
    }
}
