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
package com.yahoo.athenz.common.server.debug;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;

/**
 * Implementation that performs validation of PAM.
 */
public class DebugUserAuthority implements Authority {

    private static final Logger LOG = LoggerFactory.getLogger(DebugUserAuthority.class);

    public DebugUserAuthority() {
    }

    @Override
    public void initialize() {
    }

    @Override
    public String getDomain() {
        return "user";
    }

    @Override
    public String getHeader() {
        return "Authorization";
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
    
    @Override
    public Principal authenticate(String creds, String remoteAddr, String httpMethod, StringBuilder errMsg) {
        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;

        // the HTTP Basic authorization format is: Basic base64(<username>:<password>)
        
        if (!creds.startsWith("Basic ")) {
            errMsg.append("UserAuthority:authenticate: credentials do not start with 'Basic '");
            LOG.error(errMsg.toString());
            return null;
        }
        
        // decode - need to skip the first 6 bytes for 'Basic '
        String decoded;
        try {
            decoded = new String(Base64.decode(creds.substring(6).getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            errMsg.append("UserAuthority:authenticate: factory exc=");
            LOG.error(errMsg.toString());
            return null;
        }

        String[] userArray = decoded.split(":");
        String username = userArray[0];

        if (LOG.isDebugEnabled()) {
            LOG.debug("UserAuthority.authenticate: valid user={}", username);
        }

        // all the role members in Athenz are normalized to lower case so we need to make
        // sure our principal's name and domain are created with lower case as well

        long issueTime = 0;
        SimplePrincipal princ = (SimplePrincipal) SimplePrincipal.create(getDomain().toLowerCase(),
                userArray[0].toLowerCase(), creds, issueTime, this);
        princ.setUnsignedCreds(creds);
        return princ;
    }
}
