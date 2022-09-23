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

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An example com.yahoo.rest.Authority implementation that uses Kerberos ticket without real validation.
 * This makes it easy to fake tickets for arbitrary users to test many different users.
 * THIS IS FOR TESTING ONLY
 */
public class DebugKerberosAuthority implements Authority {

    private static final Logger LOG = LoggerFactory.getLogger(DebugKerberosAuthority.class);

    static final String KRB_HEADER    = "Authorization";
    static final String TOKEN_PREFIX  = "Negotiate";
    static final String USER_DOMAIN   = "user";

    // for setting default debug user name to be used in returned Principals
    public static final String ATHENZ_PROP_USER_NAME = "athenz.common.server.debug.krb_tkt_user_name";
    public static final String ATHENZ_PROP_USER_DOMAIN = "athenz.user_domain";

    // if Authorization header contains fake ticket with debug field, then use
    // the suffix as the user name
    // ex: "Negotiate debug:jamesdean"
    // The user name returned in the principal would be "jamesdean"
    static final String TOKEN_DEBUG_USER_FIELD = "debug:";

    String defaultUserName = "anonymous";
    String userDomain = USER_DOMAIN;
    
    public String getDomain() {
        return userDomain;
    }

    public String getHeader() {
        return KRB_HEADER;
    }

    public Principal authenticate(String creds, String remoteAddr, String httpMethod, StringBuilder errMsg) {
        String uname = defaultUserName;
        if (creds == null) {
            LOG.debug("DebugKerberosAuthority:authenticate: Missing ticket");
            return null;
        } else if (!creds.startsWith(TOKEN_PREFIX)) {
            LOG.debug("DebugKerberosAuthority:authenticate: bad format: Missing prefix={} in ticket={}", TOKEN_PREFIX, creds);
            return null;
        } else {
            creds = creds.substring(TOKEN_PREFIX.length()).trim();
            if (creds.startsWith(TOKEN_DEBUG_USER_FIELD)) {
                uname = creds.substring(TOKEN_DEBUG_USER_FIELD.length()).trim();
            }
        }
        return SimplePrincipal.create(getDomain(), uname, creds, this);
    }

    @Override
    public void initialize() {
        defaultUserName = System.getProperty(ATHENZ_PROP_USER_NAME, "anonymous");
        userDomain = System.getProperty(ATHENZ_PROP_USER_DOMAIN, USER_DOMAIN);
    }
}

