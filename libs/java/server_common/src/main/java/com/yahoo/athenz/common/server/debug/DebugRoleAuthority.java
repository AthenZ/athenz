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
import com.yahoo.athenz.auth.AuthorityKeyStore;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.RoleAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;

import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//this class does not verify the signature or the expiration times,
//just extracts what it needs for debugging purposes.
public class DebugRoleAuthority implements Authority, AuthorityKeyStore {

    private static final Logger LOG = LoggerFactory.getLogger(DebugRoleAuthority.class);
    private final String headerName = System.getProperty(RoleAuthority.ATHENZ_PROP_ROLE_HEADER, RoleAuthority.HTTP_HEADER);

    public String getDomain() {
        return null; //the domain is part of the principal for roles
    }

    public String getHeader() {
        return headerName;
    }
    
    public Principal authenticate(String zToken, String remoteAddr, String httpMethod, StringBuilder errMsg) {
        if (zToken == null) {
            return null;
        }
        String domainName = null;
        String roleNames = null;
        String version = null;
        if (zToken.indexOf(';') > 0) {
            for (String item : zToken.split(";")) {
                String [] kv = item.split("=");
                if (kv.length == 2) {
                    if ("d".equals(kv[0])) {
                        domainName = kv[1];
                    } else if ("r".equals(kv[0])) {
                        roleNames = kv[1];
                    } else if ("v".equals(kv[0])) {
                        version = kv[1];
                    }
                }
            }
        }
        if (!"Z1".equals(version)) { 
                return null; 
        }
        if (domainName == null || roleNames == null) {
            return null; 
        }

        //Expiration is not checked in this debugging class.

        List<String> roles = Arrays.asList(roleNames.split(","));
        Principal principal = SimplePrincipal.create(domainName, zToken, roles, this);
        if (LOG.isInfoEnabled()) {
            LOG.info("[debug-authenticated: '{}']", principal);
        }

        return principal;
    }

    @Override
    public void initialize() {
    }

    @Override
    public void setKeyStore(KeyStore keyStore) {
    }
}
