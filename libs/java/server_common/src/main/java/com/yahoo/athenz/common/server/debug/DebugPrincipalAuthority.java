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
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//this class does not verify the signature.
//to do that, it would need to get the public key from ZMS
public class DebugPrincipalAuthority implements Authority, AuthorityKeyStore {

    private static final Logger LOG = LoggerFactory.getLogger(DebugPrincipalAuthority.class);
    private final String headerName = System.getProperty(PrincipalAuthority.ATHENZ_PROP_PRINCIPAL_HEADER, PrincipalAuthority.HTTP_HEADER);
    
    public String getDomain() {
        return null; //services *are* a domain
    }
    
    public String getHeader() {
        return headerName;
    }
    
    public Principal authenticate(String nToken, String remoteAddr, String httpMethod, StringBuilder errMsg) {
        
        if (nToken == null) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Token was not specified for authentication");
            }
            
            return null;
        }

        if (LOG.isInfoEnabled()) {
            LOG.info("Principal Authority: authenticating token: {}", nToken);
        }
        
        String domainName = null;
        String serviceName = null;
        if (nToken.indexOf(';') > 0) {
            for (String item : nToken.split(";")) {
                String [] kv = item.split("=");
                if (kv.length == 2) {
                    if ("d".equals(kv[0])) {
                        domainName = kv[1];
                    } else if ("n".equals(kv[0])) {
                        serviceName = kv[1];
                    }
                }
            }
        }

        if (domainName == null || serviceName == null) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Unable to extract domain or service names");
            }

            return null; 
        }
        String fullName = domainName + "." + serviceName;
        if (LOG.isInfoEnabled()) {
            LOG.info("[debug-authenticated: {}]", fullName);
        }

        return SimplePrincipal.create(domainName, serviceName, nToken, 0, this);
    }

    @Override
    public void initialize() {
    }
    
    @Override
    public void setKeyStore(KeyStore keyStore) {
    }
}
