/**
 * Copyright 2016 Yahoo Inc.
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

package com.yahoo.athenz.zpe_policy_updater;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.sia.SIA;

public class SIAClientMock implements SIA {

    private final String svcVersion = "S1";
    private final String host = "somehost.somecompany.com";
    private final String salt = "saltvalue";
    private final long expirationTime = 10; // 10 seconds
    private PrivateKey servicePrivateKeyK0 = null;
    private PrivateKey servicePrivateKeyK1 = null;
    private String keyId = "0";
    
    private List<String> domainList = new ArrayList<String>();

    public SIAClientMock(boolean emptyDomainList) throws IOException 
    {
        loadKeys();
        
        if (emptyDomainList) {
            setDomainListEmpty();
        } else {
            setDomainList();
        }
    }

    public void setDomainListEmpty() {
        domainList.clear();
    }
    
    public void setDomainList() {
        domainList.add("sports");
        domainList.add("sys.auth");
    }
    
    private void loadKeys() throws IOException {
        Path path = Paths.get("./src/test/resources/zts_private_k0.pem");
        servicePrivateKeyK0 = Crypto.loadPrivateKey(new String(Files.readAllBytes(path)));

        path = Paths.get("./src/test/resources/zts_private_k1.pem");
        servicePrivateKeyK1 = Crypto.loadPrivateKey(new String(Files.readAllBytes(path)));
    }
    
    public void setPublicKeyId(String keyId) {
        this.keyId = keyId;
    }
    
    @Override
    public ArrayList<String> getDomainList() throws IOException {
        return (ArrayList<String>) domainList;
    }

    @Override
    public Principal getServicePrincipal(String domain, String service,
            Integer minExpiryTime, Integer maxExpiryTime, boolean ignoreCache) throws IOException {
        // Create and sign token
        PrincipalToken token = new PrincipalToken.Builder(svcVersion, domain, service)
            .host(host).salt(salt).issueTime(System.currentTimeMillis())
            .expirationWindow(expirationTime).keyId(keyId).build();
        
        if ("0".equals(keyId)) {
            token.sign(servicePrivateKeyK0);
        }else if ("1".equals(keyId)) {
            token.sign(servicePrivateKeyK1);
        }
        
        Principal principal = SimplePrincipal.create(domain, service, token.getSignedToken(), new PrincipalAuthority());
        
        // Create a token for validation using the signed data
        return principal;
    }

}
