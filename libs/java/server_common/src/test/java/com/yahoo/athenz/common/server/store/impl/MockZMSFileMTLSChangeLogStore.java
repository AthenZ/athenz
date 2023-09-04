/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.yahoo.athenz.common.server.store.impl;

import com.oath.auth.KeyRefresherException;
import com.yahoo.athenz.zms.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static com.yahoo.athenz.common.ServerCommonConsts.PROP_USER_DOMAIN;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class MockZMSFileMTLSChangeLogStore extends ZMSFileMTLSChangeLogStore {

    private final ZMSClient zms = mock(ZMSClient.class);
    private boolean refreshSupport = false;

    public MockZMSFileMTLSChangeLogStore(String rootDirectory, final String keyPath, final String certPath,
                                     final String trustStorePath, final String trustStorePassword)
            throws InterruptedException, KeyRefresherException, IOException {

        super(rootDirectory, keyPath, certPath, trustStorePath, trustStorePassword);
        setZMSClient(zms);
        
        // setup some default values to return when the store is initialized
        // we're going to return on domain for local list and then another
        // for server list - thus ending up with initialized store with no domains
        
        final String userDomain = System.getProperty(PROP_USER_DOMAIN, "user");

        DomainList localDomainList = new DomainList();
        List<String> localDomains = new ArrayList<>();
        localDomains.add(userDomain);
        localDomainList.setNames(localDomains);
        
        DomainList serverDomainList = new DomainList();
        List<String> serverDomains = new ArrayList<>();
        serverDomains.add("sys");
        serverDomainList.setNames(serverDomains);

        when(zms.getDomainList()).thenReturn(localDomainList).thenReturn(serverDomainList);
    }

    public void setDomainList(List<String> domains) {
        if (domains != null) {
            DomainList domList = new DomainList();
            domList.setNames(domains);
            when(zms.getDomainList()).thenReturn(domList);
        } else {
            when(zms.getDomainList()).thenThrow(new ZMSClientException(500, "Invalid request"));
        }
    }
    
    public void setSignedDomains(SignedDomains signedDomains) {
        when(zms.getSignedDomains(any(), any(), any(), anyBoolean(), anyBoolean(), any(), any()))
                .thenReturn(signedDomains);
    }

    public void setJWSDomains(SignedDomains signedDomains) {
        if (signedDomains == null) {
            when(zms.getJWSDomain(any(), any(), any())).thenReturn(null);
        } else {
            for (SignedDomain signedDomain : signedDomains.getDomains()) {
                when(zms.getJWSDomain(signedDomain.getDomain().getName(), null, null)).thenReturn(new JWSDomain());
            }
        }
    }

    public void setSignedDomainsExc() {
        when(zms.getSignedDomains(any(), any(), any(), anyBoolean(), anyBoolean(), any(), any()))
                .thenThrow(new ZMSClientException(500, "Invalid request"));
    }

    public void setRefreshSupport(boolean refreshSupport) {
        this.refreshSupport = refreshSupport;
    }

    @Override
    public boolean supportsFullRefresh() {
        return refreshSupport;
    }
}
