/*
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
package com.yahoo.athenz.zts.store.impl;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.mockito.Mockito;

import com.yahoo.athenz.zms.DomainList;
import com.yahoo.athenz.zms.SignedDomains;
import com.yahoo.athenz.zms.ZMSClient;
import com.yahoo.athenz.zms.ZMSClientException;
import com.yahoo.athenz.zts.ZTSConsts;

public class MockZMSFileChangeLogStore extends ZMSFileChangeLogStore {

    private final ZMSClient zms;
    private DomainList domList = null;
    private String tagHeader;

    public MockZMSFileChangeLogStore(String rootDirectory, PrivateKey privateKey, String privateKeyId) {
        
        super(rootDirectory, privateKey, privateKeyId);
        zms = mock(ZMSClient.class);
        
        // setup some default values to return when the store is initialized
        // we're going to return on domain for local list and then another
        // for server list - thus ending up with initialized store with no domains
        
        final String userDomain = System.getProperty(ZTSConsts.ZTS_PROP_USER_DOMAIN, "user");

        DomainList localDomainList = new DomainList();
        List<String> localDomains = new ArrayList<>();
        localDomains.add(userDomain);
        localDomainList.setNames(localDomains);
        
        DomainList serverDomainList = new DomainList();
        List<String> serverDomains = new ArrayList<>();
        serverDomains.add("sys");
        serverDomainList.setNames(serverDomains);
        
        tagHeader = "2014-01-01T12:00:00";
        when(zms.getDomainList()).thenReturn(localDomainList).thenReturn(serverDomainList);
        
    }
    
    @Override
    public ZMSClient getZMSClient() {
        return zms;
    }

    public void setDomainList(List<String> domains) {
        if (domains != null) {
            domList = new DomainList();
            domList.setNames(domains);
            when(zms.getDomainList()).thenReturn(domList);
        } else {
            when(zms.getDomainList()).thenThrow(new ZMSClientException(500, "Invalid request"));
        }
    }
    
    @SuppressWarnings("unchecked")
    public void setSignedDomains(SignedDomains signedDomains) {
        if (signedDomains != null) {
            when(zms.getSignedDomains(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.<Map>any())).thenReturn(signedDomains);
        } else {
            when(zms.getSignedDomains(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.<Map>any())).thenThrow(new ZMSClientException(500, "Invalid request"));
        }
    }
    
    public void setTagHeader(String tagHeader) {
        this.tagHeader = tagHeader;
    }
    
    @Override
    public String retrieveTagHeader(Map<String, List<String>> responseHeaders) {
        if (tagHeader == null) {
            return super.retrieveTagHeader(responseHeaders);
        } else {
            return tagHeader;
        }
    }
}
