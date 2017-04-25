/**
 * Copyright 2017 Yahoo Inc.
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
package com.yahoo.athenz.instance.provider;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.store.DataStore;

public class InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceProvider.class);

    private DataStore dataStore;
    
    public InstanceProvider(DataStore dataStore) {
        this.dataStore = dataStore;
    }
    
    public InstanceProviderClient getProviderClient(String provider) {
        int idx = provider.lastIndexOf('.');
        if (idx == -1) {
            LOGGER.error("getProviderClient: Invalid provider service name: {}", provider);
            return null;
        }
        
        final String domainName = provider.substring(0, idx);
        DataCache dataCache = dataStore.getDataCache(domainName);
        if (dataCache == null) {
            LOGGER.error("getProviderClient: Unknown domain: {}", domainName);
            return null;
        }
        
        String providerEndpoint = null;
        boolean validProviderName = false;
        List<com.yahoo.athenz.zms.ServiceIdentity> services = dataCache.getDomainData().getServices();
        if (services == null) {
            LOGGER.error("getProviderClient: Unknown provider servicee: {}", provider);
            return null;
        }
        
        for (com.yahoo.athenz.zms.ServiceIdentity service : services) {
            if (service.getName().equals(provider)) {
                providerEndpoint = service.getProviderEndpoint();
                validProviderName = true;
                break;
            }
        }

        // if we don't have an endpoint then we have an invalid and/or no service
        
        if (providerEndpoint == null) {
            if (validProviderName) {
                LOGGER.error("getProviderClient: Unknown provider service name: {}",
                        provider);
            } else {
                LOGGER.error("getProviderClient: Provider service {} does not have endpoint defined",
                        provider);
            }
            return null;
        }

        ProviderHostnameVerifier hostnameVerifier = new ProviderHostnameVerifier(provider);
        return new InstanceProviderClient(providerEndpoint, hostnameVerifier);
    }
}
