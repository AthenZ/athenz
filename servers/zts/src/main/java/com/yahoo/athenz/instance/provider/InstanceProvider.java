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

import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.store.DataStore;

public class InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceProvider.class);
    private static final String HTTPS_SCHEME = "https";

    private DataStore dataStore;
    private List<String> providerEndpoints = Collections.emptyList();

    public InstanceProvider(DataStore dataStore) {
        
        this.dataStore = dataStore;
        
        // get the list of valid provider endpoints
        
        String endPoints = System.getProperty(ZTSConsts.ZTS_PROP_PROVIDER_ENDPOINTS);
        if (endPoints != null) {
            providerEndpoints = Arrays.asList(endPoints.split(","));
        }
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
        
        if (providerEndpoint == null || providerEndpoint.isEmpty()) {
            if (validProviderName) {
                LOGGER.error("getProviderClient: Unknown provider service name: {}",
                        provider);
            } else {
                LOGGER.error("getProviderClient: Provider service {} does not have endpoint defined",
                        provider);
            }
            return null;
        }

        // before using our endpoint we need to make sure
        // it's valid according to configuration settings
        
        if (!verifyProviderEndpoint(providerEndpoint)) {
            return null;
        }
        
        ProviderHostnameVerifier hostnameVerifier = new ProviderHostnameVerifier(provider);
        return new InstanceProviderClient(providerEndpoint, hostnameVerifier);
    }
    
    boolean verifyProviderEndpoint(String providerEndpoint) {
        
        // verify that we have a valid endpoint that ends in one of our
        // configured domains.
        
        java.net.URI uri = null;
        try {
            uri = new java.net.URI(providerEndpoint);
        } catch (URISyntaxException ex) {
            LOGGER.error("verifyProviderEndpoint: Unable to verify {}: {}", providerEndpoint,
                    ex.getMessage());
            return false;
        }
        
        String host = uri.getHost();
        if (host == null) {
            LOGGER.error("verifyProviderEndpoint: Provider endpoint {} has no host component",
                    providerEndpoint);
            return false;
        }
        host = host.toLowerCase();
        
        boolean valid = false;
        for (String endpoint : providerEndpoints) {
            valid = host.endsWith(endpoint);
            if (valid) {
                break;
            }
        }
        
        if (!valid) {
            LOGGER.error("verifyProviderEndpoint: Provider host {} does not match with any of the configured domains",
                    host);
            return false;
        }
            
        String scheme = uri.getScheme();
        if (scheme == null) {
            LOGGER.error("verifyProviderEndpoint: Provider endpoint {} has no scheme component",
                    providerEndpoint);
            return false;
        }
        
        scheme = scheme.toLowerCase();
        if (!(HTTPS_SCHEME.equalsIgnoreCase(scheme))) {
            LOGGER.error("verifyProviderEndpoint: Provider scheme {} is not https", scheme);
            return false;
        }
        
        return true;
    }
}
