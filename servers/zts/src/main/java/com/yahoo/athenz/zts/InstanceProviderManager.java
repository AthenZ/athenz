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
package com.yahoo.athenz.zts;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.impl.InstanceHttpProvider;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.store.DataStore;

public class InstanceProviderManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceProviderManager.class);
    private static final String SCHEME_HTTPS = "https";
    private static final String SCHEME_CLASS = "class";

    private ConcurrentHashMap<String, Class<?>> classMap;
    private DataStore dataStore;
    List<String> providerEndpoints = Collections.emptyList();

    enum ProviderScheme {
        UNKNOWN,
        HTTPS,
        CLASS
    }
    
    public InstanceProviderManager(DataStore dataStore) {
        
        this.dataStore = dataStore;
        classMap = new ConcurrentHashMap<>();
        
        // get the list of valid provider endpoints
        
        String endPoints = System.getProperty(ZTSConsts.ZTS_PROP_PROVIDER_ENDPOINTS);
        if (endPoints != null) {
            providerEndpoints = Arrays.asList(endPoints.split(","));
        }
    }
    
    public InstanceProvider getProvider(String provider) {
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
        
        InstanceProvider instanceProvider = null;
        URI uri = null;
        try {
            uri = new URI(providerEndpoint);
        } catch (URISyntaxException ex) {
            LOGGER.error("getProviderClient: Unable to parse {}: {}", providerEndpoint,
                    ex.getMessage());
            return null;
        }
        
        ProviderScheme schemeType = getProviderEndpointScheme(uri);
        switch (schemeType) {
        case HTTPS:
            instanceProvider = new InstanceHttpProvider();
            break;
        case CLASS:
            instanceProvider = getClassInstance(uri.getHost());
            break;
        default:
            break;
        }
        
        if (instanceProvider != null) {
            instanceProvider.initialize(provider, providerEndpoint);
        }
        
        return instanceProvider;
    }
    
    InstanceProvider getClassInstance(String className) {
        InstanceProvider provider = null;
        Class<?> instanceClass = classMap.get(className);
        if (instanceClass == null) {
            try {
                instanceClass = Class.forName(className);
            } catch (ClassNotFoundException e) {
                LOGGER.error("getClassInstance: Provider class {} not found", className);
                return null;
            }
            classMap.put(className, instanceClass);
        }
        try {
            provider = (InstanceProvider) instanceClass.newInstance();
        } catch (InstantiationException | IllegalAccessException ex) {
            LOGGER.error("getClassInstance: Unable to get new instance for provider {} error {}",
                    className, ex.getMessage());
        }
        return provider;
    }
    
    ProviderScheme getProviderScheme(URI uri) {
        String scheme = uri.getScheme();
        if (scheme == null) {
            LOGGER.error("verifyProviderEndpoint: Provider endpoint {} has no scheme component",
                    uri.toString());
            return ProviderScheme.UNKNOWN;
        }
        
        ProviderScheme schemeType = ProviderScheme.UNKNOWN;
        scheme = scheme.toLowerCase();
        switch (scheme) {
        case SCHEME_HTTPS:
            schemeType = ProviderScheme.HTTPS;
            break;
        case SCHEME_CLASS:
            schemeType = ProviderScheme.CLASS;
            break;
        }
        
        return schemeType;
    }
    
    boolean verifyProviderEndpoint(String host) {
        
        if (providerEndpoints.isEmpty()) {
            return true;
        }
        
        for (String endpoint : providerEndpoints) {
            if (host.endsWith(endpoint)) {
                return true;
            }
        }
        
        return false;
    }
    
    ProviderScheme getProviderEndpointScheme(URI uri) {
        
        // verify that we have a valid endpoint that ends in one of our
        // configured domains.
        
        String host = uri.getHost();
        if (host == null) {
            LOGGER.error("verifyProviderEndpoint: Provider endpoint {} has no host component",
                    uri.toString());
            return ProviderScheme.UNKNOWN;
        }
        host = host.toLowerCase();
        
        String scheme = uri.getScheme();
        if (scheme == null) {
            LOGGER.error("verifyProviderEndpoint: Provider endpoint {} has no scheme component",
                    uri.toString());
            return ProviderScheme.UNKNOWN;
        }
        
        ProviderScheme schemeType = getProviderScheme(uri);
        if (schemeType == ProviderScheme.UNKNOWN) {
            LOGGER.error("verifyProviderEndpoint: Unknown scheme in URI {}", uri.toString());
            return ProviderScheme.UNKNOWN;
        }
        
        // we only validate endpoints for https requests
        
        if (schemeType != ProviderScheme.HTTPS) {
            return schemeType;
        }
        
        if (!verifyProviderEndpoint(host)) {
            LOGGER.error("verifyProviderEndpoint: Provider host {} does not match with any of the configured domains",
                    host);
            return ProviderScheme.UNKNOWN;
        }

        return schemeType;
    }
}
