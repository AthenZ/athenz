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
package com.yahoo.athenz.zts;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.impl.InstanceHttpProvider;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.store.DataStore;

import javax.net.ssl.SSLContext;

public class InstanceProviderManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceProviderManager.class);

    private static final String SCHEME_HTTPS = "https";
    private static final String SCHEME_CLASS = "class";
    private static final String ZTS_PROVIDER = "sys.auth.zts";
    private static final String ATHENZ_CLIENT_USER = "athenz.client";

    private final ConcurrentHashMap<String, InstanceProvider> providerMap;
    private final DataStore dataStore;
    private final KeyStore keyStore;
    private final SSLContext athenzServerSSLContext;
    private final SSLContext athenzClientSSLContext;
    private final ServerPrivateKey serverPrivateKey;
    private final ZTSHandler ztsHandler;
    private final Authorizer authorizer;
    List<String> providerEndpoints = Collections.emptyList();

    enum ProviderScheme {
        UNKNOWN,
        HTTPS,
        CLASS
    }
    
    public InstanceProviderManager(DataStore dataStore, SSLContext athenzServerSSLContext, SSLContext athenzClientSSLContext,
            ServerPrivateKey serverPrivateKey, KeyStore keyStore, Authorizer authorizer, ZTSHandler ztsHandler) {
        
        this.dataStore = dataStore;
        this.keyStore = keyStore;
        this.athenzServerSSLContext = athenzServerSSLContext;
        this.athenzClientSSLContext = athenzClientSSLContext;
        this.serverPrivateKey = serverPrivateKey;
        this.authorizer = authorizer;
        this.ztsHandler = ztsHandler;

        providerMap = new ConcurrentHashMap<>();
        
        // get the list of valid provider endpoints
        
        String endPoints = System.getProperty(ZTSConsts.ZTS_PROP_PROVIDER_ENDPOINTS);
        if (endPoints != null) {
            providerEndpoints = Arrays.asList(endPoints.split(","));
        }
    }
    
    InstanceProvider getProvider(String provider, HostnameResolver hostnameResolver) {
        int idx = provider.lastIndexOf('.');
        if (idx == -1) {
            LOGGER.error("Invalid provider service name: {}", provider);
            return null;
        }
        
        final String domainName = provider.substring(0, idx);
        DataCache dataCache = dataStore.getDataCache(domainName);
        if (dataCache == null) {
            LOGGER.error("Unknown domain: {}", domainName);
            return null;
        }
        
        String providerEndpoint = null;
        boolean validProviderName = false;
        List<com.yahoo.athenz.zms.ServiceIdentity> services = dataCache.getDomainData().getServices();
        if (services == null) {
            LOGGER.error("Unknown provider service: {}", provider);
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
        
        if (StringUtil.isEmpty(providerEndpoint)) {
            if (validProviderName) {
                LOGGER.error("Unknown provider service name: {}", provider);
            } else {
                LOGGER.error("Provider service {} does not have endpoint defined", provider);
            }
            return null;
        }

        // before using our endpoint we need to make sure
        // it's valid according to configuration settings
        
        InstanceProvider instanceProvider = null;
        URI uri;
        try {
            uri = new URI(providerEndpoint);
        } catch (URISyntaxException ex) {
            LOGGER.error("Unable to parse {}: {}", providerEndpoint, ex.getMessage());
            return null;
        }

        // if the uri has athenz.client as the authenticated user then
        // we're going to use our client ssl context otherwise we'll
        // default to our server ssl context
        boolean useClientSSLContext = ATHENZ_CLIENT_USER.equals(uri.getUserInfo());

        ProviderScheme schemeType = getProviderEndpointScheme(uri);
        switch (schemeType) {
        case HTTPS:
            instanceProvider = new InstanceHttpProvider();
            instanceProvider.initialize(provider, getProviderEndpoint(uri, useClientSSLContext, providerEndpoint),
                    getSSLContext(useClientSSLContext), keyStore);
            break;
        case CLASS:
            instanceProvider = getClassProvider(uri.getHost(), provider, getSSLContext(useClientSSLContext), hostnameResolver);
            break;
        default:
            break;
        }
        
        return instanceProvider;
    }

    InstanceProvider getClassProvider(String className, String providerName, SSLContext context, HostnameResolver hostnameResolver) {
        final String classKey = className + "-" + providerName;
        InstanceProvider provider = providerMap.get(classKey);
        if (provider != null) {
            return provider;
        }

        try {
            provider = (InstanceProvider) Class.forName(className).getConstructor().newInstance();
        } catch (Exception ex) {
            LOGGER.error("Unable to get new instance for provider {}", className, ex);
            return null;
        }
        provider.initialize(providerName, className, context, keyStore);
        provider.setHostnameResolver(hostnameResolver);
        provider.setRolesProvider(dataStore);
        provider.setExternalCredentialsProvider(new InstanceExternalCredentialsProvider(providerName, ztsHandler));
        provider.setAuthorizer(authorizer);
        provider.setPubKeysProvider(dataStore);
        if (ZTS_PROVIDER.equals(providerName)) {
            provider.setPrivateKey(serverPrivateKey.getKey(), serverPrivateKey.getId(), serverPrivateKey.getAlgorithm());
        }

        providerMap.put(classKey, provider);
        return provider;
    }

    String getProviderEndpoint(URI uri, boolean useClientSSLContext, final String providerEndpoint) {
        // if we're using the athenz client context then we need to remove
        // the authenticated user information from the endpoint
        return useClientSSLContext ? providerEndpoint.replace(uri.getRawUserInfo() + "@", "") : providerEndpoint;
    }

    SSLContext getSSLContext(boolean useClientSSLContext) {
        // if the requested ssl context is null we'll default to returning the other
        // type in order to avoid any failures if the provider accepts both types
        if (useClientSSLContext) {
            return athenzClientSSLContext != null ? athenzClientSSLContext : athenzServerSSLContext;
        } else {
            return athenzServerSSLContext != null ? athenzServerSSLContext : athenzClientSSLContext;
        }
    }

    ProviderScheme getProviderScheme(URI uri) {
        final String scheme = uri.getScheme();
        if (scheme == null) {
            LOGGER.error("Provider endpoint {} has no scheme component", uri);
            return ProviderScheme.UNKNOWN;
        }
        
        ProviderScheme schemeType;
        switch (scheme.toLowerCase()) {
        case SCHEME_HTTPS:
            schemeType = ProviderScheme.HTTPS;
            break;
        case SCHEME_CLASS:
            schemeType = ProviderScheme.CLASS;
            break;
        default:
            schemeType = ProviderScheme.UNKNOWN;
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
            LOGGER.error("Provider endpoint {} has no host component", uri);
            return ProviderScheme.UNKNOWN;
        }
        host = host.toLowerCase();
        
        String scheme = uri.getScheme();
        if (scheme == null) {
            LOGGER.error("Provider endpoint {} has no scheme component", uri);
            return ProviderScheme.UNKNOWN;
        }
        
        ProviderScheme schemeType = getProviderScheme(uri);
        if (schemeType == ProviderScheme.UNKNOWN) {
            LOGGER.error("Unknown scheme in URI {}", uri);
            return ProviderScheme.UNKNOWN;
        }
        
        // we only validate endpoints for https requests
        
        if (schemeType != ProviderScheme.HTTPS) {
            return schemeType;
        }
        
        if (!verifyProviderEndpoint(host)) {
            LOGGER.error("Provider host {} does not match with any of the configured domains", host);
            return ProviderScheme.UNKNOWN;
        }

        return schemeType;
    }
}
