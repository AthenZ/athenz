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
package com.yahoo.athenz.zts.token;

import com.yahoo.athenz.auth.TokenExchangeIdentityProvider;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsResolver;
import com.yahoo.rdl.JSON;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Loads and manages provider configurations from a JSON configuration file.
 * The JSON file should contain an array of provider configuration objects,
 * where each object has the following fields:
 * - issuerUri: The issuer URI for the provider
 * - proxyUrl: Optional proxy URL for the provider
 * - jwksUri: The JWKS URI for the provider
 * - providerClassName: The class name of the provider implementation
 * - exchangeClaims: An array of claim names to be exchanged
 */
public class ProviderConfigManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProviderConfigManager.class);

    private final Map<String, TokenExchangeIdentityProvider> identityProviders;
    private final List<JwtsResolver> jwtsResolvers;

    /**
     * Loads provider configurations from a JSON file.
     */
    public ProviderConfigManager(String configFilePath) {

        identityProviders = new HashMap<>();
        jwtsResolvers = new ArrayList<>();

        if (configFilePath == null || configFilePath.isEmpty()) {
            LOGGER.error("Provider Manager Configuration file path is null or empty");
            return;
        }

        LOGGER.info("Loading provider configurations from file: {}", configFilePath);
        
        try {
            Path path = Paths.get(configFilePath);
            byte[] fileBytes = Files.readAllBytes(path);
            
            // Parse JSON array into List of ProviderConfig objects

            ProviderConfig[] configArray = JSON.fromBytes(fileBytes, ProviderConfig[].class);
            
            if (configArray == null) {
                LOGGER.warn("No provider configurations found in file: {}", configFilePath);
                return;
            }

            for (ProviderConfig config : configArray) {
                processProviderConfig(config);
            }

        } catch (IOException ex) {
            LOGGER.error("Unable to process provider configuration file: {}", configFilePath, ex);
            throw new IllegalArgumentException(ex);
        }
    }

    void processProviderConfig(ProviderConfig config) {

        if (StringUtil.isEmpty(config.getIssuerUri())) {
            LOGGER.error("Issuer Uri is required");
            return;
        }

        // extract the jwks_uri from the openid-configuration endpoint

        JwtsHelper helper = new JwtsHelper();

        String jwksUri = helper.extractJwksUri(config.getIssuerUri() + "/.well-known/openid-configuration",
                null, config.getProxyUrl());

        if (StringUtil.isEmpty(jwksUri)) {
            jwksUri = config.getJwksUri();
        }

        if (StringUtil.isEmpty(jwksUri)) {
            LOGGER.error("Unable to extract jwks_uri for issuer: {}", config.getIssuerUri());
            return;
        }

        if (!StringUtil.isEmpty(config.getProviderClassName())) {
            TokenExchangeIdentityProvider identityProvider;
            try {
                identityProvider = (TokenExchangeIdentityProvider) Class.forName(config.getProviderClassName())
                        .getDeclaredConstructor().newInstance();
            } catch (Exception ex) {
                LOGGER.error("Invalid TokenExchangeIdentityProvider class: {}", config.getProviderClassName(), ex);
                return;
            }
            identityProviders.put(config.getIssuerUri(), identityProvider);
        }

        jwtsResolvers.add(new JwtsResolver(jwksUri, config.getProxyUrl(), null));
        LOGGER.info("Successfully loaded provider config: {}", config.getIssuerUri());
    }

    /**
     * Gets the list of loaded jwts resolvers
     *
     * @return A list of JwtsResolver objects
     */
    public List<JwtsResolver> getJwtsResolvers() {
        return this.jwtsResolvers;
    }

    /**
     * Gets a token exchange identity object by issuer URI.
     *
     * @param issuerUri The issuer URI to search for
     * @return The matching TokenExchangeIdentityProvider, or null if not found
     */
    public TokenExchangeIdentityProvider getProvider(final String issuerUri) {
        return identityProviders.get(issuerUri);
    }

    /**
     * Puts a token exchange identity provider into the manager.
     * Used for unit tests only
     *
     * @param issuerUri The issuer URI for the provider
     * @param provider  The TokenExchangeIdentityProvider to add
     */
    public void putProvider(final String issuerUri, final TokenExchangeIdentityProvider provider) {
        identityProviders.put(issuerUri, provider);
    }
}

