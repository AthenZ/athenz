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

import com.yahoo.rdl.JSON;
import com.yahoo.athenz.zts.ZTSConsts;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

/**
 * Resolves the appropriate issuer value based on the host header in the HTTP request.
 * Supports host-to-issuer mappings from a configuration file, with fallback to
 * the standard ZTS issuer determination logic.
 */
public class IssuerResolver {

    private static final Logger LOGGER = LoggerFactory.getLogger(IssuerResolver.class);

    private static final String HEADER_HOST = "Host";

    private final Map<String, String> hostToIssuerMap;
    private final String ztsOauthIssuer;
    private final String ztsOpenIDIssuer;
    private final String ztsOIDCPortIssuer;
    private final int oidcPort;
    private final int httpsPort;
    private Set<String> oauth2Issuers;

    /**
     * Initializes the IssuerResolver by reading the host mapping file and storing
     * the default issuer values.
     *
     * @param ztsOauthIssuer The default OAuth issuer value
     * @param ztsOpenIDIssuer The default OpenID issuer value
     * @param ztsOIDCPortIssuer The default OIDC port issuer value
     * @param oidcPort The OIDC port number
     * @param httpsPort The HTTPS port number
     */
    public IssuerResolver(String ztsOauthIssuer, String ztsOpenIDIssuer, String ztsOIDCPortIssuer, int oidcPort, int httpsPort) {

        this.ztsOauthIssuer = ztsOauthIssuer;
        this.ztsOpenIDIssuer = ztsOpenIDIssuer;
        this.ztsOIDCPortIssuer = ztsOIDCPortIssuer;
        this.oidcPort = oidcPort;
        this.httpsPort = httpsPort;
        this.hostToIssuerMap = new HashMap<>();

        // generate our set of oauth2 issuers

        oauth2Issuers = new HashSet<>();
        oauth2Issuers.add(ztsOauthIssuer);
        oauth2Issuers.add(ztsOpenIDIssuer);
        oauth2Issuers.add(ztsOIDCPortIssuer);

        // Read the host mapping file from configuration property
        String mappingFilePath = System.getProperty(ZTSConsts.ZTS_PROP_HOST_ISSUER_MAPPING_FILE);
        if (StringUtil.isEmpty(mappingFilePath)) {
            LOGGER.info("Host issuer mapping file not configured. Using default issuer logic only.");
            return;
        }

        LOGGER.info("Loading host issuer mappings from file: {}", mappingFilePath);

        try {
            Path path = Paths.get(mappingFilePath);
            byte[] fileBytes = Files.readAllBytes(path);

            // Parse JSON array into HostIssuerMapping objects

            HostIssuerMapping[] mappings = JSON.fromBytes(fileBytes, HostIssuerMapping[].class);
            if (mappings == null || mappings.length == 0) {
                LOGGER.warn("No host issuer mappings found in file: {}", mappingFilePath);
                return;
            }

            // Build the host-to-issuer map

            for (HostIssuerMapping mapping : mappings) {
                if (StringUtil.isEmpty(mapping.getHost()) || StringUtil.isEmpty(mapping.getIssuer())) {
                    LOGGER.warn("Skipping invalid mapping entry: host={}, issuer={}", 
                            mapping.getHost(), mapping.getIssuer());
                    continue;
                }
                hostToIssuerMap.put(mapping.getHost().toLowerCase(), mapping.getIssuer());
                LOGGER.debug("Added host mapping: {} -> {}", mapping.getHost(), mapping.getIssuer());
            }

            LOGGER.info("Successfully loaded {} host issuer mappings", hostToIssuerMap.size());

        } catch (IOException ex) {
            LOGGER.error("Unable to process host issuer mapping file: {}", mappingFilePath, ex);
            throw new IllegalArgumentException("Failed to load host issuer mapping file: " + mappingFilePath, ex);
        }

        // add the additional issuers from our mapping to the oauth2 issuers set

        oauth2Issuers.addAll(hostToIssuerMap.values());
    }

    /**
     * Return the set of oauth2 issuers
     * @return the set of oauth2 issuers
     */
    public Set<String> getOauth2Issuers() {
        return oauth2Issuers;
    }

    /**
     * Determins if the given issuer is in our set of oauth2 issuers
     * @param issuer the issuer to check
     * @return true if the issuer is in our set of oauth2 issuers, false otherwise
     */
    public boolean isOauth2Issuer(String issuer) {
        return oauth2Issuers.contains(issuer);
    }

    /**
     * Determines the appropriate issuer value based on the HTTP request and
     * the isUseOpenIDIssuer flag from AccessTokenRequest.
     *
     * @param httpServletRequest The HTTP servlet request
     * @param isUseOpenIDIssuer Whether to use OpenID issuer (from AccessTokenRequest)
     * @return The resolved issuer value
     */
    public String getAccessTokenIssuer(HttpServletRequest httpServletRequest, boolean isUseOpenIDIssuer) {

        // first check if we have a host mapping for this request

        String issuer = getHostMappedIssuer(httpServletRequest);
        if (issuer != null) {
            return issuer;
        }

        // Fall back to the current logic in ZTSImpl
        // Based on isUseOpenIDIssuer: if true use ztsOpenIDIssuer, otherwise use ztsOauthIssuer

        issuer = isUseOpenIDIssuer ? ztsOpenIDIssuer : ztsOauthIssuer;
        LOGGER.debug("Using default issuer {} (isUseOpenIDIssuer={})", issuer, isUseOpenIDIssuer);
        return issuer;
    }

    /**
     * Determines the appropriate issuer value based on the HTTP request and
     * the oidc port
     *
     * @param httpServletRequest The HTTP servlet request
     * @param issuerOption The issuer option from token request
     * @return The resolved issuer value
     */
    public String getIDTokenIssuer(HttpServletRequest httpServletRequest, final String issuerOption) {

        // first check if we have a host mapping for this request

        String issuer = getHostMappedIssuer(httpServletRequest);
        if (issuer != null) {
            return issuer;
        }

        // Fall back to the current logic in ZTSImpl
        // Based on isUseOpenIDIssuer: if true use ztsOpenIDIssuer, otherwise use ztsOauthIssuer
        
        issuer = isOidcPortRequest(httpServletRequest, issuerOption) ? ztsOIDCPortIssuer : ztsOpenIDIssuer;
        LOGGER.debug("Using default issuer {} (issuerOption={})", issuer, issuerOption);

        return issuer;
    }

    String getHostMappedIssuer(HttpServletRequest httpServletRequest) {

        // Extract host header from the request

        String host = null;
        if (httpServletRequest != null) {
            host = httpServletRequest.getHeader(HEADER_HOST);
            if (StringUtil.isEmpty(host)) {
                host = httpServletRequest.getServerName();
            }
        }

        // If we have a host, and it's in our mapping, return the mapped issuer.
        // If the host name contains a port number then we'll strip it out
        // since our mapping is based on host name only

        if (!StringUtil.isEmpty(host)) {
            final int portIdx = host.indexOf(':');
            if (portIdx != -1) {
                host = host.substring(0, portIdx);
            }
            String mappedIssuer = hostToIssuerMap.get(host.toLowerCase());
            if (mappedIssuer != null) {
                LOGGER.debug("Using mapped issuer {} for host {}", mappedIssuer, host);
                return mappedIssuer;
            }
        }

        return null;
    }

    boolean isOidcPortRequest(HttpServletRequest httpServletRequest, final String issuerOption) {

        // if the request includes a specified issuer config option
        // then we'll return our result based on that option. We'll
        // ignore any invalid values and fall back to return a result
        // based on the port number

        if (!StringUtil.isEmpty(issuerOption)) {
            if (ZTSConsts.ZTS_ISSUER_TYPE_OPENID.equals(issuerOption)) {
                return false;
            } else if (ZTSConsts.ZTS_ISSUER_TYPE_OIDC_PORT.equals(issuerOption)) {
                return true;
            }
        }

        // if our servlet request is false, then this should be an internal
        // call from our provider instances thus we're assuming it's an oidc
        // otherwise we'll handle it based on the port number

        if (httpServletRequest == null) {
            return true;
        }
        return httpServletRequest.getLocalPort() == oidcPort && oidcPort != httpsPort;
    }
}
