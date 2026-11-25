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

package com.yahoo.athenz.zts.token;

import com.yahoo.athenz.common.config.AuthzDetailsEntityList;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.rdl.JSON;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Immutable token issuance settings, loaded once at server startup and
 * shared by every code path that issues tokens.
 */
public final class TokenIssuanceConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenIssuanceConfig.class);

    private final int roleTokenDefaultTimeout;
    private final int roleTokenMaxTimeout;
    private final int idTokenMaxTimeout;
    private final int jagTokenUserMaxTimeout;
    private final int jagTokenServiceMaxTimeout;
    private final boolean logUnrequestedRolesEnabled;
    private final Set<String> authorizedProxyUsers;
    private final int maxAuthzDetailsLength;
    private final AuthzDetailsEntityList systemAuthzDetails;

    private TokenIssuanceConfig(final Builder builder) {
        roleTokenDefaultTimeout = builder.roleTokenDefaultTimeout;
        roleTokenMaxTimeout = builder.roleTokenMaxTimeout;
        idTokenMaxTimeout = builder.idTokenMaxTimeout;
        jagTokenUserMaxTimeout = builder.jagTokenUserMaxTimeout;
        jagTokenServiceMaxTimeout = builder.jagTokenServiceMaxTimeout;
        logUnrequestedRolesEnabled = builder.logUnrequestedRolesEnabled;
        authorizedProxyUsers = builder.authorizedProxyUsers == null ? null
                : Collections.unmodifiableSet(new HashSet<>(builder.authorizedProxyUsers));
        maxAuthzDetailsLength = builder.maxAuthzDetailsLength;
        systemAuthzDetails = builder.systemAuthzDetails;
    }

    /**
     * Load the settings from the server system properties.
     * @return token issuance configuration
     * @throws IllegalArgumentException if the system authorization details file is invalid
     */
    public static TokenIssuanceConfig fromSystemProperties() {

        Builder builder = new Builder();

        // check to see if we want to log the roles that the principal was
        // authorized for but were not part of the requested role list

        builder.logUnrequestedRolesEnabled(Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_LOG_UNREQUESTED_ROLES, "false")));

        // Default Role Token timeout is 2 hours. If the client asks for role tokens
        // with a min expiry time of 1 hour, the setting of 2 hours allows the client
        // to at least cache the tokens for 1 hour. We're going to set the ZTS client's
        // min default value to 15 mins so that we can by default cache tokens for
        // an hour and 45 minutes.

        long timeout = TimeUnit.SECONDS.convert(2, TimeUnit.HOURS);
        builder.roleTokenDefaultTimeout(Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT, Long.toString(timeout))));

        // Max Timeout - 30 days

        timeout = TimeUnit.SECONDS.convert(30, TimeUnit.DAYS);
        builder.roleTokenMaxTimeout(Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT, Long.toString(timeout))));

        // max (12hrs) id token timeout

        timeout = TimeUnit.SECONDS.convert(12, TimeUnit.HOURS);
        builder.idTokenMaxTimeout(Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, Long.toString(timeout))));

        timeout = TimeUnit.SECONDS.convert(1, TimeUnit.HOURS);
        builder.jagTokenUserMaxTimeout(Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_JAG_TOKEN_USER_MAX_TIMEOUT, Long.toString(timeout))));

        timeout = TimeUnit.SECONDS.convert(6, TimeUnit.HOURS);
        builder.jagTokenServiceMaxTimeout(Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_JAG_TOKEN_SERVICE_MAX_TIMEOUT, Long.toString(timeout))));

        // retrieve the list of our authorized proxy users

        final String authorizedProxyUserList = System.getProperty(ZTSConsts.ZTS_PROP_AUTHORIZED_PROXY_USERS);
        if (authorizedProxyUserList != null) {
            builder.authorizedProxyUsers(new HashSet<>(Arrays.asList(authorizedProxyUserList.split(","))));
        }

        // configured max length for authz details claims

        builder.maxAuthzDetailsLength(Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_MAX_AUTHZ_DETAILS_LENGTH, "1024")));

        builder.systemAuthzDetails(loadSystemAuthorizationDetails());
        return builder.build();
    }

    /**
     * Load the optional system authorization details file.
     * @return the configured authorization details or null if none configured
     * @throws IllegalArgumentException if the configured file is invalid
     */
    public static AuthzDetailsEntityList loadSystemAuthorizationDetails() {

        // process any system authorization details

        final String authzDetailsFname = System.getProperty(ZTSConsts.ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH);
        if (StringUtil.isEmpty(authzDetailsFname)) {
            return null;
        }

        AuthzDetailsEntityList systemAuthzDetails = null;
        try {
            Path path = Paths.get(authzDetailsFname);
            systemAuthzDetails = JSON.fromBytes(Files.readAllBytes(path), AuthzDetailsEntityList.class);
        } catch (IOException ex) {
            LOGGER.error("Unable to read authorization details file {}", authzDetailsFname, ex);
        }

        if (systemAuthzDetails == null || systemAuthzDetails.getEntities() == null) {
            LOGGER.error("Unable to parse service authorization details file {}", authzDetailsFname);
            throw new IllegalArgumentException("Invalid authorization details file");
        }
        return systemAuthzDetails;
    }

    public int getRoleTokenDefaultTimeout() {
        return roleTokenDefaultTimeout;
    }

    public int getRoleTokenMaxTimeout() {
        return roleTokenMaxTimeout;
    }

    public int getIdTokenMaxTimeout() {
        return idTokenMaxTimeout;
    }

    public int getJagTokenUserMaxTimeout() {
        return jagTokenUserMaxTimeout;
    }

    public int getJagTokenServiceMaxTimeout() {
        return jagTokenServiceMaxTimeout;
    }

    public boolean isLogUnrequestedRolesEnabled() {
        return logUnrequestedRolesEnabled;
    }

    /**
     * @return unmodifiable set of authorized proxy users or null if none configured
     */
    public Set<String> getAuthorizedProxyUsers() {
        return authorizedProxyUsers;
    }

    public int getMaxAuthzDetailsLength() {
        return maxAuthzDetailsLength;
    }

    /**
     * @return system authorization details or null if none configured
     */
    public AuthzDetailsEntityList getSystemAuthzDetails() {
        return systemAuthzDetails;
    }

    /**
     * Builder for {@link TokenIssuanceConfig}.
     */
    public static final class Builder {

        private int roleTokenDefaultTimeout;
        private int roleTokenMaxTimeout;
        private int idTokenMaxTimeout;
        private int jagTokenUserMaxTimeout;
        private int jagTokenServiceMaxTimeout;
        private boolean logUnrequestedRolesEnabled;
        private Set<String> authorizedProxyUsers;
        private int maxAuthzDetailsLength;
        private AuthzDetailsEntityList systemAuthzDetails;

        public Builder() {
        }

        /**
         * @param config configuration to copy the initial values from
         */
        public Builder(final TokenIssuanceConfig config) {
            roleTokenDefaultTimeout = config.roleTokenDefaultTimeout;
            roleTokenMaxTimeout = config.roleTokenMaxTimeout;
            idTokenMaxTimeout = config.idTokenMaxTimeout;
            jagTokenUserMaxTimeout = config.jagTokenUserMaxTimeout;
            jagTokenServiceMaxTimeout = config.jagTokenServiceMaxTimeout;
            logUnrequestedRolesEnabled = config.logUnrequestedRolesEnabled;
            authorizedProxyUsers = config.authorizedProxyUsers;
            maxAuthzDetailsLength = config.maxAuthzDetailsLength;
            systemAuthzDetails = config.systemAuthzDetails;
        }

        public Builder roleTokenDefaultTimeout(int value) {
            roleTokenDefaultTimeout = value;
            return this;
        }

        public Builder roleTokenMaxTimeout(int value) {
            roleTokenMaxTimeout = value;
            return this;
        }

        public Builder idTokenMaxTimeout(int value) {
            idTokenMaxTimeout = value;
            return this;
        }

        public Builder jagTokenUserMaxTimeout(int value) {
            jagTokenUserMaxTimeout = value;
            return this;
        }

        public Builder jagTokenServiceMaxTimeout(int value) {
            jagTokenServiceMaxTimeout = value;
            return this;
        }

        public Builder logUnrequestedRolesEnabled(boolean value) {
            logUnrequestedRolesEnabled = value;
            return this;
        }

        public Builder authorizedProxyUsers(final Set<String> value) {
            authorizedProxyUsers = value;
            return this;
        }

        public Builder maxAuthzDetailsLength(int value) {
            maxAuthzDetailsLength = value;
            return this;
        }

        public Builder systemAuthzDetails(final AuthzDetailsEntityList value) {
            systemAuthzDetails = value;
            return this;
        }

        public TokenIssuanceConfig build() {
            return new TokenIssuanceConfig(this);
        }
    }
}
