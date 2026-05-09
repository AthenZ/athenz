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
package com.yahoo.athenz.zts.utils;

import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.TagValueList;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.store.DataStore;

import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class UserIdentityTimeout implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserIdentityTimeout.class);

    static final long DEFAULT_REFRESH_INTERVAL_MINS = 10;
    static final String DEFAULT_KEY_ID = "_default_";

    private final DataStore dataStore;
    private final String userDomain;
    private volatile Map<String, Map<String, Integer>> roleCertTimeoutMap;
    private final Map<String, Integer> roleTokenTimeoutMap;
    private final ScheduledExecutorService scheduledExecutor;

    private int userCertMaxTimeout;
    private int userCertDefaultTimeout;
    private int userTokenDefaultTimeout;
    private int userTokenMaxTimeout;

    private long lastModifiedMillis;

    public UserIdentityTimeout(DataStore dataStore, String userDomain) {

        this.dataStore = dataStore;
        this.userDomain = userDomain;
        this.roleCertTimeoutMap = new ConcurrentHashMap<>();
        this.roleTokenTimeoutMap = new ConcurrentHashMap<>();
        this.lastModifiedMillis = 0;
        this.roleCertTimeoutMap.put(DEFAULT_KEY_ID, new ConcurrentHashMap<>());

        // default and max (1hr) for user cert timeouts

        long timeout = TimeUnit.MINUTES.convert(1, TimeUnit.HOURS);
        userCertMaxTimeout = Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, Long.toString(timeout)));
        if (userCertMaxTimeout <= 0) {
            LOGGER.error("Invalid user cert max timeout: {}, using default: {}", userCertMaxTimeout, timeout);
            userCertMaxTimeout = (int) timeout;
        }

        timeout = TimeUnit.MINUTES.convert(1, TimeUnit.HOURS);
        userCertDefaultTimeout = Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, Long.toString(timeout)));
        if (userCertDefaultTimeout <= 0) {
            LOGGER.error("Invalid user cert default timeout: {}, using default: {}", userCertDefaultTimeout, timeout);
            userCertDefaultTimeout = (int) timeout;
        }

        if (userCertMaxTimeout < userCertDefaultTimeout) {
            LOGGER.error("User cert max timeout: {} is less than default timeout: {}, setting both to default",
                    userCertMaxTimeout, userCertDefaultTimeout);
            userCertMaxTimeout = userCertDefaultTimeout;
        }

        // default (1hr) and max (12hrs) id token timeouts

        timeout = TimeUnit.SECONDS.convert(1, TimeUnit.HOURS);
        userTokenDefaultTimeout = Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, Long.toString(timeout)));
        if (userTokenDefaultTimeout <= 0) {
            LOGGER.error("Invalid user token default timeout: {}, using default: {}", userTokenDefaultTimeout, timeout);
            userTokenDefaultTimeout = (int) timeout;
        }

        timeout = TimeUnit.SECONDS.convert(12, TimeUnit.HOURS);
        userTokenMaxTimeout = Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, Long.toString(timeout)));
        if (userTokenMaxTimeout <= 0) {
            LOGGER.error("Invalid user token max timeout: {}, using default: {}", userTokenMaxTimeout, timeout);
            userTokenMaxTimeout = (int) timeout;
        }

        if (userTokenMaxTimeout < userTokenDefaultTimeout) {
            LOGGER.error("User token max timeout: {} is less than default timeout: {}, setting both to default",
                    userTokenMaxTimeout, userTokenDefaultTimeout);
            userTokenMaxTimeout = userTokenDefaultTimeout;
        }

        long refreshIntervalMins = Long.parseLong(
                System.getProperty(ZTSConsts.ZTS_PROP_USER_IDENTITY_TIMEOUT_REFRESH_INTERVAL,
                        Long.toString(DEFAULT_REFRESH_INTERVAL_MINS)));

        refreshTimeoutMap(null);

        scheduledExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "UserIdentityTimeout-Refresh");
            t.setDaemon(true);
            return t;
        });
        scheduledExecutor.scheduleAtFixedRate(this::refreshIfModified,
                refreshIntervalMins, refreshIntervalMins, TimeUnit.MINUTES);
    }

    void refreshIfModified() {
        try {
            DomainData domainData = dataStore.getDomainData(userDomain);
            if (domainData == null) {
                LOGGER.error("Unable to retrieve domain data for: {}", userDomain);
                return;
            }

            long modifiedMillis = domainData.getModified() != null ? domainData.getModified().millis() : 0;
            if (modifiedMillis > lastModifiedMillis) {
                LOGGER.info("Refreshing user cert timeout map...");
                refreshTimeoutMap(domainData);
            }
        } catch (Exception ex) {
            LOGGER.error("Unable to refresh user cert timeout map", ex);
        }
    }

    void refreshTimeoutMap(DomainData domainData) {

        if (domainData == null) {
            domainData = dataStore.getDomainData(userDomain);
            if (domainData == null) {
                LOGGER.error("Unable to retrieve domain data for: {}", userDomain);
                return;
            }
        }

        List<Role> roles = domainData.getRoles();
        if (roles == null) {
            roleCertTimeoutMap.clear();
            roleTokenTimeoutMap.clear();
            lastModifiedMillis = domainData.getModified() != null ? domainData.getModified().millis() : 0;
            return;
        }

        Map<String, Map<String, Integer>> newCertMap = new HashMap<>();
        Set<String> currentTokenRoles = new HashSet<>();
        for (Role role : roles) {
            Integer timeout = extractTimeoutFromRole(role, ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG);
            if (timeout != null) {
                String keyId = extractSignerKeyIdFromRole(role);
                newCertMap.computeIfAbsent(keyId, k -> new ConcurrentHashMap<>())
                        .put(role.getName(), timeout);
            }
            timeout = extractTimeoutFromRole(role, ZTSConsts.ZTS_USER_TOKEN_TIMEOUT_TAG);
            if (timeout != null) {
                roleTokenTimeoutMap.put(role.getName(), timeout);
                currentTokenRoles.add(role.getName());
            }
        }

        roleCertTimeoutMap = newCertMap;
        roleTokenTimeoutMap.keySet().retainAll(currentTokenRoles);

        lastModifiedMillis = domainData.getModified() != null ? domainData.getModified().millis() : 0;

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Refreshed user cert timeout map with {} key-id entries", roleCertTimeoutMap.size());
            LOGGER.debug("Refreshed user token timeout map with {} entries", roleTokenTimeoutMap.size());
        }
    }

    Integer extractTimeoutFromRole(Role role, final String tagName) {

        if (role == null || role.getTags() == null) {
            return null;
        }

        TagValueList tagValueList = role.getTags().get(tagName);
        if (tagValueList == null || tagValueList.getList() == null || tagValueList.getList().isEmpty()) {
            return null;
        }

        try {
            return Integer.parseInt(tagValueList.getList().get(0).trim());
        } catch (NumberFormatException ex) {
            LOGGER.error("Invalid timeout value for role {}: {}", role.getName(),
                    tagValueList.getList().get(0));
            return null;
        }
    }

    String extractSignerKeyIdFromRole(Role role) {

        if (role == null || role.getTags() == null) {
            return DEFAULT_KEY_ID;
        }

        TagValueList tagValueList = role.getTags().get(ZTSConsts.ZTS_USER_CERT_SIGNER_KEY_ID_TAG);
        if (tagValueList == null || tagValueList.getList() == null || tagValueList.getList().isEmpty()) {
            return DEFAULT_KEY_ID;
        }

        String keyId = tagValueList.getList().get(0).trim();
        return keyId.isEmpty() ? DEFAULT_KEY_ID : keyId;
    }

    public Integer getCertTimeout(String keyId, String roleName) {
        Map<String, Integer> keyMap = roleCertTimeoutMap.get(keyId != null ? keyId : DEFAULT_KEY_ID);
        return keyMap != null ? keyMap.get(roleName) : null;
    }

    public Integer getCertTimeout(String roleName) {
        return getCertTimeout(null, roleName);
    }

    public Map<String, Map<String, Integer>> getCertTimeoutMap() {
        return Collections.unmodifiableMap(roleCertTimeoutMap);
    }

    public Integer getTokenTimeout(String roleName) {
        return roleTokenTimeoutMap.get(roleName);
    }

    public Map<String, Integer> getTokenTimeoutMap() {
        return Collections.unmodifiableMap(roleTokenTimeoutMap);
    }

    Set<String> getAccessibleRoles(final String userName) {
        DataCache data = dataStore.getDataCache(userDomain);
        if (data == null) {
            return Collections.emptySet();
        }
        Set<String> roles = new HashSet<>();
        dataStore.getAccessibleRoles(data, userDomain, userName, null, false, roles, true);
        return roles;
    }

    /**
     * This method will return the maximum timeout for the user's accessible roles
     * for the given signer key id. If the signer key id is null or empty, the
     * default map is used. If the domain does not exist or the user is not part
     * of any roles, we'll return the default timeout.
     * @param userName the name of the user
     * @param signerKeyId the signer key id (null for default)
     * @return the maximum timeout for the user's accessible roles
     */
    int getUserRoleCertTimeout(final String userName, final String signerKeyId) {

        // determine which key id map to use

        final String effectiveKeyId = StringUtil.isEmpty(signerKeyId) ? DEFAULT_KEY_ID : signerKeyId;

        Map<String, Integer> keyMap = roleCertTimeoutMap.get(effectiveKeyId);
        if (keyMap == null || keyMap.isEmpty()) {
            return userCertDefaultTimeout;
        }

        // now we'll get the accessible roles for the user

        Set<String> roles = getAccessibleRoles(userName);

        int maxRoleTimeout = 0;
        for (String role : roles) {
            Integer timeout = keyMap.get(role);
            if (timeout != null && timeout > maxRoleTimeout) {
                maxRoleTimeout = timeout;
            }
        }

        // if the user is not part of any roles or we have no configured role timeouts,
        // we'll return the expected effective timeout

        return (maxRoleTimeout == 0) ? userCertDefaultTimeout : maxRoleTimeout;
    }

    /**
     * This method will return the maximum timeout for the user's accessible roles
     * If the domain does not exist or the user is not part of any roles, we'll
     * return the default timeout.
     * @param userName the name of the user
     * @return the maximum timeout for the user's accessible roles
     */
    int getUserRoleTokenTimeout(final String userName) {

        // now we'll get the accessible roles for the user

        Set<String> roles = getAccessibleRoles(userName);
        
        int maxRoleTimeout = 0;
        for (String role : roles) {
            Integer timeout = getTokenTimeout(role);
            if (timeout != null && timeout > maxRoleTimeout) {
                maxRoleTimeout = timeout;
            }
        }

        // if the user is not part of any roles or we have no configured role timeouts,
        // we'll return the expected effective timeout

        return (maxRoleTimeout == 0) ? userTokenDefaultTimeout : maxRoleTimeout;
    }

    public int getUserCertTimeout(final String userName, final String signerKeyId,
            Integer userExpiryRequested) {

        // first we'll get the maximum timeout for the user's accessible roles
        // and determine the timeout to return

        return getUserIdentityTimeout(getUserRoleCertTimeout(userName, signerKeyId),
                userCertMaxTimeout, userExpiryRequested);
    }

    public int getUserTokenTimeout(final String userName, Integer userExpiryRequested) {

        // first we'll get the maximum timeout for the user's accessible roles
        // and determine the timeout to return

        return getUserIdentityTimeout(getUserRoleTokenTimeout(userName), userTokenMaxTimeout, userExpiryRequested);
    }

    int getUserIdentityTimeout(int timeout, int maxTimetout, Integer userExpiryRequested) {

        // if the user has requested a smaller timeout than the determined timeout,
        // we'll update our timeout to the user's requested value

        if (userExpiryRequested != null && userExpiryRequested > 0 && userExpiryRequested < timeout) {
            timeout = userExpiryRequested;
        }

        // finally we'll cap the timeout at the server's configured max timeout
        // and return the result

        return Math.min(timeout, maxTimetout);
    }

    @Override
    public void close() {
        scheduledExecutor.shutdownNow();
    }
}
