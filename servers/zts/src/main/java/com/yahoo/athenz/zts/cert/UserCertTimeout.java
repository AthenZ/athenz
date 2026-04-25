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
package com.yahoo.athenz.zts.cert;

import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.TagValueList;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.store.DataStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class UserCertTimeout implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserCertTimeout.class);

    static final long DEFAULT_REFRESH_INTERVAL_MINS = 10;

    private final DataStore dataStore;
    private final String userDomain;
    private final Map<String, Integer> roleTimeoutMap;
    private final ScheduledExecutorService scheduledExecutor;

    private int userCertMaxTimeout;
    private int userCertDefaultTimeout;

    private long lastModifiedMillis;

    public UserCertTimeout(DataStore dataStore, String userDomain) {

        this.dataStore = dataStore;
        this.userDomain = userDomain;
        this.roleTimeoutMap = new ConcurrentHashMap<>();
        this.lastModifiedMillis = 0;

        // default and max (1hr) for user cert timeouts

        long timeout = TimeUnit.MINUTES.convert(1, TimeUnit.HOURS);
        userCertMaxTimeout = Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT, Long.toString(timeout)));

        timeout = TimeUnit.MINUTES.convert(1, TimeUnit.HOURS);
        userCertDefaultTimeout = Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT, Long.toString(timeout)));

        if (userCertDefaultTimeout <= 0) {
            LOGGER.error("Invalid user cert default timeout: {}, using default: {}", userCertDefaultTimeout, timeout);
            userCertDefaultTimeout = (int) timeout;
        }
        if (userCertMaxTimeout <= 0) {
            LOGGER.error("Invalid user cert max timeout: {}, using default: {}", userCertMaxTimeout, timeout);
            userCertMaxTimeout = (int) timeout;
        }
        if (userCertMaxTimeout < userCertDefaultTimeout) {
            LOGGER.error("User cert max timeout: {} is less than default timeout: {}, setting both to default",
                    userCertMaxTimeout, userCertDefaultTimeout);
            userCertMaxTimeout = userCertDefaultTimeout;
        }

        long refreshIntervalMins = Long.parseLong(
                System.getProperty(ZTSConsts.ZTS_PROP_USER_CERT_TIMEOUT_REFRESH_INTERVAL,
                        Long.toString(DEFAULT_REFRESH_INTERVAL_MINS)));

        refreshTimeoutMap();

        scheduledExecutor = Executors.newSingleThreadScheduledExecutor();
        scheduledExecutor.scheduleAtFixedRate(this::refreshIfModified,
                refreshIntervalMins, refreshIntervalMins, TimeUnit.MINUTES);
    }

    void refreshIfModified() {
        try {
            DomainData domainData = dataStore.getDomainData(userDomain);
            if (domainData == null) {
                LOGGER.warn("Unable to retrieve domain data for: {}", userDomain);
                return;
            }

            long modifiedMillis = domainData.getModified() != null ? domainData.getModified().millis() : 0;
            if (modifiedMillis > lastModifiedMillis) {
                refreshTimeoutMap();
            }
        } catch (Exception ex) {
            LOGGER.error("Unable to refresh user cert timeout map", ex);
        }
    }

    void refreshTimeoutMap() {

        DomainData domainData = dataStore.getDomainData(userDomain);
        if (domainData == null) {
            LOGGER.warn("Unable to retrieve domain data for: {}", userDomain);
            return;
        }

        List<Role> roles = domainData.getRoles();
        if (roles == null) {
            roleTimeoutMap.clear();
            lastModifiedMillis = domainData.getModified() != null ? domainData.getModified().millis() : 0;
            return;
        }

        Set<String> currentRoles = new HashSet<>();
        for (Role role : roles) {
            Integer timeout = extractTimeoutFromRole(role);
            if (timeout != null) {
                roleTimeoutMap.put(role.getName(), timeout);
                currentRoles.add(role.getName());
            }
        }

        roleTimeoutMap.keySet().retainAll(currentRoles);

        lastModifiedMillis = domainData.getModified() != null ? domainData.getModified().millis() : 0;

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Refreshed user cert timeout map with {} entries", roleTimeoutMap.size());
        }
    }

    Integer extractTimeoutFromRole(Role role) {

        if (role == null || role.getTags() == null) {
            return null;
        }

        TagValueList tagValueList = role.getTags().get(ZTSConsts.ZTS_USER_CERT_TIMEOUT_TAG);
        if (tagValueList == null || tagValueList.getList() == null || tagValueList.getList().isEmpty()) {
            return null;
        }

        try {
            return Integer.parseInt(tagValueList.getList().get(0));
        } catch (NumberFormatException ex) {
            LOGGER.error("Invalid timeout value for role {}: {}", role.getName(),
                    tagValueList.getList().get(0));
            return null;
        }
    }

    public Integer getTimeout(String roleName) {
        return roleTimeoutMap.get(roleName);
    }

    public Map<String, Integer> getTimeoutMap() {
        return Collections.unmodifiableMap(roleTimeoutMap);
    }

    /**
     * This method will return the maximum timeout for the user's accessible roles
     * If the domain does not exist or the user is not part of any roles, we'll
     * return the default timeout.
     * @param userName the name of the user
     * @return the maximum timeout for the user's accessible roles
     */
    int getUserRoleTimeout(final String userName) {

        // if for some reason the data cache is not available, we'll return the default timeout

        DataCache data = dataStore.getDataCache(userDomain);
        if (data == null) {
            return userCertDefaultTimeout;
        }

        // now we'll get the accessible roles for the user

        Set<String> roles = new HashSet<>();
        dataStore.getAccessibleRoles(data, userDomain, userName, null, false, roles, true);

        int maxRoleTimeout = 0;
        for (String role : roles) {
            Integer timeout = getTimeout(role);
            if (timeout != null && timeout > maxRoleTimeout) {
                maxRoleTimeout = timeout;
            }
        }

        // if the user is not part of any roles or we have no configured role timeouts,
        // we'll return the expected effective timeout

        return (maxRoleTimeout == 0) ? userCertDefaultTimeout : maxRoleTimeout;
    }

    public int getUserCertTimeout(final String userName, Integer userExpiryRequested) {

        // first we'll get the maximum timeout for the user's accessible roles

        int certTimeout = getUserRoleTimeout(userName);

        // if the user has requested a smaller timeout than the role timeout,
        // we'll update our cert timeout to the user's requested value

        if (userExpiryRequested != null && userExpiryRequested > 0 && userExpiryRequested < certTimeout) {
            certTimeout = userExpiryRequested;
        }

        // finally we'll cap the cert timeout at the server's configured max timeout
        // and return the result

        return Math.min(certTimeout, userCertMaxTimeout);
    }

    @Override
    public void close() {
        scheduledExecutor.shutdownNow();
    }
}
