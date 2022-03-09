/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.zms.provider;

import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.Role;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static com.yahoo.athenz.zms.ZMSConsts.*;

/**
 * This class is used to determine if a given principal is an authorized
 * Service Provider by searching in a local cache.
 * The cache is refreshed by a background daemon that periodically fetches the
 * current list of Service Providers from DB.
 */
public class ServiceProviderManager {
    private static final Logger LOGGER = LoggerFactory.getLogger(ServiceProviderManager.class);
    private ScheduledExecutorService scheduledExecutor;
    private final DBService dbService;
    private final String serviceProviderDomain;
    private final String serviceProviderRole;
    volatile Set<String> serviceProviders = new HashSet<>();

    public ServiceProviderManager(final DBService dbService) {
        LOGGER.info("initializing ServiceProviderManager to periodically refresh the list of Service Providers from DB");
        serviceProviderDomain = System.getProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_DOMAIN, ZMS_PROP_SERVICE_PROVIDER_MANAGER_DOMAIN_DEFAULT);
        serviceProviderRole = System.getProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_ROLE, ZMS_PROP_SERVICE_PROVIDER_MANAGER_ROLE_DEFAULT);
        this.dbService = dbService;
        refreshServiceProviders();

        init();
    }

    private void init() {
        scheduledExecutor = Executors.newSingleThreadScheduledExecutor();
        long serviceProviderManagerFrequency = Long.parseLong(
                System.getProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_FREQUENCY_SECONDS, ZMS_PROP_SERVICE_PROVIDER_MANAGER_FREQUENCY_SECONDS_DEFAULT));
        scheduledExecutor.scheduleAtFixedRate(this::refreshServiceProviders, serviceProviderManagerFrequency,
                serviceProviderManagerFrequency, TimeUnit.SECONDS);
    }

    /**
     * Shutdown hook for the scheduler
     */
    public void shutdown() {
        scheduledExecutor.shutdownNow();
    }

    public void setServiceProviders(Set<String> serviceProviders) {
        this.serviceProviders = serviceProviders;
    }

    private void refreshServiceProviders() {
        LOGGER.info("Refreshing service providers in cache");
        Role role = dbService.getRole(serviceProviderDomain, serviceProviderRole, false, true, false);
        if (role == null) {
            LOGGER.warn("Failed to refresh service sroviders in cache");
            return;
        }
        Set<String> serviceProvidersUpdatedSet = role.getRoleMembers().stream()
                .map(roleMember -> roleMember.getMemberName())
                .collect(Collectors.toSet());
        serviceProviders = serviceProvidersUpdatedSet;
    }

    public boolean isServiceProvider(String principal) {
        return !StringUtil.isEmpty(principal) && serviceProviders.contains(principal);
    }
}
