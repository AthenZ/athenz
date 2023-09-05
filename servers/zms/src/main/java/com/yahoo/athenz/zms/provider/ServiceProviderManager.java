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

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.common.ServerCommonConsts;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.ServiceIdentity;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.yahoo.athenz.zms.ZMSConsts.*;

/**
 * This class is used to manage service providers cache.
 * The cache is refreshed by a background daemon that periodically fetches the
 * current list of Service Providers from DB.
 */
public class ServiceProviderManager {
    private static final Logger LOGGER = LoggerFactory.getLogger(ServiceProviderManager.class);
    private ScheduledExecutorService scheduledExecutor;
    private final DBService dbService;
    private final String serviceProviderDomain;
    private final String serviceProviderRole;
    private final Authorizer authorizer;
    volatile Map<String, DomainDependencyProvider> serviceProviders;

    //The one and only instance
    private static volatile ServiceProviderManager instance;

    private ServiceProviderManager(final DBService dbService, final Authorizer authorizer) {
        LOGGER.info("initializing ServiceProviderManager to periodically refresh the list of Service Providers from DB");
        serviceProviderDomain = System.getProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_DOMAIN, ZMS_PROP_SERVICE_PROVIDER_MANAGER_DOMAIN_DEFAULT);
        serviceProviderRole = System.getProperty(ZMS_PROP_SERVICE_PROVIDER_MANAGER_ROLE, ZMS_PROP_SERVICE_PROVIDER_MANAGER_ROLE_DEFAULT);
        this.dbService = dbService;
        this.authorizer = authorizer;
        this.serviceProviders = Collections.emptyMap();
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

    public static synchronized ServiceProviderManager getInstance(DBService dbService, Authorizer authorizer) {
        if (instance == null) {
            instance = new ServiceProviderManager(dbService, authorizer);
        }
        return instance;
    }

    /**
     * Shutdown hook for the scheduler
     */
    public void shutdown() {
        scheduledExecutor.shutdownNow();
    }

    private void refreshServiceProviders() {
        LOGGER.info("Refreshing service providers in cache");
        Role role = dbService.getRole(serviceProviderDomain, serviceProviderRole, false, true, false);
        if (role == null) {
            LOGGER.warn("Unable to fetch service provider role. Service cache provider list will not be updated");
            return;
        }
        if (role.getRoleMembers() == null || role.getRoleMembers().isEmpty()) {
            LOGGER.warn("Service provider role is empty, resetting cache list.");
            serviceProviders = Collections.emptyMap();
            return;
        }

        serviceProviders = role.getRoleMembers().stream()
                .filter(roleMember -> !StringUtil.isEmpty(roleMember.getMemberName()))
                .map(roleMember -> {
                    final String provider = roleMember.getMemberName();
                    final String provSvcDomain = ZMSUtils.providerServiceDomain(provider);
                    final String provSvcName = ZMSUtils.providerServiceName(provider);
                    ServiceIdentity provSvcIdentity = dbService.getServiceIdentity(provSvcDomain, provSvcName, true);
                    if (provSvcIdentity == null) {
                        return null;
                    }
                    final String endpoint = provSvcIdentity.getProviderEndpoint();
                    boolean isInstanceProvider = isServiceProviderAuthorizedLaunch(provSvcIdentity);
                    return new DomainDependencyProvider(provider, endpoint, isInstanceProvider);
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toMap(DomainDependencyProvider::getProvider, Function.identity()));
    }

    private boolean isServiceProviderAuthorizedLaunch(ServiceIdentity provSvcIdentity) {
        Principal providerServicePrincipal = SimplePrincipal.create(
                ZMSUtils.providerServiceDomain(provSvcIdentity.getName()),
                ZMSUtils.providerServiceName(provSvcIdentity.getName()),
                (String) null);
        return authorizer.access(ServerCommonConsts.ACTION_LAUNCH, ServerCommonConsts.RESOURCE_INSTANCE,
                providerServicePrincipal, null);
    }

    /**
     * Checks if the given principal is an authorized service provider
     * @param principal the service identity to check
     * @return True if principal is an authorized service provider. False otherwise
     */
    public boolean isServiceProvider(String principal) {
        return !StringUtil.isEmpty(principal) && serviceProviders.containsKey(principal);
    }

    public void setServiceProviders(Map<String, DomainDependencyProvider> serviceProviders) {
        this.serviceProviders = serviceProviders;
    }

    public Map<String, DomainDependencyProvider> getServiceProvidersWithEndpoints() {
        return this.serviceProviders.entrySet()
                .stream()
                .filter(entry -> entry.getValue() != null && !StringUtil.isEmpty(entry.getValue().getProviderEndpoint()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    public static class DomainDependencyProvider {
        private final String provider;
        private final String providerEndpoint;
        private final boolean isInstanceProvider;

        public DomainDependencyProvider(String provider, String providerEndpoint, boolean isInstanceProvider) {
            this.provider = provider;
            this.providerEndpoint = providerEndpoint;
            this.isInstanceProvider = isInstanceProvider;
        }

        public String getProvider() {
            return provider;
        }

        public String getProviderEndpoint() {
            return providerEndpoint;
        }

        public boolean isInstanceProvider() {
            return isInstanceProvider;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                    return false;
            }
            DomainDependencyProvider that = (DomainDependencyProvider) o;
            return isInstanceProvider() == that.isInstanceProvider() && getProvider().equals(that.getProvider()) && Objects.equals(getProviderEndpoint(), that.getProviderEndpoint());
        }

        @Override
        public int hashCode() {
            return Objects.hash(getProvider(), getProviderEndpoint(), isInstanceProvider());
        }
    }
}
