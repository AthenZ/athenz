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
package com.yahoo.athenz.instance.provider.impl;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.token.OAuth2Token;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.common.server.http.HttpDriver;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ResourceException;
import com.yahoo.athenz.zts.AccessTokenResponse;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class InstanceAzureProvider implements InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceAzureProvider.class);

    static final String AZURE_PROP_AKS_DNS_SUFFIX          = "athenz.zts.azure_aks_dns_suffix";

    static final String AZURE_PROP_PROVIDER                = "athenz.zts.azure_provider";
    static final String AZURE_PROP_ZTS_RESOURCE_URI        = "athenz.zts.azure_resource_uri";
    static final String AZURE_PROP_DNS_SUFFIX              = "athenz.zts.azure_dns_suffix";
    static final String AZURE_PROP_OPENID_CONFIG_URI       = "athenz.zts.azure_openid_config_uri";
    static final String AZURE_PROP_TOKEN_UPDATE_TIMEOUT    = "athenz.zts.azure_token_update_timeout";

    static final String AZURE_PROP_MGMT_BASE_URI           = "athenz.zts.azure_mgmt_base_uri";
    static final String AZURE_PROP_META_BASE_URI           = "athenz.zts.azure_meta_base_uri";
    static final String AZURE_PROP_MGMT_MAX_POOL_ROUTE     = "athenz.zts.azure_mgmt_client_max_pool_route";
    static final String AZURE_PROP_MGMT_MAX_POOL_TOTAL     = "athenz.zts.azure_mgmt_client_max_pool_total";
    static final String AZURE_PROP_MGMT_RETRY_INTERVAL_MS  = "athenz.zts.azure_mgmt_client_retry_interval_ms";
    static final String AZURE_PROP_MGMT_MAX_RETRIES        = "athenz.zts.azure_mgmt_client_max_retries";
    static final String AZURE_PROP_MGMT_CONNECT_TIMEOUT_MS = "athenz.zts.azure_mgmt_client_connect_timeout_ms";
    static final String AZURE_PROP_MGMT_READ_TIMEOUT_MS    = "athenz.zts.azure_mgmt_client_read_timeout_ms";

    static final String AZURE_OPENID_CONFIG_URI = "https://login.microsoftonline.com/common/.well-known/openid-configuration";

    String azureProvider = null;
    Set<String> dnsSuffixes = null;
    List<String> aksDnsSuffixes = null;
    String azureJwksUri = null;
    HttpDriver httpDriver = null;
    ObjectMapper jsonMapper = null;
    String ztsResourceUri = null;
    JwtsSigningKeyResolver signingKeyResolver = null;
    String azureMgmtBaseUri = null;
    String azureMetaBaseUri = null;
    String accessToken = null;
    ScheduledExecutorService scheduledThreadPool = null;

    @Override
    public Scheme getProviderScheme() {
        return Scheme.HTTP;
    }

    @Override
    public void initialize(String provider, String providerEndpoint, SSLContext sslContext,
            KeyStore keyStore) {

        azureProvider = System.getProperty(AZURE_PROP_PROVIDER);
        azureMgmtBaseUri = System.getProperty(AZURE_PROP_MGMT_BASE_URI, "https://management.azure.com");
        azureMetaBaseUri = System.getProperty(AZURE_PROP_META_BASE_URI, "http://169.254.169.254");

        // we need to extract Azure jwks uri and initialize our jwks signer

        boolean enabled = true;
        final String openIdConfigUri = System.getProperty(AZURE_PROP_OPENID_CONFIG_URI, AZURE_OPENID_CONFIG_URI);
        JwtsHelper helper = new JwtsHelper();
        azureJwksUri = helper.extractJwksUri(openIdConfigUri, sslContext);
        if (StringUtil.isEmpty(azureJwksUri)) {
            LOGGER.error("Azure jwks uri not available - no instance requests will be authorized");
            enabled = false;
        }

        signingKeyResolver = new JwtsSigningKeyResolver(azureJwksUri, sslContext, true);

        // make sure we have retrieved some public keys

        if (signingKeyResolver.publicKeyCount() == 0) {
            LOGGER.error("No Azure public keys available - no instance requests will be authorized");
            enabled = false;
        }

        // determine the dns suffix. if this is not specified we'll
        // be rejecting all entries

        dnsSuffixes = new HashSet<>();
        final String dnsSuffix = System.getProperty(AZURE_PROP_DNS_SUFFIX);
        if (StringUtil.isEmpty(dnsSuffix)) {
            LOGGER.error("Azure Suffix not specified - no instance requests will be authorized");
            enabled = false;
        } else {
            dnsSuffixes.addAll(Arrays.asList(dnsSuffix.split(",")));
        }

        aksDnsSuffixes = InstanceUtils.processK8SDnsSuffixList(AZURE_PROP_AKS_DNS_SUFFIX);

        ztsResourceUri = System.getProperty(AZURE_PROP_ZTS_RESOURCE_URI);
        if (StringUtil.isEmpty(ztsResourceUri)) {
            LOGGER.error("Azure ZTS Resource URI not specified - no instance requests will be authorized");
            enabled = false;
        }

        // get our json deserializer

        jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        // create our http client for obtaining vm details

        try {
            httpDriver = getHttpDriver(sslContext);
        } catch (Exception ex) {
            LOGGER.error("Azure HTTP Client not created - no instance requests will be authorized");
            httpDriver = null;
            enabled = false;
        }

        // if our settings are not valid there is no point of starting
        // our timer thread to obtain AD access token

        if (enabled) {

            // let's first manually fetch the access token

            try {
                fetchAccessToken();
            } catch (Exception ex) {
                LOGGER.error("Unable to fetch VM access token", ex);
            }

            // now setup our credential updater

            int credsUpdateTime = Integer.parseInt(System.getProperty(AZURE_PROP_TOKEN_UPDATE_TIMEOUT, "10"));

            scheduledThreadPool = Executors.newScheduledThreadPool(1);
            scheduledThreadPool.scheduleAtFixedRate(new AzureCredentialsUpdater(), credsUpdateTime,
                    credsUpdateTime, TimeUnit.MINUTES);
        }
    }

    @Override
    public void close() {
        if (httpDriver != null) {
            httpDriver.close();
        }
        if (scheduledThreadPool != null) {
            scheduledThreadPool.shutdown();
        }
    }

    public ResourceException error(String message) {
        return error(ResourceException.FORBIDDEN, message);
    }
    
    public ResourceException error(int errorCode, String message) {
        LOGGER.error(message);
        return new ResourceException(errorCode, message);
    }
    
    @Override
    public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) {

        AzureAttestationData info;
        try {
            info = jsonMapper.readValue(confirmation.getAttestationData(), AzureAttestationData.class);
        } catch (Exception ex) {
            LOGGER.error("Unable to parse attestation data {}", confirmation.getAttestationData(), ex);
            throw error("Unable to parse attestation data");
        }
        
        final Map<String, String> instanceAttributes = confirmation.getAttributes();
        final String instanceDomain = confirmation.getDomain();
        final String instanceService = confirmation.getService();
        
        // before doing anything else we want to make sure our
        // object has an associated azure account id
        
        final String azureSubscription = InstanceUtils.getInstanceProperty(instanceAttributes, ZTS_INSTANCE_AZURE_SUBSCRIPTION);
        if (StringUtil.isEmpty(azureSubscription)) {
            throw error("Unable to extract Azure Subscription id");
        }

        if (!azureSubscription.equals(info.getSubscriptionId())) {
            LOGGER.error("Azure Subscription Id mismatch {}/{}", azureSubscription, info.getSubscriptionId());
            throw error("Azure Subscription Id mismatch");
        }
        
        // validate the certificate host names
        
        StringBuilder instanceId = new StringBuilder(256);
        if (!InstanceUtils.validateCertRequestSanDnsNames(instanceAttributes, instanceDomain,
                instanceService, dnsSuffixes, aksDnsSuffixes, null, false, instanceId, null)) {
            throw error("Unable to validate certificate request hostnames");
        }

        // reset attributes being sent back to the client

        setConfirmationAttributes(confirmation);

        // generate our service name for validation

        final String serviceName = instanceDomain + "." + instanceService;

        // verify that access token in the request is valid
        
        if (!verifyInstanceIdentity(info, confirmation.getProvider(), serviceName, instanceId.toString())) {
            throw error("Unable to verify instance identity credentials");
        }
        
        return confirmation;
    }

    boolean verifyInstanceIdentity(AzureAttestationData info, final String provider, final String serviceName,
                                   final String instanceId) {

        // first validate the access token provided by the client

        OAuth2Token vmToken = validateAccessToken(info.getToken());
        if (vmToken == null) {
            LOGGER.error("Unable to validate VM access token for account {}", info.getSubscriptionId());
            return false;
        }

        if (!ztsResourceUri.equals(vmToken.getAudience())) {
            LOGGER.error("Azure Token not issued for ZTS resource {}/{}", ztsResourceUri, vmToken.getAudience());
            return false;
        }

        // now fetch the details and verify object id

        final String vmDetailsData = fetchVMDetails(info);
        if (vmDetailsData == null) {
            LOGGER.error("Unable to fetch VM details for account {}", info.getSubscriptionId());
            return false;
        }

        AzureVmDetails vmDetails = parseVmDetails(vmDetailsData);
        if (vmDetails == null) {
            LOGGER.error("Unable to parse VM details for account {}", info.getSubscriptionId());
            return false;
        }

        // the vm identity id must match our token subject

        if (!vmToken.getSubject().equals(vmDetails.getIdentity().getPrincipalId())) {
            LOGGER.error("Azure Token not issued for requested VM instance {}/{}",
                    vmToken.getSubject(), vmDetails.getIdentity().getPrincipalId());
            return false;
        }

        // verify the service name details

        if (!serviceName.equals(vmDetails.getTags().getAthenz())) {
            LOGGER.error("Azure Service Name mismatch {}/{}", serviceName, vmDetails.getTags().getAthenz());
            return false;
        }

        // validate that our vm id matches our instance id

        if (!instanceId.equals(vmDetails.getProperties().getVmId())) {
            LOGGER.error("Azure VM Id mismatch {}/{}", instanceId, vmDetails.getProperties().getVmId());
            return false;
        }

        final String vmProvider = StringUtil.isEmpty(azureProvider) ?
                "athenz.azure." + vmDetails.getLocation() : azureProvider;
        if (!provider.equals(vmProvider)) {
            LOGGER.error("Azure Provider {}/{}", provider, vmProvider);
            return false;
        }

        return true;
    }

    AzureVmDetails parseVmDetails(String vmDetailsData) {

        try {
            return jsonMapper.readValue(vmDetailsData, AzureVmDetails.class);
        } catch (Exception ex) {
            LOGGER.error("Unable to parse azure vm details {}", vmDetailsData, ex);
        }
        return null;
    }

    String fetchVMDetails(AzureAttestationData info) {

        if (httpDriver == null) {
            LOGGER.error("No Azure HTTP Client available");
            return null;
        }

        if (accessToken == null) {
            LOGGER.error("No authorization access token available");
            return null;
        }

        // extract the VM details from Azure Management API

        final String vmUri = azureMgmtBaseUri + "/subscriptions/" + info.getSubscriptionId() +
                "/resourceGroups/" + info.getResourceGroupName() +
                "/providers/Microsoft.Compute/virtualMachines/" + info.getName() +
                "?api-version=2020-06-01";

        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", accessToken);

        try {
            return httpDriver.doGet(vmUri, headers);
        } catch (Exception ex) {
            LOGGER.error("Unable to extract VM details: {}", vmUri, ex);
        }
        return null;
    }

    OAuth2Token validateAccessToken(final String token) {
        OAuth2Token vmToken = null;
        try {
            vmToken = new OAuth2Token(token, signingKeyResolver);
        } catch (Exception ex) {
            LOGGER.error("Unable to validate VM access token", ex);
        }
        return vmToken;
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) {

        // for azure we have the same authentication for refresh
        // as we do for the register request

        return confirmInstance(confirmation);
    }
    
    void setConfirmationAttributes(InstanceConfirmation confirmation) {
        confirmation.setAttributes(new HashMap<>());
    }

    private HttpDriver getHttpDriver(SSLContext sslContext) {

        int maxPoolRoute = Integer.parseInt(System.getProperty(AZURE_PROP_MGMT_MAX_POOL_ROUTE, "45"));
        int maxPoolTotal = Integer.parseInt(System.getProperty(AZURE_PROP_MGMT_MAX_POOL_TOTAL, "50"));
        int clientRetryIntervalMs = Integer.parseInt(System.getProperty(AZURE_PROP_MGMT_RETRY_INTERVAL_MS, "1000"));
        int clientMaxRetries = Integer.parseInt(System.getProperty(AZURE_PROP_MGMT_MAX_RETRIES, "2"));
        int clientConnectTimeoutMs = Integer.parseInt(System.getProperty(AZURE_PROP_MGMT_CONNECT_TIMEOUT_MS, "5000"));
        int clientReadTimeoutMs = Integer.parseInt(System.getProperty(AZURE_PROP_MGMT_READ_TIMEOUT_MS, "15000"));

        return new HttpDriver.Builder("", sslContext)
                .maxPoolPerRoute(maxPoolRoute)
                .maxPoolTotal(maxPoolTotal)
                .clientRetryIntervalMs(clientRetryIntervalMs)
                .clientMaxRetries(clientMaxRetries)
                .clientConnectTimeoutMs(clientConnectTimeoutMs)
                .clientReadTimeoutMs(clientReadTimeoutMs)
                .build();
    }

    void fetchAccessToken() throws IOException {
        // extract the VM details from Azure Management API

        final String tokenUri = azureMetaBaseUri + "/metadata/identity/oauth2/token?api-version=2020-06-01&resource=" +
                azureMgmtBaseUri;

        Map<String, String> headers = new HashMap<>();
        headers.put("Metadata", "true");

        String tokenData = httpDriver.doGet(tokenUri, headers);
        if (tokenData == null) {
            throw error("Unable to fetch access token");
        }

        AccessTokenResponse tokenResponse = null;
        try {
            tokenResponse = jsonMapper.readValue(tokenData, AccessTokenResponse.class);
        } catch (Exception ex) {
            LOGGER.error("unable to parse access token response: {}", tokenData, ex);
        }

        if (tokenResponse == null) {
            throw error("Unable to parse access token response");
        }

        if (StringUtil.isEmpty(tokenResponse.access_token)) {
            throw error("Empty access token returned");
        }

        accessToken = "Bearer " + tokenResponse.access_token;
    }

    class AzureCredentialsUpdater implements Runnable {

        @Override
        public void run() {

            LOGGER.info("AzureCredentialsUpdater: Starting Azure credentials updater task...");

            try {
                fetchAccessToken();
            } catch (Exception ex) {
                LOGGER.error("AzureCredentialsUpdater: unable to fetch Azure access token", ex);
            }

            LOGGER.info("AzureCredentialsUpdater: Azure credentials updater task completed");
        }
    }
}
