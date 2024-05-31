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

import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.http.HttpDriver;
import com.yahoo.athenz.instance.provider.ExternalCredentialsProvider;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ResourceException;
import com.yahoo.athenz.zts.ExternalCredentialsResponse;
import io.jsonwebtoken.SignatureAlgorithm;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.matches;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class InstanceAzureProviderTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private final File ecPublicKey = new File("./src/test/resources/unit_test_ec_public.key");

    @BeforeMethod
    public void setup() {
        System.setProperty(InstanceAzureProvider.AZURE_PROP_DNS_SUFFIX, "azure.cloud");
        System.setProperty(InstanceAzureProvider.AZURE_PROP_MGMT_MAX_RETRIES, "0");
        System.setProperty(InstanceAzureProvider.AZURE_PROP_MGMT_CONNECT_TIMEOUT_MS, "100");
    }

    @AfterMethod
    public void shutdown() {
        System.clearProperty(InstanceAzureProvider.AZURE_PROP_DNS_SUFFIX);
        System.clearProperty(InstanceAzureProvider.AZURE_PROP_MGMT_MAX_RETRIES);
        System.clearProperty(InstanceAzureProvider.AZURE_PROP_MGMT_CONNECT_TIMEOUT_MS);
    }

    private void setUpExternalCredentialsProvider(InstanceAzureProvider provider) {
        ExternalCredentialsProvider credentialsProvider = Mockito.mock(ExternalCredentialsProvider.class);
        provider.setExternalCredentialsProvider(credentialsProvider);
        ExternalCredentialsResponse response = new ExternalCredentialsResponse();
        response.setAttributes(new HashMap<>());
        response.getAttributes().put("accessToken", "access-token");
        Mockito.when(credentialsProvider.getExternalCredentials(any(), any(), any())).thenReturn(response);
    }

    @Test
    public void testInitializeDefaults() throws IOException {

        File configUri = new File("./src/test/resources/azure-openid-uri.json");
        System.setProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI, "file://" + configUri.getCanonicalPath());

        InstanceAzureProvider provider = new InstanceAzureProvider();
        setUpExternalCredentialsProvider(provider);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAzureProvider", null, null);

        assertEquals(provider.getProviderScheme(), InstanceProvider.Scheme.HTTP);
        assertTrue(provider.dnsSuffixes.contains("azure.cloud"));
        assertEquals(provider.azureJwksUri, "file://src/test/resources/keys.json");
        provider.close();

        System.clearProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI);
    }

    @Test
    public void testInitializeEmptyValues() throws IOException {

        File configUri = new File("./src/test/resources/azure-openid-nouri.json");
        System.setProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI, "file://" + configUri.getCanonicalPath());
        System.clearProperty(InstanceAzureProvider.AZURE_PROP_DNS_SUFFIX);

        InstanceAzureProvider provider = new InstanceAzureProvider();
        setUpExternalCredentialsProvider(provider);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAzureProvider", null, null);

        assertTrue(provider.dnsSuffixes.isEmpty());
        assertNull(provider.azureJwksUri);
        provider.close();

        System.clearProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI);
    }

    @Test
    public void testConfirmInstance() throws IOException {

        File configFile = new File("./src/test/resources/azure-openid.json");
        File jwksUri = new File("./src/test/resources/azure-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, true);

        System.setProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI, "https://azure-zts");
        System.setProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI, "file://" + configFile.getCanonicalPath());
        InstanceAzureProvider provider = new InstanceAzureProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAzureProvider", null, null);

        ExternalCredentialsResponse credentialsResponse = new ExternalCredentialsResponse();
        credentialsResponse.setAttributes(new HashMap<>());
        credentialsResponse.getAttributes().put("accessToken", "access-token");
        provider.externalCredentialsProvider = Mockito.mock(ExternalCredentialsProvider.class);
        Mockito.when(provider.externalCredentialsProvider.getExternalCredentials(eq("azure"), eq("athenz"), argThat(arg -> {
            return arg.getClientId().equals("athenz.azure.azure-client") &&
                   arg.getAttributes().get("athenzScope").equals("openid athenz.azure:role.azure-client") &&
                   arg.getAttributes().size() == 1;
        }))).thenReturn(credentialsResponse);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("athenz");
        confirmation.setService("backend");
        confirmation.setProvider("athenz.azure.westus2");
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_AZURE_SUBSCRIPTION, "1111-2222");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "backend.athenz.azure.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/athenz.azure.uswest2/2222-3333");
        confirmation.setAttributes(attributes);

        AzureAttestationData data = new AzureAttestationData();
        data.setVmId("2222-3333");
        data.setSubscriptionId("1111-2222");
        data.setResourceGroupName("prod");
        data.setName("athenz-client");
        data.setLocation("westus2");
        data.setToken(createAccessToken());

        confirmation.setAttestationData(provider.jsonMapper.writeValueAsString(data));

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        provider.signingKeyResolver.addPublicKey("eckey1", publicKey);

        provider.httpDriver = setupHttpDriver();

        InstanceConfirmation providerConfirm = provider.confirmInstance(confirmation);
        assertNotNull(providerConfirm);

        provider.close();

        System.clearProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI);
        System.clearProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI);
        removeOpenIdConfigFile(configFile, jwksUri);
    }

    @Test
    public void testConfirmInstanceProviderConfig() throws IOException {

        File configFile = new File("./src/test/resources/azure-openid.json");
        File jwksUri = new File("./src/test/resources/azure-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, true);

        System.setProperty(InstanceAzureProvider.AZURE_PROP_PROVIDER, "athenz.azure.provider");
        System.setProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI, "https://azure-zts");
        System.setProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI, "file://" + configFile.getCanonicalPath());
        InstanceAzureProvider provider = new InstanceAzureProvider();
        setUpExternalCredentialsProvider(provider);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAzureProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("athenz");
        confirmation.setService("backend");
        confirmation.setProvider("athenz.azure.provider");
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_AZURE_SUBSCRIPTION, "1111-2222");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "backend.athenz.azure.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/athenz.azure.uswest2/2222-3333");
        confirmation.setAttributes(attributes);

        AzureAttestationData data = new AzureAttestationData();
        data.setVmId("2222-3333");
        data.setSubscriptionId("1111-2222");
        data.setResourceGroupName("prod");
        data.setName("athenz-client");
        data.setLocation("westus2");
        data.setToken(createAccessToken());

        confirmation.setAttestationData(provider.jsonMapper.writeValueAsString(data));

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        provider.signingKeyResolver.addPublicKey("eckey1", publicKey);

        provider.httpDriver = setupHttpDriver();

        InstanceConfirmation providerConfirm = provider.confirmInstance(confirmation);
        assertNotNull(providerConfirm);

        provider.close();

        System.clearProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI);
        System.clearProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI);
        System.clearProperty(InstanceAzureProvider.AZURE_PROP_PROVIDER);
        removeOpenIdConfigFile(configFile, jwksUri);
    }

    @Test
    public void testRefreshInstance() throws IOException {

        File configFile = new File("./src/test/resources/azure-openid.json");
        File jwksUri = new File("./src/test/resources/azure-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, true);

        System.setProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI, "https://azure-zts");
        System.setProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI, "file://" + configFile.getCanonicalPath());
        InstanceAzureProvider provider = new InstanceAzureProvider();
        setUpExternalCredentialsProvider(provider);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAzureProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("athenz");
        confirmation.setService("backend");
        confirmation.setProvider("athenz.azure.westus2");
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_AZURE_SUBSCRIPTION, "1111-2222");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "backend.athenz.azure.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/athenz.azure.uswest2/2222-3333");
        confirmation.setAttributes(attributes);

        AzureAttestationData data = new AzureAttestationData();
        data.setVmId("2222-3333");
        data.setSubscriptionId("1111-2222");
        data.setResourceGroupName("prod");
        data.setName("athenz-client");
        data.setLocation("westus2");
        data.setToken(createAccessToken());

        confirmation.setAttestationData(provider.jsonMapper.writeValueAsString(data));

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        provider.signingKeyResolver.addPublicKey("eckey1", publicKey);


        String vmDetailsWithUserAssignedIdentities =
                "{\n" +
                "  \"name\": \"athenz-client\",\n" +
                "  \"id\": \"/subscriptions/123456/resourceGroups/Athenz/providers/Microsoft.Compute/virtualMachines/athenz-client\",\n" +
                "  \"location\": \"westus2\",\n" +
                "  \"tags\": {\n" +
                "    \"athenz\": \"athenz.backend\"\n" +
                "  },\n" +
                "  \"identity\": {\n" +
                "    \"type\": \"UserAssigned\",\n" +
                "    \"userAssignedIdentities\": {\n" +
                "      \"/subscriptions/23423423-d46a-45db-aad6-29a1fdab4f86/resourceGroups/system/providers/Microsoft.ManagedIdentity/userAssignedIdentities/my-id\": {\n" +
                "        \"principalId\": \"111111-2222-3333-4444-555555555\",\n" +
                "        \"clientId\": \"f6ed0c62-f2cb-4ebc-8c4e-e81c43887914\"\n" +
                "      }\n" +
                "    }\n" +
                "  },\n" +
                "  \"properties\": {\n" +
                "    \"vmId\": \"2222-3333\"\n" +
                "  }\n" +
                "}";


        provider.httpDriver = setupHttpDriver(vmDetailsWithUserAssignedIdentities);

        InstanceConfirmation providerConfirm = provider.refreshInstance(confirmation);
        assertNotNull(providerConfirm);

        provider.close();

        System.clearProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI);
        System.clearProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI);
        removeOpenIdConfigFile(configFile, jwksUri);
    }

    private HttpDriver setupHttpDriver() throws IOException {
        final String vmDetails =
                "{\n" +
                "  \"name\": \"athenz-client\",\n" +
                "  \"id\": \"/subscriptions/123456/resourceGroups/Athenz/providers/Microsoft.Compute/virtualMachines/athenz-client\",\n" +
                "  \"location\": \"westus2\",\n" +
                "  \"tags\": {\n" +
                "    \"athenz\": \"athenz.backend\"\n" +
                "  },\n" +
                "  \"identity\": {\n" +
                "    \"type\": \"SystemAssigned, UserAssigned\",\n" +
                "    \"principalId\": \"111111-2222-3333-4444-555555555\",\n" +
                "    \"tenantId\": \"222222-3333-4444-5555-66666666\"\n" +
                "  },\n" +
                "  \"properties\": {\n" +
                "    \"vmId\": \"2222-3333\"\n" +
                "  }\n" +
                "}";
        return setupHttpDriver(vmDetails);
    }

    private HttpDriver setupHttpDriver(String vmDetails) throws IOException {

        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);

        final String vmUri = "https://management.azure.com/subscriptions/1111-2222/resourceGroups/prod" +
                "/providers/Microsoft.Compute/virtualMachines/athenz-client?api-version=2020-06-01";

        Map<String, String> vmHeaders = new HashMap<>();
        vmHeaders.put("Authorization", "Bearer access-token");
        Mockito.when(httpDriver.doGet(vmUri, vmHeaders)).thenReturn(vmDetails);

        return httpDriver;
    }

    @Test
    public void testConfirmInstanceInvalidAttestationData() {

        InstanceAzureProvider provider = new InstanceAzureProvider();
        setUpExternalCredentialsProvider(provider);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData("invalid-json");

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Unable to parse attestation data"));
        }

        provider.close();
    }

    @Test
    public void testConfirmInstanceAzureSubscriptionIssues() throws IOException {

        InstanceAzureProvider provider = new InstanceAzureProvider();
        setUpExternalCredentialsProvider(provider);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAzureProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("athenz");
        confirmation.setService("backend");
        confirmation.setProvider("athenz.azure.westus2");
        Map<String, String> attributes = new HashMap<>();
        confirmation.setAttributes(attributes);

        AzureAttestationData data = new AzureAttestationData();
        data.setVmId("2222-3333");
        data.setSubscriptionId("1111-2222");

        confirmation.setAttestationData(provider.jsonMapper.writeValueAsString(data));

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Unable to extract Azure Subscription id"));
        }

        // add the subscription but different from what's in the data object

        attributes.put(InstanceProvider.ZTS_INSTANCE_AZURE_SUBSCRIPTION, "1111-3333");

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Azure Subscription Id mismatch"));
        }

        provider.close();
    }

    @Test
    public void testConfirmInstanceSanDnsMismatch() throws IOException {

        InstanceAzureProvider provider = new InstanceAzureProvider();
        setUpExternalCredentialsProvider(provider);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAzureProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("athenz");
        confirmation.setService("backend");
        confirmation.setProvider("athenz.azure.westus2");
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_AZURE_SUBSCRIPTION, "1111-2222");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "backend.athenz.azure.test.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/athenz.azure.uswest2/2222-3333");
        confirmation.setAttributes(attributes);

        AzureAttestationData data = new AzureAttestationData();
        data.setVmId("2222-3333");
        data.setSubscriptionId("1111-2222");

        confirmation.setAttestationData(provider.jsonMapper.writeValueAsString(data));

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Unable to validate certificate request hostnames"));
        }

        provider.close();
    }

    @Test
    public void testConfirmInstanceInvalidAccessToken() throws IOException {

        File configFile = new File("./src/test/resources/azure-openid.json");
        File jwksUri = new File("./src/test/resources/azure-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, false);

        System.setProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI, "https://azure-zts");
        System.setProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI, "file://" + configFile.getCanonicalPath());
        InstanceAzureProvider provider = new InstanceAzureProvider();
        setUpExternalCredentialsProvider(provider);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAzureProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("athenz");
        confirmation.setService("backend");
        confirmation.setProvider("athenz.azure.westus2");
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_AZURE_SUBSCRIPTION, "1111-2222");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "backend.athenz.azure.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/athenz.azure.uswest2/2222-3333");
        confirmation.setAttributes(attributes);

        AzureAttestationData data = new AzureAttestationData();
        data.setVmId("2222-3333");
        data.setSubscriptionId("1111-2222");
        data.setResourceGroupName("prod");
        data.setName("athenz-client");
        data.setLocation("westus2");
        data.setToken("invalid-token");

        confirmation.setAttestationData(provider.jsonMapper.writeValueAsString(data));

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Unable to verify instance identity credentials"));
        }

        provider.close();

        System.clearProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI);
        System.clearProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI);
        removeOpenIdConfigFile(configFile, jwksUri);
    }

    @Test
    public void testConfirmInstanceAudienceMismatch() throws IOException {

        File configFile = new File("./src/test/resources/azure-openid.json");
        File jwksUri = new File("./src/test/resources/azure-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, false);

        System.setProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI, "https://azure-zts-nomatch");
        System.setProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI, "file://" + configFile.getCanonicalPath());
        InstanceAzureProvider provider = new InstanceAzureProvider();
        setUpExternalCredentialsProvider(provider);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAzureProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("athenz");
        confirmation.setService("backend");
        confirmation.setProvider("athenz.azure.westus2");
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_AZURE_SUBSCRIPTION, "1111-2222");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "backend.athenz.azure.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/athenz.azure.uswest2/2222-3333");
        confirmation.setAttributes(attributes);

        AzureAttestationData data = new AzureAttestationData();
        data.setVmId("2222-3333");
        data.setSubscriptionId("1111-2222");
        data.setResourceGroupName("prod");
        data.setName("athenz-client");
        data.setLocation("westus2");
        data.setToken(createAccessToken());

        confirmation.setAttestationData(provider.jsonMapper.writeValueAsString(data));

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        provider.signingKeyResolver.addPublicKey("eckey1", publicKey);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Unable to verify instance identity credentials"));
        }

        provider.close();

        System.clearProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI);
        System.clearProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI);
        removeOpenIdConfigFile(configFile, jwksUri);
    }

    @Test
    public void testConfirmInstanceUnableToFetchVMDetails() throws IOException {

        File configFile = new File("./src/test/resources/azure-openid.json");
        File jwksUri = new File("./src/test/resources/azure-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, false);

        System.setProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI, "https://azure-zts");
        System.setProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI, "file://" + configFile.getCanonicalPath());
        InstanceAzureProvider provider = new InstanceAzureProvider();
        setUpExternalCredentialsProvider(provider);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAzureProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("athenz");
        confirmation.setService("backend");
        confirmation.setProvider("athenz.azure.westus2");
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_AZURE_SUBSCRIPTION, "1111-2222");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "backend.athenz.azure.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/athenz.azure.uswest2/2222-3333");
        confirmation.setAttributes(attributes);

        AzureAttestationData data = new AzureAttestationData();
        data.setVmId("2222-3333");
        data.setSubscriptionId("1111-2222");
        data.setResourceGroupName("prod");
        data.setName("athenz-client");
        data.setLocation("westus2");
        data.setToken(createAccessToken());

        confirmation.setAttestationData(provider.jsonMapper.writeValueAsString(data));

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        provider.signingKeyResolver.addPublicKey("eckey1", publicKey);

        // first with null http-driver

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Unable to verify instance identity credentials"));
        }

        // then will null access tokens

        provider.httpDriver = Mockito.mock(HttpDriver.class);
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Unable to verify instance identity credentials"));
        }

        // then with mock throwing an exception

        Mockito.when(provider.httpDriver.doGet(any(), any())).thenThrow(new IllegalArgumentException("bad client"));
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Unable to verify instance identity credentials"));
        }

        provider.close();

        System.clearProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI);
        System.clearProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI);
        removeOpenIdConfigFile(configFile, jwksUri);
    }

    @Test
    public void testConfirmInstanceInvalidVMDetails() throws IOException {

        File configFile = new File("./src/test/resources/azure-openid.json");
        File jwksUri = new File("./src/test/resources/azure-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, false);

        System.setProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI, "https://azure-zts");
        System.setProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI, "file://" + configFile.getCanonicalPath());
        InstanceAzureProvider provider = new InstanceAzureProvider();
        setUpExternalCredentialsProvider(provider);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAzureProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("athenz");
        confirmation.setService("backend");
        confirmation.setProvider("athenz.azure.westus2");
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_AZURE_SUBSCRIPTION, "1111-2222");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "backend.athenz.azure.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/athenz.azure.uswest2/2222-3333");
        confirmation.setAttributes(attributes);

        AzureAttestationData data = new AzureAttestationData();
        data.setVmId("2222-3333");
        data.setSubscriptionId("1111-2222");
        data.setResourceGroupName("prod");
        data.setName("athenz-client");
        data.setLocation("westus2");
        data.setToken(createAccessToken());

        confirmation.setAttestationData(provider.jsonMapper.writeValueAsString(data));

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        provider.signingKeyResolver.addPublicKey("eckey1", publicKey);

        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);
        Mockito.when(httpDriver.doGet(any(), any())).thenReturn("invalid-vmdetails");
        provider.httpDriver = httpDriver;

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Unable to verify instance identity credentials"));
        }

        provider.close();

        System.clearProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI);
        System.clearProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI);
        removeOpenIdConfigFile(configFile, jwksUri);
    }

    @Test
    public void testConfirmInstanceSubjectMismatch() throws IOException {

        File configFile = new File("./src/test/resources/azure-openid.json");
        File jwksUri = new File("./src/test/resources/azure-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, false);

        System.setProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI, "https://azure-zts");
        System.setProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI, "file://" + configFile.getCanonicalPath());
        InstanceAzureProvider provider = new InstanceAzureProvider();
        setUpExternalCredentialsProvider(provider);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAzureProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("athenz");
        confirmation.setService("backend");
        confirmation.setProvider("athenz.azure.westus2");
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_AZURE_SUBSCRIPTION, "1111-2222");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "backend.athenz.azure.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/athenz.azure.uswest2/2222-3333");
        confirmation.setAttributes(attributes);

        AzureAttestationData data = new AzureAttestationData();
        data.setVmId("2222-3333");
        data.setSubscriptionId("1111-2222");
        data.setResourceGroupName("prod");
        data.setName("athenz-client");
        data.setLocation("westus2");
        data.setToken(createAccessToken());

        confirmation.setAttestationData(provider.jsonMapper.writeValueAsString(data));

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        provider.signingKeyResolver.addPublicKey("eckey1", publicKey);

        final String vmDetails =
                "{\n" +
                        "  \"name\": \"athenz-client\",\n" +
                        "  \"id\": \"/subscriptions/123456/resourceGroups/Athenz/providers/Microsoft.Compute/virtualMachines/athenz-client\",\n" +
                        "  \"location\": \"westus2\",\n" +
                        "  \"tags\": {\n" +
                        "    \"athenz\": \"athenz.backend\"\n" +
                        "  },\n" +
                        "  \"identity\": {\n" +
                        "    \"type\": \"SystemAssigned, UserAssigned\",\n" +
                        "    \"principalId\": \"4444-555555555\",\n" +
                        "    \"tenantId\": \"222222-3333-4444-5555-66666666\"\n" +
                        "  },\n" +
                        "  \"properties\": {\n" +
                        "    \"vmId\": \"2222-3333\"\n" +
                        "  }\n" +
                        "}";
        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);
        Mockito.when(httpDriver.doGet(any(), any())).thenReturn(vmDetails);
        provider.httpDriver = httpDriver;

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Unable to verify instance identity credentials"));
        }

        provider.close();

        System.clearProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI);
        System.clearProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI);
        removeOpenIdConfigFile(configFile, jwksUri);
    }

    @Test
    public void testConfirmInstanceServiceNameMismatch() throws IOException {

        File configFile = new File("./src/test/resources/azure-openid.json");
        File jwksUri = new File("./src/test/resources/azure-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, false);

        System.setProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI, "https://azure-zts");
        System.setProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI, "file://" + configFile.getCanonicalPath());
        InstanceAzureProvider provider = new InstanceAzureProvider();
        setUpExternalCredentialsProvider(provider);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAzureProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("athenz");
        confirmation.setService("api");
        confirmation.setProvider("athenz.azure.westus2");
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_AZURE_SUBSCRIPTION, "1111-2222");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.athenz.azure.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/athenz.azure.uswest2/2222-3333");
        confirmation.setAttributes(attributes);

        AzureAttestationData data = new AzureAttestationData();
        data.setVmId("2222-3333");
        data.setSubscriptionId("1111-2222");
        data.setResourceGroupName("prod");
        data.setName("athenz-client");
        data.setLocation("westus2");
        data.setToken(createAccessToken());

        confirmation.setAttestationData(provider.jsonMapper.writeValueAsString(data));

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        provider.signingKeyResolver.addPublicKey("eckey1", publicKey);

        final String vmDetails =
                "{\n" +
                        "  \"name\": \"athenz-client\",\n" +
                        "  \"id\": \"/subscriptions/123456/resourceGroups/Athenz/providers/Microsoft.Compute/virtualMachines/athenz-client\",\n" +
                        "  \"location\": \"westus2\",\n" +
                        "  \"tags\": {\n" +
                        "    \"athenz\": \"athenz.backend\"\n" +
                        "  },\n" +
                        "  \"identity\": {\n" +
                        "    \"type\": \"SystemAssigned, UserAssigned\",\n" +
                        "    \"principalId\": \"111111-2222-3333-4444-555555555\",\n" +
                        "    \"tenantId\": \"222222-3333-4444-5555-66666666\"\n" +
                        "  },\n" +
                        "  \"properties\": {\n" +
                        "    \"vmId\": \"2222-3333\"\n" +
                        "  }\n" +
                        "}";
        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);
        Mockito.when(httpDriver.doGet(any(), any())).thenReturn(vmDetails);
        provider.httpDriver = httpDriver;

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Unable to verify instance identity credentials"));
        }

        provider.close();

        System.clearProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI);
        System.clearProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI);
        removeOpenIdConfigFile(configFile, jwksUri);
    }

    @Test
    public void testConfirmInstanceVMIdMismatch() throws IOException {

        File configFile = new File("./src/test/resources/azure-openid.json");
        File jwksUri = new File("./src/test/resources/azure-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, false);

        System.setProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI, "https://azure-zts");
        System.setProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI, "file://" + configFile.getCanonicalPath());
        InstanceAzureProvider provider = new InstanceAzureProvider();
        setUpExternalCredentialsProvider(provider);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAzureProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("athenz");
        confirmation.setService("backend");
        confirmation.setProvider("athenz.azure.westus2");
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_AZURE_SUBSCRIPTION, "1111-2222");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "backend.athenz.azure.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/athenz.azure.uswest2/2222-3333");
        confirmation.setAttributes(attributes);

        AzureAttestationData data = new AzureAttestationData();
        data.setVmId("2222-3333");
        data.setSubscriptionId("1111-2222");
        data.setResourceGroupName("prod");
        data.setName("athenz-client");
        data.setLocation("westus2");
        data.setToken(createAccessToken());

        confirmation.setAttestationData(provider.jsonMapper.writeValueAsString(data));

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        provider.signingKeyResolver.addPublicKey("eckey1", publicKey);

        final String vmDetails =
                "{\n" +
                        "  \"name\": \"athenz-client\",\n" +
                        "  \"id\": \"/subscriptions/123456/resourceGroups/Athenz/providers/Microsoft.Compute/virtualMachines/athenz-client\",\n" +
                        "  \"location\": \"westus2\",\n" +
                        "  \"tags\": {\n" +
                        "    \"athenz\": \"athenz.backend\"\n" +
                        "  },\n" +
                        "  \"identity\": {\n" +
                        "    \"type\": \"SystemAssigned, UserAssigned\",\n" +
                        "    \"principalId\": \"111111-2222-3333-4444-555555555\",\n" +
                        "    \"tenantId\": \"222222-3333-4444-5555-66666666\"\n" +
                        "  },\n" +
                        "  \"properties\": {\n" +
                        "    \"vmId\": \"2222-5555\"\n" +
                        "  }\n" +
                        "}";
        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);
        Mockito.when(httpDriver.doGet(any(), any())).thenReturn(vmDetails);
        provider.httpDriver = httpDriver;

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Unable to verify instance identity credentials"));
        }

        provider.close();

        System.clearProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI);
        System.clearProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI);
        removeOpenIdConfigFile(configFile, jwksUri);
    }

    @Test
    public void testConfirmInstanceProviderMismatch() throws IOException {

        File configFile = new File("./src/test/resources/azure-openid.json");
        File jwksUri = new File("./src/test/resources/azure-jwks.json");
        createOpenIdConfigFile(configFile, jwksUri, false);

        System.setProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI, "https://azure-zts");
        System.setProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI, "file://" + configFile.getCanonicalPath());
        InstanceAzureProvider provider = new InstanceAzureProvider();
        setUpExternalCredentialsProvider(provider);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAzureProvider", null, null);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("athenz");
        confirmation.setService("backend");
        confirmation.setProvider("athenz.azure.eastus1");
        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_AZURE_SUBSCRIPTION, "1111-2222");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "backend.athenz.azure.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/athenz.azure.uswest2/2222-3333");
        confirmation.setAttributes(attributes);

        AzureAttestationData data = new AzureAttestationData();
        data.setVmId("2222-3333");
        data.setSubscriptionId("1111-2222");
        data.setResourceGroupName("prod");
        data.setName("athenz-client");
        data.setLocation("westus2");
        data.setToken(createAccessToken());

        confirmation.setAttestationData(provider.jsonMapper.writeValueAsString(data));

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        provider.signingKeyResolver.addPublicKey("eckey1", publicKey);

        final String vmDetails =
                "{\n" +
                        "  \"name\": \"athenz-client\",\n" +
                        "  \"id\": \"/subscriptions/123456/resourceGroups/Athenz/providers/Microsoft.Compute/virtualMachines/athenz-client\",\n" +
                        "  \"location\": \"westus2\",\n" +
                        "  \"tags\": {\n" +
                        "    \"athenz\": \"athenz.backend\"\n" +
                        "  },\n" +
                        "  \"identity\": {\n" +
                        "    \"type\": \"SystemAssigned, UserAssigned\",\n" +
                        "    \"principalId\": \"111111-2222-3333-4444-555555555\",\n" +
                        "    \"tenantId\": \"222222-3333-4444-5555-66666666\"\n" +
                        "  },\n" +
                        "  \"properties\": {\n" +
                        "    \"vmId\": \"2222-3333\"\n" +
                        "  }\n" +
                        "}";
        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);
        Mockito.when(httpDriver.doGet(any(), any())).thenReturn(vmDetails);
        provider.httpDriver = httpDriver;

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Unable to verify instance identity credentials"));
        }

        provider.close();

        System.clearProperty(InstanceAzureProvider.AZURE_PROP_ZTS_RESOURCE_URI);
        System.clearProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI);
        removeOpenIdConfigFile(configFile, jwksUri);
    }

    private String createAccessToken() {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = new AccessToken();
        accessToken.setAuthTime(now);
        accessToken.setSubject("111111-2222-3333-4444-555555555");
        accessToken.setExpiryTime(now + 3600);
        accessToken.setIssueTime(now);
        accessToken.setClientId("azure-client");
        accessToken.setAudience("https://azure-zts");
        accessToken.setVersion(1);
        accessToken.setIssuer("azure");

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        return accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
    }

    private void removeOpenIdConfigFile(File configFile, File jwksUri) {
        try {
            Files.delete(configFile.toPath());
        } catch (Exception ignored) {
        }
        try {
            Files.delete(jwksUri.toPath());
        } catch (Exception ignored) {
        }
    }

    private void createOpenIdConfigFile(File configFile, File jwksUri, boolean createJkws) throws IOException {

        final String fileContents = "{\n" +
                "    \"jwks_uri\": \"file://" + jwksUri.getCanonicalPath() + "\"\n" +
                "}";
        Files.write(configFile.toPath(), fileContents.getBytes());

        if (createJkws) {
            final String keyContents = "{\n" +
                    "    \"keys\": [\n" +
                    "        {\n" +
                    "        \"kty\": \"RSA\",\n" +
                    "        \"e\": \"AQAB\",\n" +
                    "        \"kid\": \"c9986ee3-7b2a-4d20-b86a-0839856f2541\",\n" +
                    "        \"n\": \"y3c3TEePZZPaxqNU2xV4ortsXrw1EXTNQj2QUgL8UOPaQS0lbHJtD1cbcCFnzfXRXTOGqh8l-XWTRIOlt4yU-mEhgR0_JKILTPwmS0fj3D1PT6IjZShuNyd4USVdcjfCRBRb9ExIptJyeTTUu0UujWNEcGOWAkUZcsonmiEz7bIMVkGy5uYnWGbsKP51Zf_PFMb96RcHeE0ZUitIB4YK1bgHLyAEBJIka5mRC_jWq_mlq3jiP5RaVWbzQiJbrjuYWd1Vps_xnrABx6_4Ft_M0AnSQN0SYjc_nWT1yGPpCwtWmWUU5NNHd-w6TdgOjdu00wownwblovtEYED-rncb913qfBM98kNHyj357BSzlvhiwEH5Ayo9DTnx1j9HuJGZXzymVypuQXLu_tkHMEt-c4kytKJNi6MLiauy9xtXGLXgOvZUM8V0Z27Z6CTfCzWZ0nwnEWDdH-NJyusL6pJgEGUBh6E9fdJInV7YOCF-P9_19imPHrZ0blTXK1TDfKS_pCLOXO_OmmH-p-UxQ77OpeP5wlt5Jem0ErSisl_Qxhh1OtJcLwFdA7uC7rOTMrSEGLO--5-CatsXj7BEK2l-3As8fJEkoWXd1-4KOUMfV_fnT_z6U8-bcsYn0nvWPl8XuMbwNWjqHYgqhl1RLA7M17HCydWCF50HI2XojtGgRN0\"\n" +
                    "        }\n" +
                    "    ]\n" +
                    "}";
            Files.write(jwksUri.toPath(), keyContents.getBytes());
        }
    }

    @Test
    public void testInitializeFailedHttpClient() throws IOException {

        File configUri = new File("./src/test/resources/azure-openid-nouri.json");
        System.setProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI, "file://" + configUri.getCanonicalPath());
        System.clearProperty(InstanceAzureProvider.AZURE_PROP_DNS_SUFFIX);

        SSLContext sslContext = Mockito.mock(SSLContext.class);
        InstanceAzureProvider provider = new InstanceAzureProvider();
        setUpExternalCredentialsProvider(provider);
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceAzureProvider", sslContext, null);

        assertNull(provider.httpDriver);

        // without http driver we can't fetch our vm details

        assertNull(provider.fetchVMDetails(null, null));
        provider.close();

        System.clearProperty(InstanceAzureProvider.AZURE_PROP_OPENID_CONFIG_URI);
    }

}
