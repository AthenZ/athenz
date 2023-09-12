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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oath.auth.KeyRefresherException;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.http.HttpDriver;
import com.yahoo.athenz.common.server.http.HttpDriverResponse;
import com.yahoo.athenz.zms.ZMSConsts;
import org.apache.http.ProtocolVersion;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicStatusLine;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

import static com.yahoo.athenz.zms.ZMSConsts.*;
import static com.yahoo.athenz.zms.ZMSConsts.ZMS_PROP_PROVIDER_TRUST_STORE_PASSWORD;
import static org.mockito.ArgumentMatchers.any;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNull;

public class ServiceProviderClientTest {

    private final ObjectMapper jsonMapper = new ObjectMapper();

    @Test
    public void testServiceProviderClient() throws IOException {
        serviceProviderClientWithInstance(false);
    }

    @Test
    public void testServiceProviderClientInstanceProvider() throws IOException {
        serviceProviderClientWithInstance(true);
    }

    private void serviceProviderClientWithInstance(boolean isInstanceProvider) throws IOException {
        String provider = "provider-test";
        String providerEndpoint = "https://provider-endpoint:12345";
        ServiceProviderManager.DomainDependencyProvider domainDependencyProvider = new ServiceProviderManager.DomainDependencyProvider(provider, providerEndpoint, isInstanceProvider);
        String domain = "test.domain";
        String principal = "user.someone";
        DomainDependencyProviderResponse domainDependencyProviderResponse = new DomainDependencyProviderResponse();
        domainDependencyProviderResponse.setStatus("allow");
        String responseBody = jsonMapper.writeValueAsString(domainDependencyProviderResponse);
        StatusLine statusLine = new BasicStatusLine(new ProtocolVersion("https", 1, 1), 200, "success");
        HttpDriverResponse response = new HttpDriverResponse(200, responseBody, statusLine);

        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);
        Mockito.when(httpDriver.doPostHttpResponse(any())).thenReturn(response);
        ArgumentCaptor<HttpPost> httpPostArgumentCaptor = ArgumentCaptor.forClass(HttpPost.class);

        ServiceProviderClient serviceProviderClient = new ServiceProviderClient(httpDriver, "home.");
        DomainDependencyProviderResponse dependencyStatus = serviceProviderClient.getDependencyStatus(domainDependencyProvider, domain, principal);
        assertEquals(dependencyStatus.getStatus(), ZMSConsts.PROVIDER_RESPONSE_ALLOW);
        assertNull(dependencyStatus.getMessage());

        Mockito.verify(httpDriver, Mockito.times(1)).doPostHttpResponse(httpPostArgumentCaptor.capture());
        assertEquals(httpPostArgumentCaptor.getAllValues().size(), 1);
        HttpPost httpPost = httpPostArgumentCaptor.getValue();
        assertEquals(httpPost.getMethod(), "POST");
        String expectedUri = isInstanceProvider ? "https://provider-endpoint:12345/dependency-check" : "https://provider-endpoint:12345";
        assertEquals(httpPost.getURI().toString(), expectedUri);
        InputStream inputStream = httpPost.getEntity().getContent();
        String text = new BufferedReader(
                new InputStreamReader(inputStream, StandardCharsets.UTF_8))
                .lines()
                .collect(Collectors.joining("\n"));
        assertEquals(text,
                "{" +
                "\"operation\":\"delete\"," +
                "\"domainName\":\"test.domain\"," +
                "\"objectType\":\"domain\"," +
                "\"objectName\":\"test.domain\"," +
                "\"principal\":\"user.someone\"," +
                "\"provider\":\"provider-test\"}");
    }

    @Test
    public void testServiceProviderClientHomeDomain() {
        String provider = "provider-test";
        String providerEndpoint = "https://provider-endpoint:12345";
        ServiceProviderManager.DomainDependencyProvider domainDependencyProvider = new ServiceProviderManager.DomainDependencyProvider(provider, providerEndpoint, false);
        String domain = "home.domain";
        String principal = "user.someone";
        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);
        ServiceProviderClient serviceProviderClient = new ServiceProviderClient(httpDriver, "home.");
        DomainDependencyProviderResponse dependencyStatus = serviceProviderClient.getDependencyStatus(domainDependencyProvider, domain, principal);
        assertEquals(dependencyStatus.getStatus(), ZMSConsts.PROVIDER_RESPONSE_ALLOW);
        assertEquals(dependencyStatus.getMessage(), "Dependency on home domain home.domain is invalid");
    }

    @Test
    public void testServiceProviderClientNoEndpoint() {
        String provider = "provider-test";
        ServiceProviderManager.DomainDependencyProvider domainDependencyProvider = new ServiceProviderManager.DomainDependencyProvider(provider, null, false);
        String domain = "test.domain";
        String principal = "user.someone";
        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);
        ServiceProviderClient serviceProviderClient = new ServiceProviderClient(httpDriver, "home.");
        DomainDependencyProviderResponse dependencyStatus = serviceProviderClient.getDependencyStatus(domainDependencyProvider, domain, principal);
        assertEquals(dependencyStatus.getStatus(), ZMSConsts.PROVIDER_RESPONSE_DENY);
        assertEquals(dependencyStatus.getMessage(), "No provider endpoint is listed. Please contact an administrator");
    }

    @Test
    public void testServiceProviderClientException() throws IOException {
        String provider = "provider-test";
        String providerEndpoint = "https://provider-endpoint:12345";
        ServiceProviderManager.DomainDependencyProvider domainDependencyProvider = new ServiceProviderManager.DomainDependencyProvider(provider, providerEndpoint, false);
        String domain = "test.domain";
        String principal = "user.someone";
        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);
        Mockito.when(httpDriver.doPostHttpResponse(any())).thenThrow(new IOException("test exception"));
        ServiceProviderClient serviceProviderClient = new ServiceProviderClient(httpDriver, "home.");
        DomainDependencyProviderResponse dependencyStatus = serviceProviderClient.getDependencyStatus(domainDependencyProvider, domain, principal);
        assertEquals(dependencyStatus.getStatus(), ZMSConsts.PROVIDER_RESPONSE_DENY);
        assertEquals(dependencyStatus.getMessage(), "Exception thrown during call to provider: test exception");
    }

    @Test
    public void testServiceProviderClientError404() throws IOException {
        String provider = "test.domain.provider-test";
        String providerEndpoint = "https://provider-endpoint:12345";
        String domain = "test.domain";
        String principal = "user.someone";
        String responseBody = jsonMapper.writeValueAsString("server error");
        StatusLine statusLine = new BasicStatusLine(new ProtocolVersion("https", 1, 1), 404, "server error");
        HttpDriverResponse response = new HttpDriverResponse(404, responseBody, statusLine);

        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);
        Mockito.when(httpDriver.doPostHttpResponse(any())).thenReturn(response);

        ServiceProviderClient serviceProviderClient = new ServiceProviderClient(httpDriver, "home.");
        ServiceProviderManager.DomainDependencyProvider domainDependencyProvider = new ServiceProviderManager.DomainDependencyProvider(provider, providerEndpoint, false);
        DomainDependencyProviderResponse dependencyStatus = serviceProviderClient.getDependencyStatus(domainDependencyProvider, domain, principal);
        assertEquals(dependencyStatus.getStatus(), ZMSConsts.PROVIDER_RESPONSE_DENY);
        assertEquals(dependencyStatus.getMessage(), "Invalid dependency status request to service provider 'test.domain.provider-test' with endpoint 'https://provider-endpoint:12345', Received error code 404");
    }

    @Test
    public void testServiceProviderClientError500() throws IOException {
        String provider = "provider-test";
        String providerEndpoint = "https://provider-endpoint:12345";
        ServiceProviderManager.DomainDependencyProvider domainDependencyProvider = new ServiceProviderManager.DomainDependencyProvider(provider, providerEndpoint, false);
        String domain = "test.domain";
        String principal = "user.someone";
        String responseBody = jsonMapper.writeValueAsString("server error");
        StatusLine statusLine = new BasicStatusLine(new ProtocolVersion("https", 1, 1), 500, "server error");
        HttpDriverResponse response = new HttpDriverResponse(500, responseBody, statusLine);

        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);
        Mockito.when(httpDriver.doPostHttpResponse(any())).thenReturn(response);

        ServiceProviderClient serviceProviderClient = new ServiceProviderClient(httpDriver, "home.");
        DomainDependencyProviderResponse dependencyStatus = serviceProviderClient.getDependencyStatus(domainDependencyProvider, domain, principal);
        assertEquals(dependencyStatus.getStatus(), ZMSConsts.PROVIDER_RESPONSE_DENY);
        assertEquals(dependencyStatus.getMessage(), "Http Status: 500, error: \"server error\"");
    }

    @Test
    public void testServiceProviderClientDisabled() throws KeyRefresherException, IOException, InterruptedException {
        System.clearProperty(ZMS_PROP_PROVIDER_KEY_PATH);
        System.clearProperty(ZMS_PROP_PROVIDER_CERT_PATH);
        System.clearProperty(ZMS_PROP_PROVIDER_TRUST_STORE);
        System.clearProperty(ZMS_PROP_PROVIDER_TRUST_STORE_PASSWORD);
        PrivateKeyStore privateKeyStore = Mockito.mock(PrivateKeyStore.class);
        ServiceProviderClient serviceProviderClient = new ServiceProviderClient(privateKeyStore, "home.");
        String provider = "provider-test";
        String providerEndpoint = "https://provider-endpoint:12345";
        ServiceProviderManager.DomainDependencyProvider domainDependencyProvider = new ServiceProviderManager.DomainDependencyProvider(provider, providerEndpoint, false);
        String domain = "test.domain";
        String principal = "user.someone";
        DomainDependencyProviderResponse dependencyStatus = serviceProviderClient.getDependencyStatus(domainDependencyProvider, domain, principal);
        assertEquals(dependencyStatus.getStatus(), ZMSConsts.PROVIDER_RESPONSE_ALLOW);
        assertEquals(dependencyStatus.getMessage(), "ServiceProviderClient is disabled");
    }
}
