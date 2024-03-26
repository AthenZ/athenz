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
package com.yahoo.athenz.creds.gcp;

import com.google.api.client.http.HttpTransport;
import com.oath.auth.KeyRefresher;
import com.oath.auth.KeyRefresherException;
import com.oath.auth.Utils;
import org.apache.http.*;
import org.apache.http.protocol.HttpContext;
import org.mockito.Mockito;
import org.testng.annotations.*;

import java.io.*;
import java.util.Collections;
import java.util.Objects;

import static org.testng.Assert.*;

public class GCPZTSCredentialsTest {

    ClassLoader classLoader = this.getClass().getClassLoader();

    private GCPZTSCredentials.Builder createBuilder() {

        return new GCPZTSCredentials.Builder()
                .setZtsUrl("https://localhost:4443")
                .setProjectId("project-id")
                .setProjectNumber("project-number")
                .setWorkloadPoolName("athenz")
                .setWorkloadProviderName("athenz")
                .setServiceAccountName("admin-service")
                .setCertFile(Objects.requireNonNull(classLoader.getResource("ec_public_x509.cert")).getPath())
                .setKeyFile(Objects.requireNonNull(classLoader.getResource("unit_test_ec_private.key")).getPath())
                .setTrustStorePath(Objects.requireNonNull(classLoader.getResource("truststore.jks")).getPath())
                .setTrustStorePassword("123456".toCharArray())
                .setCertRefreshTimeout(30000)
                .setDomainName("sports")
                .setRoleNames(Collections.singletonList("hockey"))
                .setClientId("sports.gcp")
                .setRedirectUriSuffix("gcp.athenz.io")
                .setTokenLifetimeSeconds(3600);
    }

    @Test
    public void testBuilder() throws KeyRefresherException, IOException, InterruptedException {
        GCPZTSCredentials.Builder builder = createBuilder();
        assertNotNull(builder.build());

        // GCP requires that field must be between 600 and 43200 seconds

        try {
            builder.setTokenLifetimeSeconds(599);
            fail();
        } catch (IllegalArgumentException ignored) {
        }

        try {
            builder.setTokenLifetimeSeconds(43201);
            fail();
        } catch (IllegalArgumentException ignored) {
        }

        builder.setTokenLifetimeSeconds(600);
        builder.setTokenLifetimeSeconds(43200);

        try {
            builder.setProxyPort(-5);
            fail();
        } catch (IllegalArgumentException ignored) {
        }

        try {
            builder.setProxyPort(65536);
            fail();
        } catch (IllegalArgumentException ignored) {
        }

        builder.setProxyPort(4443);
        builder.setProxyPort(0);
        builder.setProxyPort(65535);
    }

    @Test
    public void testBuilderWithProxy() throws KeyRefresherException, IOException, InterruptedException {

        // with null proxy host

        GCPZTSCredentials.Builder builder = createBuilder();
        builder.setProxyHost(null);
        builder.setProxyPort(4443);
        assertNotNull(builder.build());

        // with empty proxy host

        builder.setProxyHost("");
        builder.setProxyPort(4443);
        assertNotNull(builder.build());

        // with valid hostname

        builder.setProxyHost("athenz.io");
        builder.setProxyPort(4443);
        assertNotNull(builder.build());
    }

    @Test
    public void testBuilderWithSslContext() throws KeyRefresherException, IOException, InterruptedException {
        KeyRefresher keyRefresher = Utils.generateKeyRefresher(Objects.requireNonNull(classLoader.getResource("truststore.jks")).getPath(), "123456",
                Objects.requireNonNull(classLoader.getResource("ec_public_x509.cert")).getPath(),
                Objects.requireNonNull(classLoader.getResource("unit_test_ec_private.key")).getPath());
        GCPZTSCredentials.Builder builder = new GCPZTSCredentials.Builder()
                .setZtsUrl("https://localhost:4443")
                .setProjectId("project-id")
                .setProjectNumber("project-number")
                .setWorkloadPoolName("athenz")
                .setWorkloadProviderName("athenz")
                .setServiceAccountName("admin-service")
                .setDomainName("sports")
                .setRoleNames(Collections.singletonList("hockey"))
                .setClientId("sports.gcp")
                .setRedirectUriSuffix("gcp.athenz.io")
                .setTokenLifetimeSeconds(3600)
                .setSslContext(Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(), keyRefresher.getTrustManagerProxy()));
        assertNotNull(builder.build());
    }

    @Test
    public void testGetTokenAPICredentials() throws KeyRefresherException, IOException, InterruptedException {
        testGetTokenAPICredentials(-1, true);
        testGetTokenAPICredentials(-1, false);
        testGetTokenAPICredentials(60000, true);
        testGetTokenAPICredentials(60000, false);
    }

    private void testGetTokenAPICredentials(int certRefreshTimeout, boolean proxy) throws KeyRefresherException, IOException, InterruptedException {
        GCPZTSCredentials.Builder builder = createBuilder();
        builder.setCertRefreshTimeout(certRefreshTimeout);
        if (proxy) {
            builder = builder.setProxyHost("localhost")
                    .setProxyPort(4080)
                    .setProxyAuth("auth");
        }
        GCPZTSCredentials creds = builder.build();
        assertNotNull(creds.getTokenAPICredentials());
        creds.close();
    }

    @Test
    public void testGetTokenAPICredentialsInvalid() throws KeyRefresherException, IOException, InterruptedException {
        GCPZTSCredentials.Builder builder = createBuilder();
        builder.setCertRefreshTimeout(-1);
        builder.setTrustStorePath("/var/lib/sia/cacert");
        try {
            builder.build();
            fail();
        } catch (FileNotFoundException ignored) {
        }
    }

    @Test
    public void testAthenztHttpProxyTransportFactory() {

        HttpTransport httpTransport = Mockito.mock(HttpTransport.class);
        GCPZTSCredentials.AthenztHttpTransportFactory factory = new GCPZTSCredentials.AthenztHttpTransportFactory(httpTransport);
        assertNotNull(factory.create());
    }

    @Test
    public void testAthenzProxyHttpRequestExecutor() throws IOException, HttpException {
        GCPZTSCredentials.AthenzProxyHttpRequestExecutor executor =
                new GCPZTSCredentials.AthenzProxyHttpRequestExecutor("auth");
        HttpRequest request = Mockito.mock(HttpRequest.class);
        RequestLine requestLine = Mockito.mock(RequestLine.class);
        Mockito.when(request.getRequestLine()).thenReturn(requestLine);
        Mockito.when(requestLine.getMethod()).thenReturn("CONNECT");
        HttpClientConnection conn = Mockito.mock(HttpClientConnection.class);
        HttpContext context = Mockito.mock(HttpContext.class);
        HttpResponse response = Mockito.mock(HttpResponse.class);
        Mockito.when(conn.receiveResponseHeader()).thenReturn(response);
        StatusLine statusLine = Mockito.mock(StatusLine.class);
        Mockito.when(response.getStatusLine()).thenReturn(statusLine);
        Mockito.when(statusLine.getStatusCode()).thenReturn(204);
        executor.execute(request, conn, context);
    }
}
