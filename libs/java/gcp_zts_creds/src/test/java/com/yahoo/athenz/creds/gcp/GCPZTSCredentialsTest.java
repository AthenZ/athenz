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

import com.google.api.client.json.GenericJson;
import com.google.gson.Gson;
import com.google.gson.internal.LinkedTreeMap;
import com.oath.auth.KeyRefresher;
import com.oath.auth.KeyRefresherException;
import com.oath.auth.Utils;
import org.testng.annotations.*;

import javax.net.ssl.SSLContext;
import java.io.*;
import java.util.Collections;
import java.util.Objects;
import java.util.stream.Collectors;

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
    public void testBuilder() {
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
    public void testBuilderWithProxy() {

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
    public void testCreateTokenAPIStream() {
        GCPZTSCredentials.Builder builder = createBuilder();
        GCPZTSCredentials creds = builder.build();
        InputStream stream = creds.createTokenAPIStream();
        String confData = new BufferedReader(new InputStreamReader(stream))
                .lines().collect(Collectors.joining("\n"));
        GenericJson json = new Gson().fromJson(confData, GenericJson.class);
        assertNotNull(json);
        assertEquals(json.get("type"), "external_account");
        assertEquals(json.get("audience"), "//iam.googleapis.com/projects/project-number/locations/global/workloadIdentityPools/athenz/providers/athenz");
        assertEquals(json.get("subject_token_type"), "urn:ietf:params:oauth:token-type:jwt");
        assertEquals(json.get("token_url"), "https://sts.googleapis.com/v1/token");
        assertEquals(json.get("service_account_impersonation_url"), "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/admin-service@project-id.iam.gserviceaccount.com:generateAccessToken");
        LinkedTreeMap<String, Object> serviceAccountImpersonation = (LinkedTreeMap<String, Object>) json.get("service_account_impersonation");
        assertEquals(serviceAccountImpersonation.get("token_lifetime_seconds"), 3600.0);
        LinkedTreeMap<String, Object> credentialSource = (LinkedTreeMap<String, Object>) json.get("credential_source");
        assertTrue(credentialSource.get("url").toString().startsWith("https://localhost:4443/oauth2/auth?response_type=id_token&client_id=sports.gcp&redirect_uri=https%3A%2F%2Fgcp.sports.gcp.athenz.io&scope=openid+sports%3Arole.hockey&nonce="));
        LinkedTreeMap<String, Object> credentialSourceFormat = (LinkedTreeMap<String, Object>) credentialSource.get("format");
        assertEquals(credentialSourceFormat.get("type"), "json");
        assertEquals(credentialSourceFormat.get("subject_token_field_name"), "id_token");
    }

    @Test
    public void testGetTokenAPICredentials() throws KeyRefresherException, IOException, InterruptedException {
        testGetTokenAPICredentials(-1);
        testGetTokenAPICredentials(60000);
    }

    private void testGetTokenAPICredentials(int certRefreshTimeout) throws KeyRefresherException, IOException, InterruptedException {
        GCPZTSCredentials.Builder builder = createBuilder();
        builder.setCertRefreshTimeout(certRefreshTimeout);
        GCPZTSCredentials creds = builder.build();
        assertNotNull(creds.getTokenAPICredentials());
        creds.close();
    }

    @Test
    public void testGetTokenAPICredentialsInvalid() throws KeyRefresherException, IOException, InterruptedException {
        GCPZTSCredentials.Builder builder = createBuilder();
        builder.setCertRefreshTimeout(-1);
        builder.setTrustStorePath("/var/lib/sia/cacert");
        GCPZTSCredentials creds = builder.build();
        try {
            creds.getTokenAPICredentials();
            fail();
        } catch (FileNotFoundException ignored) {
        }
        creds.close();
    }

    @Test
    public void testAthenztHttpTransportFactory() throws KeyRefresherException, IOException, InterruptedException {

        KeyRefresher keyRefresher = Utils.generateKeyRefresher(
                Objects.requireNonNull(classLoader.getResource("truststore.jks")).getPath(),
                "123456".toCharArray(),
                Objects.requireNonNull(classLoader.getResource("ec_public_x509.cert")).getPath(),
                Objects.requireNonNull(classLoader.getResource("unit_test_ec_private.key")).getPath());
        SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                keyRefresher.getTrustManagerProxy());

        GCPZTSCredentials.AthenztHttpTransportFactory factory =
                new GCPZTSCredentials.AthenztHttpTransportFactory(sslContext, null);
        assertNotNull(factory);
        assertNotNull(factory.create());
        keyRefresher.shutdown();
    }
}
