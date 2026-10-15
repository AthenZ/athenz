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

package io.athenz.server.aws.common.creds.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.zts.AWSTemporaryCredentials;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.http.ExecutableHttpRequest;
import software.amazon.awssdk.http.HttpExecuteRequest;
import software.amazon.awssdk.http.HttpExecuteResponse;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.StsClientBuilder;
import software.amazon.rolesanywhere.plugin.RolesAnywhereCredentialsProvider;
import software.amazon.rolesanywhere.plugin.X509Identity;
import software.amazon.rolesanywhere.plugin.X509IdentityProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import static io.athenz.server.aws.common.creds.impl.RolesAnywhereCredentialsProviderFactory.*;
import static org.testng.Assert.*;

public class RolesAnywhereCredentialsProviderFactoryTest {

    private final Map<String, String> originalProperties = new HashMap<>();

    private static final char[] STORE_PASSWORD = "store-password".toCharArray();

    private static final String[] ALL_PROPS = {
            PROP_CERT_PATH, PROP_KEY_PATH, PROP_CHAIN_PATH, PROP_KEY_ALGORITHM,
            PROP_TRUST_ANCHOR_ARN, PROP_PROFILE_ARN, PROP_ROLE_ARN, PROP_REGION,
            PROP_KEYSTORE_PATH, PROP_KEYSTORE_TYPE, PROP_KEYSTORE_PASSWORD,
            PROP_KEYSTORE_PASSWORD_APPNAME, PROP_KEYSTORE_PASSWORD_KEYGROUPNAME, PROP_KEYSTORE_ALIAS,
            ZTS_PROP_AWS_REGION_NAME, TempCredsProvider.ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS,
            ATHENZ_PROP_KEYSTORE_PATH, ATHENZ_PROP_KEYSTORE_TYPE, ATHENZ_PROP_KEYSTORE_PASSWORD,
            ATHENZ_PROP_KEYSTORE_PASSWORD_APPNAME, ATHENZ_PROP_KEYSTORE_PASSWORD_KEYGROUPNAME
    };

    private void setValidProperties() {
        System.setProperty(PROP_CERT_PATH, "/nonexistent/zts_cert.pem");
        System.setProperty(PROP_KEY_PATH, "/nonexistent/zts_key.pem");
        System.setProperty(PROP_TRUST_ANCHOR_ARN,
                "arn:aws:rolesanywhere:ap-northeast-1:123456789012:trust-anchor/ta-id");
        System.setProperty(PROP_PROFILE_ARN,
                "arn:aws:rolesanywhere:ap-northeast-1:123456789012:profile/profile-id");
        System.setProperty(PROP_ROLE_ARN, "arn:aws:iam::123456789012:role/athenz-zts");
        System.setProperty(PROP_REGION, "ap-northeast-1");
    }

    @BeforeMethod
    public void saveProperties() {
        for (String prop : ALL_PROPS) {
            originalProperties.put(prop, System.getProperty(prop));
        }
        clearProperties();
    }

    private void clearProperties() {
        for (String prop : ALL_PROPS) {
            System.clearProperty(prop);
        }
    }

    @AfterMethod
    public void restoreProperties() {
        originalProperties.forEach((prop, value) -> {
            if (value == null) {
                System.clearProperty(prop);
            } else {
                System.setProperty(prop, value);
            }
        });
        originalProperties.clear();
    }

    // Check the configuration exposed by the real provider.
    @Test
    public void testCreateWiresPropertiesToProvider() throws ServerResourceException {
        setValidProperties();
        try (RolesAnywhereCredentialsProvider credentialsProvider =
                (RolesAnywhereCredentialsProvider) new RolesAnywhereCredentialsProviderFactory().create()) {
            final String provider = credentialsProvider.toString();
            assertTrue(provider.contains("region=ap-northeast-1"), provider);
            assertTrue(provider.contains("roleArn=arn:aws:iam::123456789012:role/athenz-zts"), provider);
            assertTrue(provider.contains(
                    "profileArn=arn:aws:rolesanywhere:ap-northeast-1:123456789012:profile/profile-id"), provider);
            assertTrue(provider.contains(
                    "trustAnchorArn=arn:aws:rolesanywhere:ap-northeast-1:123456789012:trust-anchor/ta-id"), provider);
        }
    }

    @Test
    public void testDefaultFactoryDoesNotRequireRolesAnywhereSettings() throws ServerResourceException {
        String originalFactory = System.getProperty(TempCredsProvider.ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS);
        System.clearProperty(TempCredsProvider.ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS);
        TempCredsProvider provider = new TempCredsProvider();
        try {
            provider.initialize();
            assertTrue(provider.credentialsProvider instanceof InstanceProfileCredentialsProvider);
        } finally {
            provider.close();
            if (originalFactory != null) {
                System.setProperty(TempCredsProvider.ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS, originalFactory);
            }
        }
    }

    @Test
    public void testRolesAnywhereFactoryIsSelectedExplicitly() throws ServerResourceException {
        setValidProperties();
        String property = TempCredsProvider.ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS;
        String originalFactory = System.getProperty(property);
        System.setProperty(property, RolesAnywhereCredentialsProviderFactory.class.getName());
        TempCredsProvider provider = new TempCredsProvider();
        try {
            provider.initialize();
            assertTrue(provider.credentialsProvider instanceof RolesAnywhereCredentialsProvider);
        } finally {
            provider.close();
            if (originalFactory == null) {
                System.clearProperty(property);
            } else {
                System.setProperty(property, originalFactory);
            }
        }
    }

    @DataProvider
    public Object[][] pemChainPaths() {
        return new Object[][] { {null}, {""}, {"/nonexistent/zts_chain.pem"} };
    }

    @Test(dataProvider = "pemChainPaths")
    public void testResolveCredentialsAndCacheWithRolesAnywhere(String chainPath) throws Exception {
        setValidProperties();
        if (chainPath != null) {
            System.setProperty(PROP_CHAIN_PATH, chainPath);
        }
        boolean hasChain = chainPath != null && !chainPath.isEmpty();
        KeyStore keyStore = keyStoreWithChain("zts");
        Certificate[] chain = keyStore.getCertificateChain("zts");
        String expectedLeaf = Base64.getEncoder().encodeToString(chain[0].getEncoded());
        String expectedChain = Base64.getEncoder().encodeToString(chain[1].getEncoded());
        RolesAnywhereCredentialsProviderFactory factory = new RolesAnywhereCredentialsProviderFactory();
        SdkHttpClient httpClient = mock(SdkHttpClient.class);
        ExecutableHttpRequest request = mock(ExecutableHttpRequest.class);
        String response = "{\"credentialSet\":[{\"credentials\":{"
                + "\"accessKeyId\":\"test-access-key\",\"secretAccessKey\":\"test-secret-key\","
                + "\"sessionToken\":\"test-session-token\",\"expiration\":\""
                + Instant.now().plusSeconds(3600) + "\"}}]}";
        when(request.call()).thenReturn(HttpExecuteResponse.builder()
                .response(SdkHttpResponse.builder().statusCode(201).build())
                .responseBody(AbortableInputStream.create(new ByteArrayInputStream(
                        response.getBytes(StandardCharsets.UTF_8)))).build());
        when(httpClient.prepareRequest(any(HttpExecuteRequest.class))).thenAnswer(invocation -> {
            HttpExecuteRequest execution = invocation.getArgument(0);
            assertEquals(execution.httpRequest().encodedPath(), "/sessions");
            assertEquals(execution.httpRequest().host(), "rolesanywhere.ap-northeast-1.amazonaws.com");
            String authorization = execution.httpRequest().firstMatchingHeader("Authorization").orElse("");
            assertTrue(authorization.startsWith("AWS4-X509-RSA-SHA256"));
            assertTrue(expectedLeaf.equals(execution.httpRequest().firstMatchingHeader("X-Amz-X509").orElse("")),
                    "The leaf certificate must be sent in X-Amz-X509");
            if (hasChain) {
                assertTrue(expectedChain.equals(
                        execution.httpRequest().firstMatchingHeader("X-Amz-X509-Chain").orElse("")),
                        "X-Amz-X509-Chain must contain the configured intermediate certificate");
                assertTrue(authorization.contains("x-amz-x509-chain"), "The chain header must be signed");
            } else {
                assertFalse(execution.httpRequest().firstMatchingHeader("X-Amz-X509-Chain").isPresent());
                assertFalse(authorization.contains("x-amz-x509-chain"));
            }
            try (var body = execution.contentStreamProvider().orElseThrow().newStream()) {
                String json = new String(body.readAllBytes(), StandardCharsets.UTF_8);
                assertTrue(json.contains(System.getProperty(PROP_TRUST_ANCHOR_ARN)));
                assertTrue(json.contains(System.getProperty(PROP_PROFILE_ARN)));
                assertTrue(json.contains(System.getProperty(PROP_ROLE_ARN)));
            }
            return request;
        });
        RolesAnywhereCredentialsProvider.Builder builder = RolesAnywhereCredentialsProvider.builder()
                .httpClient(httpClient);
        // Replace file I/O and HTTP transport; keep PEM parsing and signing real.
        try (MockedStatic<Files> files = mockStatic(Files.class);
                MockedStatic<RolesAnywhereCredentialsProvider> providerClass =
                Mockito.mockStatic(RolesAnywhereCredentialsProvider.class)) {
            stubPemFiles(files, keyStore);
            providerClass.when(RolesAnywhereCredentialsProvider::builder).thenReturn(builder);
            try (RolesAnywhereCredentialsProvider provider = (RolesAnywhereCredentialsProvider) factory.create()) {
                AwsSessionCredentials credentials = (AwsSessionCredentials) provider.resolveCredentials();
                assertEquals(credentials.accessKeyId(), "test-access-key");
                assertEquals(credentials.secretAccessKey(), "test-secret-key");
                assertEquals(credentials.sessionToken(), "test-session-token");
                assertSame(provider.resolveCredentials(), credentials);
                verify(httpClient, times(1)).prepareRequest(any(HttpExecuteRequest.class));
                files.verify(() -> Files.newInputStream(Paths.get("/nonexistent/zts_chain.pem")),
                        times(hasChain ? 1 : 0));
            }
        }
    }

    @DataProvider
    public Object[][] invalidPemChains() {
        return new Object[][] { {true}, {false} };
    }

    @Test(dataProvider = "invalidPemChains")
    public void testPemIdentityRejectsUnreadableOrInvalidChain(boolean missingFile) throws Exception {
        setValidProperties();
        System.setProperty(PROP_CHAIN_PATH, "/nonexistent/zts_chain.pem");
        KeyStore keyStore = keyStoreWithChain("zts");
        X509IdentityProvider identityProvider = new RolesAnywhereCredentialsProviderFactory().identityProvider();
        try (MockedStatic<Files> files = mockStatic(Files.class)) {
            stubPemFiles(files, keyStore);
            if (missingFile) {
                files.when(() -> Files.newInputStream(Paths.get("/nonexistent/zts_chain.pem")))
                        .thenThrow(new IOException("chain file is unavailable"));
            } else {
                files.when(() -> Files.newInputStream(Paths.get("/nonexistent/zts_chain.pem")))
                        .thenReturn(new ByteArrayInputStream("invalid certificate".getBytes(StandardCharsets.UTF_8)));
            }
            try {
                identityProvider.resolve();
                fail("An invalid configured chain must not be ignored");
            } catch (SdkClientException ex) {
                assertTrue(missingFile ? ex.getCause() instanceof IOException
                        : ex.getCause() instanceof CertificateException);
            }
            files.verify(() -> Files.newInputStream(Paths.get("/nonexistent/zts_chain.pem")));
        }
    }

    private void stubPemFiles(MockedStatic<Files> files, KeyStore keyStore) throws Exception {
        // JAR resource loading still needs real file metadata.
        files.when(() -> Files.readAttributes(any(Path.class), eq(BasicFileAttributes.class)))
                .thenCallRealMethod();
        Certificate[] chain = keyStore.getCertificateChain("zts");
        byte[] certificate = pemBytes("CERTIFICATE", chain[0].getEncoded());
        byte[] key = pemBytes("PRIVATE KEY", keyStore.getKey("zts", STORE_PASSWORD).getEncoded());
        byte[] intermediates = pemBytes("CERTIFICATE", chain[1].getEncoded());
        files.when(() -> Files.readAllBytes(Paths.get("/nonexistent/zts_cert.pem"))).thenReturn(certificate);
        files.when(() -> Files.readAllBytes(Paths.get("/nonexistent/zts_key.pem"))).thenReturn(key);
        files.when(() -> Files.getPosixFilePermissions(Paths.get("/nonexistent/zts_key.pem")))
                .thenReturn(Collections.singleton(PosixFilePermission.OWNER_READ));
        files.when(() -> Files.newInputStream(Paths.get("/nonexistent/zts_chain.pem")))
                .thenAnswer(invocation -> new ByteArrayInputStream(intermediates));
    }

    private byte[] pemBytes(String label, byte[] encoded) {
        String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(encoded);
        return ("-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n")
                .getBytes(StandardCharsets.UTF_8);
    }

    @Test
    public void testRolesAnywhereCredentialsSignStsRequest() throws Exception {
        setValidProperties();
        System.setProperty(ZTS_PROP_AWS_REGION_NAME, "us-west-2");
        System.setProperty(TempCredsProvider.ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS,
                RolesAnywhereCredentialsProviderFactory.class.getName());
        X509Identity identity = identityFromKeyStore(keyStoreWithChain("zts"), "zts", STORE_PASSWORD);
        SdkHttpClient rolesAnywhereHttp = mock(SdkHttpClient.class);
        ExecutableHttpRequest sessionRequest = mock(ExecutableHttpRequest.class);
        when(rolesAnywhereHttp.prepareRequest(any(HttpExecuteRequest.class))).thenAnswer(invocation -> {
            HttpExecuteRequest execution = invocation.getArgument(0);
            assertEquals(execution.httpRequest().host(), "rolesanywhere.ap-northeast-1.amazonaws.com");
            assertEquals(execution.httpRequest().encodedPath(), "/sessions");
            assertTrue(execution.httpRequest().firstMatchingHeader("Authorization").orElse("")
                    .startsWith("AWS4-X509-RSA-SHA256"));
            return sessionRequest;
        });
        when(sessionRequest.call()).thenReturn(httpResponse(201,
                "{\"credentialSet\":[{\"credentials\":{\"accessKeyId\":\"test-source-access\","
                        + "\"secretAccessKey\":\"test-source-secret\",\"sessionToken\":\"test-source-session\","
                        + "\"expiration\":\"" + Instant.now().plusSeconds(3600) + "\"}}]}"));

        SdkHttpClient stsHttp = mock(SdkHttpClient.class);
        ExecutableHttpRequest assumeRoleRequest = mock(ExecutableHttpRequest.class);
        when(stsHttp.prepareRequest(any(HttpExecuteRequest.class))).thenAnswer(invocation -> {
            HttpExecuteRequest execution = invocation.getArgument(0);
            assertEquals(execution.httpRequest().host(), "sts.us-west-2.amazonaws.com");
            assertTrue(execution.httpRequest().firstMatchingHeader("Authorization").orElse("")
                    .contains("Credential=test-source-access/"));
            assertEquals(execution.httpRequest().firstMatchingHeader("X-Amz-Security-Token").orElse(""),
                    "test-source-session");
            try (var body = execution.contentStreamProvider().orElseThrow().newStream()) {
                String form = URLDecoder.decode(new String(body.readAllBytes(), StandardCharsets.UTF_8),
                        StandardCharsets.UTF_8);
                assertTrue(form.contains("Action=AssumeRole"));
                assertTrue(form.contains("RoleArn=arn:aws:iam::123456789012:role/target-role"));
                assertTrue(form.contains("DurationSeconds=900"));
            }
            return assumeRoleRequest;
        });
        Instant expiration = Instant.now().plusSeconds(900);
        when(assumeRoleRequest.call()).thenReturn(httpResponse(200,
                "<AssumeRoleResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">"
                        + "<AssumeRoleResult><Credentials><AccessKeyId>test-target-access</AccessKeyId>"
                        + "<SecretAccessKey>test-target-secret</SecretAccessKey>"
                        + "<SessionToken>test-target-session</SessionToken><Expiration>" + expiration
                        + "</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>"));

        RolesAnywhereCredentialsProvider.Builder providerBuilder = RolesAnywhereCredentialsProvider.builder()
                .httpClient(rolesAnywhereHttp);
        StsClientBuilder stsBuilder = spy(StsClient.builder().httpClient(stsHttp));
        AtomicReference<StsClient> stsClient = new AtomicReference<>();
        doAnswer(invocation -> {
            StsClient client = (StsClient) invocation.callRealMethod();
            stsClient.set(client);
            return client;
        }).when(stsBuilder).build();

        TempCredsProvider provider = new TempCredsProvider();
        // Keep configuration, factory creation, both signers and response parsing real.
        try (MockedStatic<X509IdentityProvider> identities = mockStatic(X509IdentityProvider.class);
                MockedStatic<RolesAnywhereCredentialsProvider> providers =
                        mockStatic(RolesAnywhereCredentialsProvider.class);
                MockedStatic<StsClient> clients = mockStatic(StsClient.class)) {
            identities.when(() -> X509IdentityProvider.fromFiles(Paths.get("/nonexistent/zts_cert.pem"),
                    Paths.get("/nonexistent/zts_key.pem"), "RSA"))
                    .thenReturn((X509IdentityProvider) () -> identity);
            providers.when(RolesAnywhereCredentialsProvider::builder).thenReturn(providerBuilder);
            clients.when(StsClient::builder).thenReturn(stsBuilder);
            provider.initialize();
            StringBuilder error = new StringBuilder();
            AWSTemporaryCredentials result = provider.getTemporaryCredentials(
                    "123456789012", "target-role", "test.service", 900, null, error);
            assertEquals(result.getAccessKeyId(), "test-target-access");
            assertEquals(result.getSecretAccessKey(), "test-target-secret");
            assertEquals(result.getSessionToken(), "test-target-session");
            assertEquals(result.getExpiration().millis(), expiration.toEpochMilli());
            assertEquals(error.length(), 0);
            verify(rolesAnywhereHttp).prepareRequest(any(HttpExecuteRequest.class));
            verify(stsHttp).prepareRequest(any(HttpExecuteRequest.class));
        } finally {
            if (stsClient.get() != null) {
                stsClient.get().close();
            }
            provider.close();
        }
    }

    private HttpExecuteResponse httpResponse(int statusCode, String body) {
        return HttpExecuteResponse.builder()
                .response(SdkHttpResponse.builder().statusCode(statusCode).build())
                .responseBody(AbortableInputStream.create(new ByteArrayInputStream(
                        body.getBytes(StandardCharsets.UTF_8)))).build();
    }

    @Test
    public void testRegionFallsBackToAwsRegionName() throws ServerResourceException {
        setValidProperties();
        System.clearProperty(PROP_REGION);
        System.setProperty(ZTS_PROP_AWS_REGION_NAME, "us-west-2");
        assertEquals(new RolesAnywhereCredentialsProviderFactory().regionName(), "us-west-2");
    }

    @Test
    public void testRegionFailsWhenNeitherPropertyIsSet() {
        setValidProperties();
        System.clearProperty(PROP_REGION);
        try {
            new RolesAnywhereCredentialsProviderFactory().regionName();
            fail("expected failure when no region is configured");
        } catch (ServerResourceException ex) {
            assertTrue(ex.getMessage().contains(PROP_REGION), ex.getMessage());
            assertTrue(ex.getMessage().contains(ZTS_PROP_AWS_REGION_NAME), ex.getMessage());
        }
    }

    @Test
    public void testCreateFailsWhenRequiredPropertyMissing() {
        final String[] required = { PROP_TRUST_ANCHOR_ARN, PROP_PROFILE_ARN, PROP_ROLE_ARN };
        for (String missing : required) {
            setValidProperties();
            System.clearProperty(missing);
            try {
                new RolesAnywhereCredentialsProviderFactory().create();
                fail("expected failure when " + missing + " is not set");
            } catch (ServerResourceException ex) {
                assertEquals(ex.getCode(), ServerResourceException.INTERNAL_SERVER_ERROR);
                assertTrue(ex.getMessage().contains(missing), ex.getMessage());
            }
            clearProperties();
        }
    }

    @Test
    public void testRequiredPropertyRejectsEmptyValue() {
        System.setProperty(PROP_ROLE_ARN, "");
        try {
            requiredProperty(PROP_ROLE_ARN);
            fail("expected failure for empty value");
        } catch (ServerResourceException ex) {
            assertTrue(ex.getMessage().contains(PROP_ROLE_ARN), ex.getMessage());
        }
    }

    @Test
    public void testIdentityProviderFailsWhenNoIdentityConfigured() {
        setValidProperties();
        System.clearProperty(PROP_CERT_PATH);
        try {
            new RolesAnywhereCredentialsProviderFactory().identityProvider();
            fail("expected failure when neither cert_path nor a key store is configured");
        } catch (ServerResourceException ex) {
            assertTrue(ex.getMessage().contains(PROP_CERT_PATH), ex.getMessage());
            assertTrue(ex.getMessage().contains(PROP_KEYSTORE_PATH), ex.getMessage());
        }
    }

    @Test
    public void testIdentityProviderRequiresKeyPathWithCertPath() {
        setValidProperties();
        System.clearProperty(PROP_KEY_PATH);
        try {
            new RolesAnywhereCredentialsProviderFactory().identityProvider();
            fail("expected failure when cert_path is set without key_path");
        } catch (ServerResourceException ex) {
            assertTrue(ex.getMessage().contains(PROP_KEY_PATH), ex.getMessage());
        }
    }

    // Use a missing file to verify path selection without reading credentials.
    @Test
    public void testKeyStoreIdentityProviderReadsConfiguredPath() throws ServerResourceException {
        setValidProperties();
        System.clearProperty(PROP_CERT_PATH);
        System.setProperty(PROP_KEYSTORE_PATH, "/nonexistent/zts_keystore.p12");
        try {
            new RolesAnywhereCredentialsProviderFactory().identityProvider().resolve();
            fail("expected failure when the key store file does not exist");
        } catch (SdkClientException ex) {
            assertTrue(ex.getMessage().contains("/nonexistent/zts_keystore.p12"), ex.getMessage());
        }
    }

    @Test
    public void testKeyStorePathFallsBackToServerSetting() throws ServerResourceException {
        setValidProperties();
        System.clearProperty(PROP_CERT_PATH);
        System.setProperty(ATHENZ_PROP_KEYSTORE_PATH, "/nonexistent/from_ssl_key_store.p12");
        try {
            new RolesAnywhereCredentialsProviderFactory().identityProvider().resolve();
            fail("expected failure when the key store file does not exist");
        } catch (SdkClientException ex) {
            assertTrue(ex.getMessage().contains("/nonexistent/from_ssl_key_store.p12"), ex.getMessage());
        }
    }

    // An explicit PEM identity takes precedence over the key store.
    @Test
    public void testPemIdentityProviderReadsConfiguredPath() throws ServerResourceException {
        setValidProperties();
        System.setProperty(PROP_CERT_PATH, "/nonexistent/zts_cert.pem");
        System.setProperty(PROP_KEYSTORE_PATH, "/nonexistent/zts_keystore.p12");
        try {
            new RolesAnywhereCredentialsProviderFactory().identityProvider().resolve();
            fail("expected failure when the certificate file does not exist");
        } catch (RuntimeException ex) {
            assertTrue(ex.getMessage().contains("/nonexistent/zts_cert.pem"), ex.getMessage());
            assertFalse(ex.getMessage().contains("zts_keystore.p12"), ex.getMessage());
        }
    }

    @Test
    public void testIdentityFromKeyStorePicksLeafAndChain() throws Exception {
        KeyStore keyStore = keyStoreWithChain("zts");
        X509Identity identity = identityFromKeyStore(keyStore, null, STORE_PASSWORD);

        assertEquals(identity.certificate().getSubjectX500Principal().getName(),
                "CN=zts.example.com");
        assertNotNull(identity.privateKey());
        assertEquals(identity.certificateChain().size(), 1);
        assertEquals(identity.certificateChain().get(0).getSubjectX500Principal().getName(),
                "CN=athenz.intermediate.ca");
    }

    @Test
    public void testIdentityFromKeyStoreUsesConfiguredAlias() throws Exception {
        KeyStore keyStore = keyStoreWithChain("first");
        addKeyEntry(keyStore, "second", "CN=second.example.com");
        X509Identity identity = identityFromKeyStore(keyStore, "second", STORE_PASSWORD);
        assertEquals(identity.certificate().getSubjectX500Principal().getName(),
                "CN=second.example.com");
    }

    @Test
    public void testIdentityFromKeyStoreRejectsStoreWithoutKeyEntry() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, STORE_PASSWORD);
        try {
            identityFromKeyStore(keyStore, null, STORE_PASSWORD);
            fail("expected failure for a key store with no private key entry");
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("no private key entry"), ex.getMessage());
        }
    }

    @Test
    public void testIdentityFromKeyStoreRejectsUnknownAlias() throws Exception {
        KeyStore keyStore = keyStoreWithChain("zts");
        try {
            identityFromKeyStore(keyStore, "missing", STORE_PASSWORD);
            fail("expected failure for an alias that is not in the key store");
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("missing"), ex.getMessage());
        }
    }

    @Test
    public void testKeyStorePasswordFallsBackToServerSetting() {
        System.setProperty(ATHENZ_PROP_KEYSTORE_PASSWORD, "test-key-store-password");
        RolesAnywhereCredentialsProviderFactory factory = new RolesAnywhereCredentialsProviderFactory();
        assertEquals(new String(factory.keyStorePassword()), "test-key-store-password");
    }

    // Resolve the configured reference through PrivateKeyStore.
    @Test
    public void testKeyStorePasswordResolvedThroughPrivateKeyStore() {
        System.setProperty(ATHENZ_PROP_KEYSTORE_PASSWORD, "test-key-store-password");
        System.setProperty(ATHENZ_PROP_KEYSTORE_PASSWORD_APPNAME, "zts");

        final String[] seen = new String[3];
        PrivateKeyStore store = new PrivateKeyStore() {
            @Override
            public char[] getSecret(String appName, String keygroupName, String keyName) {
                seen[0] = appName;
                seen[1] = keygroupName;
                seen[2] = keyName;
                return "decrypted".toCharArray();
            }
        };

        RolesAnywhereCredentialsProviderFactory factory = new RolesAnywhereCredentialsProviderFactory();
        factory.setPrivateKeyStore(store);

        assertEquals(new String(factory.keyStorePassword()), "decrypted");
        assertEquals(seen[0], "zts");
        assertNull(seen[1]);
        assertEquals(seen[2], "test-key-store-password");
    }

    @Test
    public void testKeyStoreSettingsOverrideServerSettings() throws Exception {
        System.setProperty(ATHENZ_PROP_KEYSTORE_PATH, "/nonexistent/server.p12");
        System.setProperty(ATHENZ_PROP_KEYSTORE_TYPE, "invalid-server-type");
        System.setProperty(ATHENZ_PROP_KEYSTORE_PASSWORD, "server-password-ref");
        System.setProperty(ATHENZ_PROP_KEYSTORE_PASSWORD_APPNAME, "server-app");
        System.setProperty(ATHENZ_PROP_KEYSTORE_PASSWORD_KEYGROUPNAME, "server-group");
        System.setProperty(PROP_KEYSTORE_PATH, "/nonexistent/rolesanywhere.p12");
        System.setProperty(PROP_KEYSTORE_TYPE, "PKCS12");
        System.setProperty(PROP_KEYSTORE_PASSWORD, "rolesanywhere-password-ref");
        System.setProperty(PROP_KEYSTORE_PASSWORD_APPNAME, "rolesanywhere-app");
        System.setProperty(PROP_KEYSTORE_PASSWORD_KEYGROUPNAME, "rolesanywhere-group");
        PrivateKeyStore secrets = mock(PrivateKeyStore.class);
        when(secrets.getSecret("rolesanywhere-app", "rolesanywhere-group", "rolesanywhere-password-ref"))
                .thenReturn(STORE_PASSWORD);
        RolesAnywhereCredentialsProviderFactory factory = new RolesAnywhereCredentialsProviderFactory();
        factory.setPrivateKeyStore(secrets);
        byte[] encoded = encodeKeyStore(keyStoreWithChain("zts"));
        // Replace file access with an in-memory PKCS12 stream; keep decoding real.
        try (MockedStatic<Files> files = mockStatic(Files.class)) {
            files.when(() -> Files.newInputStream(Paths.get("/nonexistent/rolesanywhere.p12")))
                    .thenReturn(new ByteArrayInputStream(encoded));
            X509Identity identity = factory.identityProvider().resolve();
            assertEquals(identity.certificate().getSubjectX500Principal().getName(), "CN=zts.example.com");
            files.verify(() -> Files.newInputStream(Paths.get("/nonexistent/rolesanywhere.p12")));
            verify(secrets).getSecret("rolesanywhere-app", "rolesanywhere-group", "rolesanywhere-password-ref");
            verifyNoMoreInteractions(secrets);
        }
    }

    @Test
    public void testKeyStoreIdentityReloadsContentsAndPassword() throws Exception {
        System.setProperty(PROP_KEYSTORE_PATH, "/nonexistent/rotating.p12");
        System.setProperty(PROP_KEYSTORE_PASSWORD, "password-ref");
        PrivateKeyStore secrets = mock(PrivateKeyStore.class);
        when(secrets.getSecret(null, null, "password-ref")).thenReturn(STORE_PASSWORD);
        RolesAnywhereCredentialsProviderFactory factory = new RolesAnywhereCredentialsProviderFactory();
        factory.setPrivateKeyStore(secrets);
        X509IdentityProvider identities = factory.identityProvider();
        KeyStore keyStore = keyStoreWithChain("zts");
        byte[] first = encodeKeyStore(keyStore);
        addKeyEntry(keyStore, "zts", "CN=rotated.example.com");
        byte[] rotated = encodeKeyStore(keyStore);
        try (MockedStatic<Files> files = mockStatic(Files.class)) {
            files.when(() -> Files.newInputStream(Paths.get("/nonexistent/rotating.p12")))
                    .thenReturn(new ByteArrayInputStream(first), new ByteArrayInputStream(rotated));
            X509Identity originalIdentity = identities.resolve();
            X509Identity rotatedIdentity = identities.resolve();
            assertEquals(originalIdentity.certificate().getSubjectX500Principal().getName(), "CN=zts.example.com");
            assertEquals(rotatedIdentity.certificate().getSubjectX500Principal().getName(), "CN=rotated.example.com");
            files.verify(() -> Files.newInputStream(Paths.get("/nonexistent/rotating.p12")), times(2));
            verify(secrets, times(2)).getSecret(null, null, "password-ref");
        }
    }

    private byte[] encodeKeyStore(KeyStore keyStore) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        keyStore.store(output, STORE_PASSWORD);
        return output.toByteArray();
    }

    @Test
    public void testKeyStorePasswordIsEmptyWhenUnset() {
        RolesAnywhereCredentialsProviderFactory factory = new RolesAnywhereCredentialsProviderFactory();
        assertEquals(new String(factory.keyStorePassword()), "");
    }

    private KeyStore keyStoreWithChain(final String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, STORE_PASSWORD);
        addKeyEntry(keyStore, alias, "CN=zts.example.com");
        return keyStore;
    }

    // Generate test identities in memory, with a separate issuer for the leaf.
    private void addKeyEntry(KeyStore keyStore, final String alias, final String subject) throws Exception {
        final String caSubject = "CN=athenz.intermediate.ca";

        KeyPair caKeyPair = generateKeyPair();
        KeyPair rootKeyPair = generateKeyPair();
        X509Certificate caCert = Crypto.generateX509Certificate(
                certRequest(caKeyPair, caSubject), rootKeyPair.getPrivate(),
                new X500Name("CN=athenz.root.ca"), 60, true);

        KeyPair keyPair = generateKeyPair();
        X509Certificate leaf = Crypto.generateX509Certificate(
                certRequest(keyPair, subject), caKeyPair.getPrivate(),
                new X500Name(caSubject), 60, false);

        keyStore.setKeyEntry(alias, keyPair.getPrivate(), STORE_PASSWORD,
                new Certificate[] { leaf, caCert });
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private PKCS10CertificationRequest certRequest(KeyPair keyPair, final String subject) throws Exception {
        return Crypto.getPKCS10CertRequest(
                Crypto.generateX509CSR(keyPair.getPrivate(), keyPair.getPublic(), subject, null));
    }
}
