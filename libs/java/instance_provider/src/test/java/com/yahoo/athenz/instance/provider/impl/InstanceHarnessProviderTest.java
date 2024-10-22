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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static org.mockito.ArgumentMatchers.*;
import static org.testng.Assert.*;

public class InstanceHarnessProviderTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");

    private final ClassLoader classLoader = this.getClass().getClassLoader();

    private final Map<String, ?> testClaims = Map.of(
            "iss", "https://athenz.harness.io",
            "aud", "https://athenz.io",
            "sub", "account/1234:org/athenzorg:project/athenz",
            "account_id", "1234",
            "organization_id", "athenzorg",
            "project_id", "athenz",
            "pipeline_id", "job-uuid",
            "context", "triggerType:manual/triggerEvent:null/sequenceId:1"
    );

    static void createOpenIdConfigFile(File configFile, File jwksUri) throws IOException {

        final String fileContents = "{\n" +
                "    \"jwks_uri\": \"file://" + jwksUri.getCanonicalPath() + "\"\n" +
                "}";
        Files.createDirectories(configFile.toPath().getParent());
        Files.write(configFile.toPath(), fileContents.getBytes());
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty(InstanceHarnessProvider.HARNESS_PROP_ACCOUNT_ID);
        System.clearProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI);
        System.clearProperty(InstanceHarnessProvider.HARNESS_PROP_AUDIENCE);
        System.clearProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER);
    }

    @Test
    public void testInitializeWithConfig() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ACCOUNT_ID, "athenz");
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://harness.io");

        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);
        assertEquals(provider.getProviderScheme(), InstanceProvider.Scheme.CLASS);
    }

    @Test
    public void testInitializeWithOpenIdConfig() throws IOException {

        File issuerFile = new File("./src/test/resources/config-openid");
        File configFile = new File("./src/test/resources/config-openid/.well-known/openid-configuration");
        File jwksUriFile = new File("./src/test/resources/jwt-jwks.json");
        createOpenIdConfigFile(configFile, jwksUriFile);

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "file://" + issuerFile.getCanonicalPath());

        // std test where the http driver will return null for the config object

        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);
        assertNotNull(provider);
        Files.delete(configFile.toPath());
    }

    @Test
    public void testInitializeMissingIssuer() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ACCOUNT_ID, "athenz");

        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        try {
            provider.initialize("sys.auth.harness",
                    "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Issuer not specified"));
        }
    }

    @Test
    public void testConfirmInstance() throws ProviderResourceException {
        testConfirmInstance(true, true);
        testConfirmInstance(false, true);
        testConfirmInstance(true, false);
        testConfirmInstance(false, false);
    }

    private void testConfirmInstance(boolean includeAccountId, boolean includePipelineIdInSubject) throws ProviderResourceException {

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://athenz.harness.io");

        if (includeAccountId) {
            System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ACCOUNT_ID, "1234");
        }

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_AUDIENCE, "https://athenz.io");

        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal mainPrincipal = SimplePrincipal.create("sports", "api", (String) null);
        String mainResource = "sports:account/1234:org/athenzorg:project/athenz";
        String action = "harness.manual";
        Mockito.when(authorizer.access(eq(action), startsWith(mainResource), eq(mainPrincipal), isNull())).thenReturn(true);
        provider.setAuthorizer(authorizer);

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "athenzorg:athenz:job-uuid:1");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.harness/athenzorg:athenz:job-uuid:1");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.harness.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");

        Map<String, Object> claims = new HashMap<>(testClaims);
        if (includePipelineIdInSubject) {
            claims.put("sub", "account/1234:org/athenzorg:project/athenz:pipeline/job-uuid");
        }
        confirmation.setAttestationData(generateIdToken(Duration.ZERO, claims));
        System.out.println("token: " + confirmation.getAttestationData());
        confirmation.setAttributes(instanceAttributes);

        InstanceConfirmation confirmResponse = provider.confirmInstance(confirmation);
        assertNotNull(confirmResponse);
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_REFRESH), "false");
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_USAGE), "client");
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_EXPIRY_TIME), "360");
    }

    @Test
    public void testConfirmInstanceWithTrigger() throws ProviderResourceException {

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://athenz.harness.io");
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ACCOUNT_ID, "1234");

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_AUDIENCE, "https://athenz.io");

        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal mainPrincipal = SimplePrincipal.create("sports", "api", (String) null);
        String mainResource = "sports:account/1234:org/athenzorg:project/athenz";
        String action = "harness.webhook.pr";
        Mockito.when(authorizer.access(eq(action), startsWith(mainResource), eq(mainPrincipal), isNull())).thenReturn(true);
        provider.setAuthorizer(authorizer);

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "athenzorg:athenz:job-uuid:1");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.harness/athenzorg:athenz:job-uuid:1");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.harness.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");

        Map<String, Object> claims = new HashMap<>(testClaims);
        claims.put("context", "triggerType:webhook/triggerEvent:pr/sequenceId:1");
        confirmation.setAttestationData(generateIdToken(Duration.ZERO, claims));
        confirmation.setAttributes(instanceAttributes);

        InstanceConfirmation confirmResponse = provider.confirmInstance(confirmation);
        assertNotNull(confirmResponse);
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_REFRESH), "false");
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_USAGE), "client");
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_EXPIRY_TIME), "360");
    }

    @Test
    public void testConfirmInstanceFailures() {

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://athenz.harness.io");

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks_empty.json")).toString();
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_AUDIENCE, "https://athenz.io");

        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal mainPrincipal = SimplePrincipal.create("sports", "api", (String) null);
        String mainResource = "sports:account/1234:org/athenzorg:project/athenz";
        String action = "harness.manual";
        Mockito.when(authorizer.access(eq(action), startsWith(mainResource), eq(mainPrincipal), isNull())).thenReturn(true);
        provider.setAuthorizer(authorizer);

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "athenzorg:athenz:job-uuid:1");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.harness/athenzorg:athenz:job-uuid:1");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.harness.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setAttestationData(generateIdToken(Duration.ZERO, testClaims));
        confirmation.setAttributes(instanceAttributes);

        // without the public key we should get a token validation failure

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("no matching key(s) found"));
        }

        provider.close();
    }

    @Test
    public void testConfirmInstanceFailuresInvalidSanDNS() {

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://athenz.harness.io");

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_AUDIENCE, "https://athenz.io");

        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal mainPrincipal = SimplePrincipal.create("sports", "api", (String) null);
        String mainResource = "sports:account/1234:org/athenzorg:project/athenz";
        String action = "harness.manual";
        Mockito.when(authorizer.access(eq(action), startsWith(mainResource), eq(mainPrincipal), isNull())).thenReturn(true);
        provider.setAuthorizer(authorizer);

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "athenzorg:athenz:job-uuid:1");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.harness/athenzorg:athenz:job-uuid:1");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "host1.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setAttestationData(generateIdToken(Duration.ZERO, testClaims));
        confirmation.setAttributes(instanceAttributes);

        // we should get a failure due to invalid san dns entry

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Unable to validate certificate request sanDNS entries"));
        }
    }

    @Test
    public void testConfirmInstanceWithoutAuthorizer() {

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://athenz.harness.io");

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);
        provider.setAuthorizer(null);
        try {
            provider.confirmInstance(null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Authorizer not available"));
        }
    }

    @Test
    public void testConfirmInstanceWithSanIP() {

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://athenz.harness.io");

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.1");
        confirmation.setAttributes(instanceAttributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Request must not have any sanIP addresses"));
        }
    }

    @Test
    public void testConfirmInstanceWithHostname() {

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://athenz.harness.io");

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "host1.athenz.io");
        confirmation.setAttributes(instanceAttributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Request must not have any hostname values"));
        }
    }

    @Test
    public void testConfirmInstanceWithSanURI() {

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://athenz.harness.io");

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/athenz.production/instanceid,https://athenz.io");
        confirmation.setAttributes(instanceAttributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Unable to validate certificate request URI values"));
        }
    }

    @Test
    public void testConfirmInstanceWithoutAttestationData() {

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://athenz.harness.io");

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Service credentials not provided"));
        }
    }

    @Test
    public void testRefreshNotSupported() {

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://athenz.harness.io");

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);
        try {
            provider.refreshInstance(null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Harness X.509 Certificates cannot be refreshed"));
        }
    }

    @Test
    public void testValidateSanUri() {
        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        assertTrue(provider.validateSanUri(null));
        assertTrue(provider.validateSanUri(""));
        assertTrue(provider.validateSanUri("spiffe://ns/athenz.production/instanceid"));
        assertTrue(provider.validateSanUri("athenz://instanceid/athenz.production/instanceid"));
        assertTrue(provider.validateSanUri("athenz://instanceid/athenz.production/instanceid,spiffe://ns/athenz.production/instanceid"));
        assertFalse(provider.validateSanUri("athenz://instanceid/athenz.production/instanceid,spiffe://ns/athenz.production/instanceid,https://athenz.io"));
        assertFalse(provider.validateSanUri("athenz://hostname/host1,athenz://instanceid/athenz.production/instanceid"));
        assertFalse(provider.validateSanUri("athenz://hostname/host1"));
    }

    @Test
    public void testValidateOIDCTokenWithoutJWTProcessor() {

        InstanceHarnessProvider provider = new InstanceHarnessProvider();

        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(provider.validateOIDCToken("some-jwt", "sports", "api", "athenzorg:athenz:job-uuid:1", errMsg));
        assertTrue(errMsg.toString().contains("JWT Processor not initialized"));

        provider.close();
    }

    @Test
    public void testValidateOIDCTokenIssuerMismatch() {

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://athenz.harness.io");

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_AUDIENCE, "https://athenz.io");

        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);

        // our issuer will not match

        Map<String, Object> claims = new HashMap<>(testClaims);
        claims.put("iss", "https://some-other-issuer.com");
        String idToken = generateIdToken(Duration.ZERO, claims);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "athenzorg:athenz:job-uuid:1", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token issuer is not Harness"));
    }

    @Test
    public void testValidateOIDCTokenAudienceMismatch() {

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://athenz.harness.io");

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_AUDIENCE, "https://test.athenz.io");

        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);

        // our audience will not match

        Map<String, Object> claims = new HashMap<>(testClaims);
        claims.put("aud", "https://some-other-audience.com");
        String idToken = generateIdToken(Duration.ZERO, claims);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "athenzorg:athenz:job-uuid:1", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token audience is not ZTS Server audience"));
    }

    @Test
    public void testValidateOIDCTokenAccountIdMismatch() {

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://athenz.harness.io");

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_AUDIENCE, "https://athenz.io");
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ACCOUNT_ID, "12345");

        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);

        Map<String, Object> claims = new HashMap<>(testClaims);
        String idToken = generateIdToken(Duration.ZERO, claims);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "athenzorg:athenz:job-uuid:1", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token account id is not the configured account id"));
    }

    @Test
    public void testValidateOIDCTokenStartNotRecentEnough() {

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://athenz.harness.io");

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_AUDIENCE, "https://athenz.io");

        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);

        // our issue time is not recent enough

        String idToken = generateIdToken(Duration.ofSeconds(400).negated(), testClaims);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "athenzorg:athenz:job-uuid:1", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("job start time is not recent enough"));
    }

    @Test
    public void testValidateOIDCTokenRunIdMismatch() {

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://athenz.harness.io");

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_AUDIENCE, "https://athenz.io");

        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);

        // instance ID from confirmation attributes does not match claims

        String idToken = generateIdToken(Duration.ZERO, testClaims);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "athenzorg:athenz:job-uuid:2", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("instance id: athenzorg:athenz:job-uuid:2 does not match claims instance id: athenzorg:athenz:job-uuid:1"));

        // missing organization id

        Map<String, Object> claims = new HashMap<>(testClaims);
        claims.remove("organization_id");
        idToken = generateIdToken(Duration.ZERO, claims);
        errMsg.setLength(0);
        result = provider.validateOIDCToken(idToken, "sports", "api", "athenzorg:athenz:job-uuid:1", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("instance id: athenzorg:athenz:job-uuid:1 does not match claims instance id: null:athenz:job-uuid:1"));

        // missing pipeline id

        claims = new HashMap<>(testClaims);
        claims.remove("pipeline_id");
        idToken = generateIdToken(Duration.ZERO, claims);
        errMsg.setLength(0);
        result = provider.validateOIDCToken(idToken, "sports", "api", "athenzorg:athenz:job-uuid:1", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("instance id: athenzorg:athenz:job-uuid:1 does not match claims instance id: athenzorg:athenz:null:1"));

        // missing project id

        claims = new HashMap<>(testClaims);
        claims.remove("project_id");
        idToken = generateIdToken(Duration.ZERO, claims);
        errMsg.setLength(0);
        result = provider.validateOIDCToken(idToken, "sports", "api", "athenzorg:athenz:job-uuid:1", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("instance id: athenzorg:athenz:job-uuid:1 does not match claims instance id: athenzorg:null:job-uuid:1"));

        // missing sequence number

        claims = new HashMap<>(testClaims);
        claims.remove("context");
        idToken = generateIdToken(Duration.ZERO, claims);
        assertNotNull(idToken);
        errMsg.setLength(0);
        result = provider.validateOIDCToken(idToken, "sports", "api", "athenzorg:athenz:job-uuid:1", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("instance id: athenzorg:athenz:job-uuid:1 does not match claims instance id: athenzorg:athenz:job-uuid:null"));

        // missing trigger type

        claims = new HashMap<>(testClaims);
        claims.put("context", "triggerEvent:null/sequenceId:1");
        idToken = generateIdToken(Duration.ZERO, claims);
        assertNotNull(idToken);
        errMsg.setLength(0);
        result = provider.validateOIDCToken(idToken, "sports", "api", "athenzorg:athenz:job-uuid:1", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token does not contain required trigger type"));
    }

    @Test
    public void testValidateOIDCTokenSubjectFailures() {

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://athenz.harness.io");

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_AUDIENCE, "https://athenz.io");

        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);

        // create an id token without the subject claim

        Map<String, Object> claims = new HashMap<>(testClaims);
        claims.remove("sub");
        String idToken = generateIdToken(Duration.ZERO, claims);

        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "athenzorg:athenz:job-uuid:1", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token does not contain required subject claim"));

        // create an id token with invalid subject

        claims = new HashMap<>(testClaims);
        claims.put("sub", "invalid-subject");
        idToken = generateIdToken(Duration.ZERO, claims);

        errMsg.setLength(0);
        result = provider.validateOIDCToken(idToken, "sports", "api", "athenzorg:athenz:job-uuid:1", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("subject: invalid-subject does not match subject fields"));
    }

    @Test
    public void testGetFieldFromContext() {
        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        assertEquals(provider.getFieldFromContext("triggerType:manual/triggerEvent:null/sequenceId:1", "triggerType"), "manual");
        assertEquals(provider.getFieldFromContext("triggerType:manual/triggerEvent:null/sequenceId:1", "triggerEvent"), "null");
        assertEquals(provider.getFieldFromContext("triggerType:manual/triggerEvent:null/sequenceId:1", "sequenceId"), "1");
        assertNull(provider.getFieldFromContext("triggerType:manual/triggerEvent:null/sequenceId:1", "unknown"));
    }

    @Test
    public void testConfirmInstanceAuthzFailure() {

        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ISSUER, "https://athenz.harness.io");
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_ACCOUNT_ID, "1234");

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceHarnessProvider.HARNESS_PROP_AUDIENCE, "https://athenz.io");

        InstanceHarnessProvider provider = new InstanceHarnessProvider();
        provider.initialize("sys.auth.harness",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceHarnessProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal mainPrincipal = SimplePrincipal.create("sports", "api", (String) null);
        String mainResource = "sports:account/1234:org/athenzorg:project/athenz";
        String action = "harness.manual";
        Mockito.when(authorizer.access(eq(action), startsWith(mainResource), eq(mainPrincipal), isNull())).thenReturn(false);
        provider.setAuthorizer(authorizer);

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "athenzorg:athenz:job-uuid:1");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.harness/athenzorg:athenz:job-uuid:1");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.harness.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");

        Map<String, Object> claims = new HashMap<>(testClaims);
        confirmation.setAttestationData(generateIdToken(Duration.ZERO, claims));
        confirmation.setAttributes(instanceAttributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("authorization check failed for action: harness.manual"));
        }
    }

    private String generateIdToken(Duration issuedAtOffset, Map<String, ?> claims) {

        try {
            PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

            JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
            JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                    .expirationTime(Date.from(Instant.now().plus(issuedAtOffset).plusSeconds(3600)))
                    .issueTime(Date.from(Instant.now().plus(issuedAtOffset)));
            claims.forEach(claimsSetBuilder::claim);

            SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(),
                    claimsSetBuilder.build());
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (Exception ex) {
            return null;
        }
    }
}
