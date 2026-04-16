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

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class InstanceSpaceliftProviderTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");

    private final ClassLoader classLoader = this.getClass().getClassLoader();

    private final Map<String, ?> testClaims = Map.of(
            "iss", "https://demo.app.spacelift.io",
            "aud", "https://athenz.io",
            "sub", "space:my-space:stack:my-stack:run_type:TRACKED:scope:write",
            "spaceId", "my-space",
            "callerType", "stack",
            "callerId", "my-stack",
            "runType", "TRACKED",
            "runId", "run-uuid-123",
            "scope", "write"
    );

    static void createOpenIdConfigFile(File configFile, File jwksUri) throws IOException {

        String fileContents;
        if (jwksUri == null) {
            fileContents = "{}";
        } else {
            fileContents = "{\n" +
                    "    \"jwks_uri\": \"file://" + jwksUri.getCanonicalPath() + "\"\n" +
                    "}";
        }
        Files.createDirectories(configFile.toPath().getParent());
        Files.write(configFile.toPath(), fileContents.getBytes());
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_AUDIENCE);
        System.clearProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_JWKS_URI);
        System.clearProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER);
    }

    @Test
    public void testInitializeWithConfig() {
        String jwksUri = "https://test.jwks";
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER, "https://demo.app.spacelift.io");

        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        provider.initialize("sys.auth.spacelift",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);
        assertEquals(provider.getProviderScheme(), InstanceProvider.Scheme.CLASS);
    }

    @Test
    public void testInitializeWithOpenIdConfig() throws IOException {

        File issuerFile = new File("./src/test/resources/config-openid/");
        File configFile = new File("./src/test/resources/config-openid/.well-known/openid-configuration");
        File jwksUriFile = new File("./src/test/resources/jwt-jwks.json");
        createOpenIdConfigFile(configFile, jwksUriFile);

        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER, "file://" + issuerFile.getCanonicalPath());

        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        provider.initialize("sys.auth.spacelift",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);
        assertNotNull(provider);
        Files.delete(configFile.toPath());
    }

    @Test
    public void testInitializeWithOpenIdConfigWithoutUri() throws IOException {

        File issuerFile = new File("./src/test/resources/config-openid/");
        File configFile = new File("./src/test/resources/config-openid/.well-known/openid-configuration");
        createOpenIdConfigFile(configFile, null);

        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER, "file://" + issuerFile.getCanonicalPath());

        // without a jwks_uri in the openid config and no explicit jwks_uri property,
        // the provider should fail to initialize since there is no fallback

        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        try {
            provider.initialize("sys.auth.spacelift",
                    "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Jwks uri must be specified"));
        }
        Files.delete(configFile.toPath());
    }

    @Test
    public void testInitializeMissingIssuer() {
        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        try {
            provider.initialize("sys.auth.spacelift",
                    "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Issuer not specified"));
        }
    }

    @Test
    public void testConfirmInstance() throws ProviderResourceException {

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_AUDIENCE, "https://athenz.io");
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER, "https://demo.app.spacelift.io");

        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        provider.initialize("sys.auth.spacelift",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal trackedPrincipal = SimplePrincipal.create("sports", "api", (String) null);
        Principal proposedPrincipal = SimplePrincipal.create("sports", "pr", (String) null);
        String trackedResource = "sports:space:my-space:stack:my-stack:run_type:TRACKED";
        String proposedResource = "sports:space:my-space:stack:my-stack:run_type:PROPOSED";
        String action = "spacelift.run";
        Mockito.when(authorizer.access(eq(action), startsWith(trackedResource), eq(trackedPrincipal), isNull()))
                .thenReturn(true);
        Mockito.when(authorizer.access(eq(action), startsWith(proposedResource), eq(proposedPrincipal), isNull()))
                .thenReturn(true);
        provider.setAuthorizer(authorizer);

        // test for a tracked run requesting the main service

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "my-space:my-stack:run-uuid-123");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.spacelift/my-space:my-stack:run-uuid-123");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.spacelift.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");

        Map<String, Object> claims = new HashMap<>(testClaims);
        confirmation.setAttestationData(generateIdToken(Duration.ZERO, claims));
        confirmation.setAttributes(instanceAttributes);

        InstanceConfirmation confirmResponse = provider.confirmInstance(confirmation);
        assertNotNull(confirmResponse);
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_REFRESH), "false");
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_USAGE), "client");
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_EXPIRY_TIME), "360");

        // test for a proposed run requesting the main service (should fail)

        claims.put("sub", "space:my-space:stack:my-stack:run_type:PROPOSED:scope:read");
        claims.put("runType", "PROPOSED");
        claims.put("scope", "read");
        confirmation.setAttestationData(generateIdToken(Duration.ZERO, claims));
        confirmation.setAttributes(instanceAttributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("authorization check failed for action"));
        }

        // test for a proposed run requesting the pr service

        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/pr,athenz://instanceid/sys.auth.spacelift/my-space:my-stack:run-uuid-123");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "pr.sports.spacelift.athenz.io");
        confirmation.setService("pr");
        confirmation.setAttestationData(generateIdToken(Duration.ZERO, claims));
        confirmation.setAttributes(instanceAttributes);

        confirmResponse = provider.confirmInstance(confirmation);
        assertNotNull(confirmResponse);
    }

    @Test
    public void testConfirmInstanceFailures() {

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks_empty.json")).toString();
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_AUDIENCE, "https://athenz.io");
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER, "https://demo.app.spacelift.io");

        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        provider.initialize("sys.auth.spacelift",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = SimplePrincipal.create("sports", "api", (String) null);
        Mockito.when(authorizer.access(eq("spacelift.run"), startsWith("sports:space:my-space:stack:my-stack:run_type:TRACKED"), eq(principal), isNull()))
                .thenReturn(true);
        provider.setAuthorizer(authorizer);

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "my-space:my-stack:run-uuid-123");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.spacelift/my-space:my-stack:run-uuid-123");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "host1.athenz.io");

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

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_AUDIENCE, "https://athenz.io");
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER, "https://demo.app.spacelift.io");

        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        provider.initialize("sys.auth.spacelift",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = SimplePrincipal.create("sports", "api", (String) null);
        Mockito.when(authorizer.access(eq("spacelift.run"), startsWith("sports:space:my-space:stack:my-stack:run_type:TRACKED"), eq(principal), isNull()))
                .thenReturn(true);
        provider.setAuthorizer(authorizer);

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "my-space:my-stack:run-uuid-123");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.spacelift/my-space:my-stack:run-uuid-123");
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
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER, "https://demo.app.spacelift.io");
        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        provider.initialize("sys.auth.spacelift",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);
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
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER, "https://demo.app.spacelift.io");
        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        provider.initialize("sys.auth.spacelift",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);

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
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER, "https://demo.app.spacelift.io");
        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        provider.initialize("sys.auth.spacelift",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);

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
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER, "https://demo.app.spacelift.io");
        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        provider.initialize("sys.auth.spacelift",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);

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
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER, "https://demo.app.spacelift.io");
        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        provider.initialize("sys.auth.spacelift",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);

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
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER, "https://demo.app.spacelift.io");
        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        provider.initialize("sys.auth.spacelift",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);
        try {
            provider.refreshInstance(null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Spacelift X.509 Certificates cannot be refreshed"));
        }
    }

    @Test
    public void testValidateSanUri() {
        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
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

        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();

        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(provider.validateOIDCToken("some-jwt", "sports", "api", "my-space:my-stack:run-uuid-123", errMsg));
        assertTrue(errMsg.toString().contains("JWT Processor not initialized"));

        provider.close();
    }

    @Test
    public void testValidateOIDCTokenIssuerMismatch() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_AUDIENCE, "https://athenz.io");
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER, "https://demo.app.spacelift.io");

        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        provider.initialize("sys.auth.spacelift",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);

        // our issuer will not match

        Map<String, Object> claims = new HashMap<>(testClaims);
        claims.put("iss", "https://some-other-issuer.com");
        String idToken = generateIdToken(Duration.ZERO, claims);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "my-space:my-stack:run-uuid-123", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token issuer is not Spacelift"));
    }

    @Test
    public void testValidateOIDCTokenAudienceMismatch() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_AUDIENCE, "https://test.athenz.io");
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER, "https://demo.app.spacelift.io");

        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        provider.initialize("sys.auth.spacelift",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);

        // our audience will not match

        Map<String, Object> claims = new HashMap<>(testClaims);
        claims.put("aud", "https://some-other-audience.com");
        String idToken = generateIdToken(Duration.ZERO, claims);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "my-space:my-stack:run-uuid-123", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token audience is not ZTS Server audience"));
    }

    @Test
    public void testValidateOIDCTokenStartNotRecentEnough() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_AUDIENCE, "https://athenz.io");
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER, "https://demo.app.spacelift.io");

        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        provider.initialize("sys.auth.spacelift",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);

        // our issue time is not recent enough

        String idToken = generateIdToken(Duration.ofSeconds(400).negated(), testClaims);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "my-space:my-stack:run-uuid-123", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("job start time is not recent enough"));
    }

    @Test
    public void testValidateOIDCTokenInstanceIdMismatch() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_AUDIENCE, "https://athenz.io");
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER, "https://demo.app.spacelift.io");

        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        provider.initialize("sys.auth.spacelift",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);

        // instance ID from confirmation attributes does not match claims

        String idToken = generateIdToken(Duration.ZERO, testClaims);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "my-space:my-stack:wrong-run-id", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("invalid instance id: my-space:my-stack:run-uuid-123/my-space:my-stack:wrong-run-id"));

        // missing spaceId

        Map<String, ?> claims = new HashMap<>(testClaims);
        claims.remove("spaceId");
        idToken = generateIdToken(Duration.ZERO, claims);
        errMsg.setLength(0);
        result = provider.validateOIDCToken(idToken, "sports", "api", "athenz:sia:1001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token does not contain required spaceId claim"));

        // missing callerId

        claims = new HashMap<>(testClaims);
        claims.remove("callerId");
        idToken = generateIdToken(Duration.ZERO, claims);
        errMsg.setLength(0);
        result = provider.validateOIDCToken(idToken, "sports", "api", "athenz:sia:1001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token does not contain required callerId claim"));

        // missing runId

        claims = new HashMap<>(testClaims);
        claims.remove("runId");
        idToken = generateIdToken(Duration.ZERO, claims);
        errMsg.setLength(0);
        result = provider.validateOIDCToken(idToken, "sports", "api", "athenz:sia:1001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token does not contain required runId claim"));
    }

    @Test
    public void testValidateOIDCTokenMissingSubject() {

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_AUDIENCE, "https://athenz.io");
        System.setProperty(InstanceSpaceliftProvider.SPACELIFT_PROP_ISSUER, "https://demo.app.spacelift.io");

        InstanceSpaceliftProvider provider = new InstanceSpaceliftProvider();
        provider.initialize("sys.auth.spacelift",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceSpaceliftProvider", null, null);

        // create an id token without the subject claim

        Map<String, ?> claims = new HashMap<>(testClaims);
        claims.remove("sub");
        String idToken = generateIdToken(Duration.ZERO, claims);

        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "my-space:my-stack:run-uuid-123", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token does not contain required subject claim"));
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
