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

import com.nimbusds.jose.JOSEException;
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
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import java.util.Objects;

import static org.testng.Assert.*;

public class InstanceGithubActionsProviderTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");

    private final ClassLoader classLoader = this.getClass().getClassLoader();

    @AfterMethod
    public void tearDown() {
        System.clearProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_ENTERPRISE);
        System.clearProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI);
        System.clearProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_AUDIENCE);
        System.clearProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_ENTERPRISE);
        System.clearProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_ISSUER);
    }

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

    @Test
    public void testInitializeWithConfig() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_ENTERPRISE, "athenz");

        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);
        assertEquals(provider.getProviderScheme(), InstanceProvider.Scheme.CLASS);
    }

    @Test
    public void testInitializeWithOpenIdConfig() throws IOException {

        File issuerFile = new File("./src/test/resources/config-openid/");
        File configFile = new File("./src/test/resources/config-openid/.well-known/openid-configuration");
        File jwksUriFile = new File("./src/test/resources/jwt-jwks.json");
        createOpenIdConfigFile(configFile, jwksUriFile);

        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_ISSUER, "file://" + issuerFile.getCanonicalPath());

        // std test where the http driver will return null for the config object

        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);
        assertNotNull(provider);
        Files.delete(configFile.toPath());
    }

    @Test
    public void testInitializeWithOpenIdConfigMissingUri() throws IOException {

        File issuerFile = new File("./src/test/resources/config-openid/");
        File configFile = new File("./src/test/resources/config-openid/.well-known/openid-configuration");
        createOpenIdConfigFile(configFile, null);

        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_ISSUER, "file://" + issuerFile.getCanonicalPath());

        // std test where the http driver will return null for the config object

        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);
        assertNotNull(provider);
        Files.delete(configFile.toPath());
    }

    @Test
    public void testConfirmInstance() throws JOSEException, ProviderResourceException {

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_AUDIENCE, "https://athenz.io");

        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = SimplePrincipal.create("sports", "api", (String) null);
        Mockito.when(authorizer.access("github.push", "sports:repo:athenz/sia:ref:refs/heads/main", principal, null))
                .thenReturn(true);
        provider.setAuthorizer(authorizer);

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "athenz:sia:0001");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.github-actions/athenz:sia:001");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.github-actions.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.github-actions");
        confirmation.setAttestationData(generateIdToken("https://token.actions.githubusercontent.com",
                System.currentTimeMillis() / 1000, false, false, false, false, false));
        confirmation.setAttributes(instanceAttributes);

        InstanceConfirmation confirmResponse = provider.confirmInstance(confirmation);
        assertNotNull(confirmResponse);
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_REFRESH), "false");
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_USAGE), "client");
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_EXPIRY_TIME), "360");
    }

    @Test
    public void testConfirmInstanceFailuresInvalidSANEntries() throws JOSEException {

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_AUDIENCE, "https://athenz.io");

        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = SimplePrincipal.create("sports", "api", (String) null);
        Mockito.when(authorizer.access("github.push", "sports:repo:athenz/sia:ref:refs/heads/main", principal, null))
                .thenReturn(true);
        provider.setAuthorizer(authorizer);

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "athenz:sia:0001");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.github-actions/athenz:sia:001");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "host1.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.github-actions");
        confirmation.setAttestationData(generateIdToken("https://token.actions.githubusercontent.com",
                System.currentTimeMillis() / 1000, false, false, false, false, false));
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
    public void testConfirmInstanceFailuresNoPublicKey() throws JOSEException {

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks_empty.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_AUDIENCE, "https://athenz.io");

        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = SimplePrincipal.create("sports", "api", (String) null);
        Mockito.when(authorizer.access("github.push", "sports:repo:athenz/sia:ref:refs/heads/main", principal, null))
                .thenReturn(true);
        provider.setAuthorizer(authorizer);

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "athenz:sia:0001");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.github-actions/athenz:sia:001");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "host1.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.github-actions");
        confirmation.setAttestationData(generateIdToken("https://token.actions.githubusercontent.com",
                System.currentTimeMillis() / 1000, false, false, false, false, false));
        confirmation.setAttributes(instanceAttributes);

        // without the public key we should get a token validation failure

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Signed JWT rejected: Another algorithm expected, or no matching key(s) found"));
        }
    }

    @Test
    public void testConfirmInstanceWithoutAuthorizer() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);
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
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);

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
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);

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
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);

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
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);

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
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);
        try {
            provider.refreshInstance(null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("GitHub Action X.509 Certificates cannot be refreshed"));
        }
    }

    @Test
    public void testValidateSanUri() {
        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
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

        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        String issuer = "https://token.actions.githubusercontent.com";
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(provider.validateOIDCToken(issuer, "some-jwt", "sports", "api", "athenz:sia:0001", errMsg));
        assertTrue(errMsg.toString().contains("JWT Processor not initialized"));

        provider.close();
    }

    @Test
    public void testValidateOIDCTokenIssuerMismatch() throws JOSEException {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_AUDIENCE, "https://athenz.io");

        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);

        // our issuer will not match

        String wrongIssuer = "https://token-actions.githubusercontent.com";
        String idToken = generateIdToken(wrongIssuer,
                System.currentTimeMillis() / 1000, false, false, false, false, false);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(wrongIssuer, idToken, "sports", "api", "athenz:sia:0001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token issuer is not GitHub Actions"));
    }

    @Test
    public void testValidateOIDCTokenAudienceMismatch() throws JOSEException {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_AUDIENCE, "https://test.athenz.io");

        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);

        // our audience will not match

        String issuer = "https://token.actions.githubusercontent.com";
        String idToken = generateIdToken(issuer,
                System.currentTimeMillis() / 1000, false, false, false, false, false);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(issuer, idToken, "sports", "api", "athenz:sia:0001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token audience is not ZTS Server audience"));
    }

    @Test
    public void testValidateOIDCTokenEnterpriseMismatch() throws JOSEException {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_AUDIENCE, "https://athenz.io");
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_ENTERPRISE, "athenz-test");

        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);

        // our enterprise will not match

        String issuer = "https://token.actions.githubusercontent.com";
        String idToken = generateIdToken(issuer,
                System.currentTimeMillis() / 1000, false, false, false, false, false);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(issuer, idToken, "sports", "api", "athenz:sia:0001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token enterprise is not the configured enterprise"));
    }

    @Test
    public void testValidateOIDCTokenStartNotRecentEnough() throws JOSEException {

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_AUDIENCE, "https://athenz.io");

        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);

        // our issue time is not recent enough

        String issuer = "https://token.actions.githubusercontent.com";
        String idToken = generateIdToken(issuer,
                System.currentTimeMillis() / 1000 - 400, false, false, false, false, false);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(issuer, idToken, "sports", "api", "athenz:sia:0001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("job start time is not recent enough"));

        // create another token without the issue time
        idToken = generateIdToken(issuer,
                System.currentTimeMillis() / 1000, false, false, true, false, false);
        errMsg.setLength(0);
        result = provider.validateOIDCToken(issuer, idToken, "sports", "api", "athenz:sia:0001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("job start time is not recent enough"));
    }

    @Test
    public void testValidateOIDCTokenRunIdMismatch() throws JOSEException {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_AUDIENCE, "https://athenz.io");
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_ENTERPRISE, "athenz");

        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);

        // our issue time is not recent enough
        String issuer = "https://token.actions.githubusercontent.com";
        String idToken = generateIdToken(issuer,
                System.currentTimeMillis() / 1000, false, false, false, false, false);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(issuer, idToken, "sports", "api", "athenz:sia:1001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("invalid instance id: athenz:sia:0001/athenz:sia:1001"));

        idToken = generateIdToken(issuer,
                System.currentTimeMillis() / 1000, false, false, false, true, false);
        errMsg.setLength(0);
        result = provider.validateOIDCToken(issuer, idToken, "sports", "api", "athenz:sia:1001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token does not contain required run_id or repository claims"));

        idToken = generateIdToken(issuer,
                System.currentTimeMillis() / 1000, false, false, false, false, true);
        errMsg.setLength(0);
        result = provider.validateOIDCToken(issuer, idToken, "sports", "api", "athenz:sia:1001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token does not contain required run_id or repository claims"));
    }

    @Test
    public void testValidateOIDCTokenMissingEventName() throws JOSEException {

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_AUDIENCE, "https://athenz.io");
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_ENTERPRISE, "athenz");

        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);

        //provider.signingKeyResolver.addPublicKey("0", Crypto.loadPublicKey(ecPublicKey));

        // create an id token without the event_name claim
        String issuer = "https://token.actions.githubusercontent.com";
        String idToken = generateIdToken(issuer,
                System.currentTimeMillis() / 1000, false, true, false, false, false);

        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(issuer, idToken, "sports", "api", "athenz:sia:0001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token does not contain required event_name claim"));
    }

    @Test
    public void testValidateOIDCTokenMissingSubject() throws JOSEException {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_AUDIENCE, "https://athenz.io");
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_ENTERPRISE, "athenz");

        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);

        // create an id token without the subject claim
        String issuer = "https://token.actions.githubusercontent.com";
        String idToken = generateIdToken(issuer,
                System.currentTimeMillis() / 1000, true, false, false, false, false);

        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(issuer, idToken, "sports", "api", "athenz:sia:0001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token does not contain required subject claim"));
    }

    @Test
    public void testValidateOIDCTokenAuthorizationFailure() throws JOSEException {

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_AUDIENCE, "https://athenz.io");
        System.setProperty(InstanceGithubActionsProvider.GITHUB_ACTIONS_PROP_ENTERPRISE, "athenz");

        InstanceGithubActionsProvider provider = new InstanceGithubActionsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceGithubActionsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = SimplePrincipal.create("sports", "api", (String) null);
        Mockito.when(authorizer.access("github.push", "sports:repo:athenz/sia:ref:refs/heads/main", principal, null))
                .thenReturn(false);
        provider.setAuthorizer(authorizer);

        // create an id token
        String issuer = "https://token.actions.githubusercontent.com";
        String idToken = generateIdToken(issuer,
                System.currentTimeMillis() / 1000, false, false, false, false, false);

        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(issuer, idToken, "sports", "api", "athenz:sia:0001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("authorization check failed for action"));
    }

    private String generateIdToken(final String issuer, long currentTimeSecs, boolean skipSubject,
            boolean skipEventName, boolean skipIssuedAt, boolean skipRunId, boolean skipRepository) throws JOSEException {

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .expirationTime(Date.from(Instant.ofEpochSecond(currentTimeSecs + 3600)))
                .issuer(issuer)
                .audience("https://athenz.io")
                .claim("enterprise", "athenz");
        if (!skipRunId) {
            claimsSetBuilder.claim("run_id", "0001");
        }
        if (!skipRepository) {
            claimsSetBuilder.claim("repository", "athenz/sia");
        }
        if (!skipSubject) {
            claimsSetBuilder.subject("repo:athenz/sia:ref:refs/heads/main");
        }
        if (!skipEventName) {
            claimsSetBuilder.claim("event_name", "push");
        }
        if (!skipIssuedAt) {
            claimsSetBuilder.issueTime(Date.from(Instant.ofEpochSecond(currentTimeSecs)));
        }

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(),
                claimsSetBuilder.build());
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }
}
