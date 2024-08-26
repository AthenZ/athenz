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

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.http.HttpDriver;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ResourceException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class InstanceBuildKiteProviderTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private final File ecPublicKey = new File("./src/test/resources/unit_test_ec_public.key");

    private final Map<String, ?> testClaims = Map.of(
            "iss", "https://agent.buildkite.com",
            "aud", "https://athenz.io",
            "sub", "organization:my-org:pipeline:my-pipe:ref:refs/heads/main:commit:deadbeef:step:my-step",
            "organization_slug", "my-org",
            "pipeline_slug", "my-pipe",
            "build_number", 123,
            "job_id", "job-uuid"
    );

    private static class InstanceBuildKiteProviderTestImpl extends InstanceBuildKiteProvider {

        HttpDriver httpDriver;

        public void setHttpDriver(HttpDriver httpDriver) {
            this.httpDriver = httpDriver;
        }

        @Override
        HttpDriver getHttpDriver(String url) {
            return httpDriver;
        }
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_AUDIENCE);
        System.clearProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_JWKS_URI);
    }

    @Test
    public void testInitializeWithConfig() {
        String jwksUri = "https://test.jwks";
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_JWKS_URI, jwksUri);

        InstanceBuildKiteProvider provider = new InstanceBuildKiteProvider();
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);
        assertEquals(provider.signingKeyResolver.getJwksUri(), jwksUri);
        assertEquals(provider.getProviderScheme(), InstanceProvider.Scheme.CLASS);
        assertNotNull(provider.getHttpDriver(jwksUri));
    }

    @Test
    public void testInitializeWithHttpDriver() throws IOException {

        // std test where the http driver will return null for the config object

        InstanceBuildKiteProviderTestImpl provider = new InstanceBuildKiteProviderTestImpl();
        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);
        provider.setHttpDriver(httpDriver);
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);
        assertNotNull(provider);
        assertEquals(provider.signingKeyResolver.getJwksUri(), InstanceBuildKiteProvider.BUILD_KITE_ISSUER_JWKS_URI);

        // test where the http driver will return a valid config object

        provider = new InstanceBuildKiteProviderTestImpl();
        httpDriver = Mockito.mock(HttpDriver.class);
        Mockito.when(httpDriver.doGet("/.well-known/openid-configuration", null))
                .thenReturn("{\"jwks_uri\":\"https://athenz.io/jwks\"}");
        provider.setHttpDriver(httpDriver);
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);
        assertNotNull(provider);
        assertEquals(provider.signingKeyResolver.getJwksUri(), "https://athenz.io/jwks");

        // test when http driver return invalid data

        provider = new InstanceBuildKiteProviderTestImpl();
        httpDriver = Mockito.mock(HttpDriver.class);
        Mockito.when(httpDriver.doGet("/.well-known/openid-configuration", null))
                .thenReturn("invalid-json");
        provider.setHttpDriver(httpDriver);
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);
        assertNotNull(provider);
        assertEquals(provider.signingKeyResolver.getJwksUri(), InstanceBuildKiteProvider.BUILD_KITE_ISSUER_JWKS_URI);

        // and finally throwing an exception

        provider = new InstanceBuildKiteProviderTestImpl();
        httpDriver = Mockito.mock(HttpDriver.class);
        Mockito.when(httpDriver.doGet("/.well-known/openid-configuration", null))
                .thenThrow(new IOException("invalid-json"));
        provider.setHttpDriver(httpDriver);
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);
        assertNotNull(provider);
        assertEquals(provider.signingKeyResolver.getJwksUri(), InstanceBuildKiteProvider.BUILD_KITE_ISSUER_JWKS_URI);
    }

    @Test
    public void testConfirmInstance() {

        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_AUDIENCE, "https://athenz.io");

        InstanceBuildKiteProvider provider = new InstanceBuildKiteProvider();
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal mainPrincipal = SimplePrincipal.create("sports", "api", (String) null);
        Principal prPrincipal = SimplePrincipal.create("sports", "pr", (String) null);
        String mainResource = "sports:organization:my-org:pipeline:my-pipe:ref:refs/heads/main";
        String prResource = "sports:organization:my-org:pipeline:my-pipe";
        String action = "build-kite.build";
        Mockito.when(authorizer.access(eq(action), startsWith(mainResource), eq(mainPrincipal), isNull()))
                .thenReturn(true);
        Mockito.when(authorizer.access(eq(action), startsWith(prResource), eq(prPrincipal), isNull()))
                .thenReturn(true);
        provider.setAuthorizer(authorizer);

        assertTrue(authorizer.access(action, mainResource, mainPrincipal, null));
        assertTrue(authorizer.access(action, mainResource, prPrincipal, null));
        assertFalse(authorizer.access(action, prResource, mainPrincipal, null));
        assertTrue(authorizer.access(action, prResource, prPrincipal, null));

        // first, test for a build run from the main branch, requesting the main service

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "my-org:my-pipe:123:job-uuid");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.build-kite/my-org:my-pipe:job-uuid:123");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.build-kite.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");

        Map<String, Object> claims = new HashMap<>(testClaims);
        confirmation.setAttestationData(generateIdToken(Duration.ZERO, claims));
        confirmation.setAttributes(instanceAttributes);

        provider.signingKeyResolver.addPublicKey("0", Crypto.loadPublicKey(ecPublicKey));
        InstanceConfirmation confirmResponse = provider.confirmInstance(confirmation);
        assertNotNull(confirmResponse);
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_REFRESH), "false");
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_USAGE), "client");
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_EXPIRY_TIME), "360");

        // next, test for a build from a different branch, requesting the main service

        claims.put("sub", "organization:my-org:pipeline:my-pipe:ref:refs/heads/patch-1:commit:deadbeef:step:my-step");
        confirmation.setAttestationData(generateIdToken(Duration.ZERO, claims));
        confirmation.setAttributes(instanceAttributes);

        try {
            provider.confirmInstance(confirmation);
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("authorization check failed for action"));
        }

        // then, test for a build from a different branch, requesting the pr service

        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/pr,athenz://instanceid/sys.auth.build-kite/my-org:my-pipe:job-uuid:123");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "pr.sports.build-kite.athenz.io");
        confirmation.setService("pr");
        confirmation.setAttestationData(generateIdToken(Duration.ZERO, claims));
        confirmation.setAttributes(instanceAttributes);

        confirmResponse = provider.confirmInstance(confirmation);
        assertNotNull(confirmResponse);

        // finally, test for a build from the main branch, requesting the pr service (not really an intended use case)

        claims.put("sub", "organization:my-org:pipeline:my-pipe:ref:refs/heads/main:commit:deadbeef:step:my-step");
        confirmation.setAttestationData(generateIdToken(Duration.ZERO, claims));
        confirmation.setAttributes(instanceAttributes);

        confirmResponse = provider.confirmInstance(confirmation);
        assertNotNull(confirmResponse);
    }

    @Test
    public void testConfirmInstanceFailures() {

        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_AUDIENCE, "https://athenz.io");

        InstanceBuildKiteProvider provider = new InstanceBuildKiteProvider();
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = SimplePrincipal.create("sports", "api", (String) null);
        Mockito.when(authorizer.access(eq("build-kite.build"), startsWith("sports:organization:my-org:pipeline:my-pipe:ref:refs/heads/main"), eq(principal), isNull()))
                .thenReturn(true);
        provider.setAuthorizer(authorizer);

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "my-org:my-pipe:123:job-uuid");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.build-kite/my-org:my-pipe:job-uuid:123");
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Unable to validate Certificate Request: Unable to parse and validate token: A signing key must be specified if the specified JWT is digitally signed."));
        }

        // once we add the expected public key we should get a failure due to invalid san dns entry

        provider.signingKeyResolver.addPublicKey("0", Crypto.loadPublicKey(ecPublicKey));
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Unable to validate certificate request sanDNS entries"));
        }
    }

    @Test
    public void testConfirmInstanceWithoutAuthorizer() {
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceBuildKiteProvider provider = new InstanceBuildKiteProvider();
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);
        provider.setAuthorizer(null);
        try {
            provider.confirmInstance(null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Authorizer not available"));
        }
    }

    @Test
    public void testConfirmInstanceWithSanIP() {
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceBuildKiteProvider provider = new InstanceBuildKiteProvider();
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.1");
        confirmation.setAttributes(instanceAttributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Request must not have any sanIP addresses"));
        }
    }

    @Test
    public void testConfirmInstanceWithHostname() {
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceBuildKiteProvider provider = new InstanceBuildKiteProvider();
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "host1.athenz.io");
        confirmation.setAttributes(instanceAttributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Request must not have any hostname values"));
        }
    }

    @Test
    public void testConfirmInstanceWithSanURI() {
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceBuildKiteProvider provider = new InstanceBuildKiteProvider();
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/athenz.production/instanceid,https://athenz.io");
        confirmation.setAttributes(instanceAttributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Unable to validate certificate request URI values"));
        }
    }

    @Test
    public void testConfirmInstanceWithoutAttestationData() {
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceBuildKiteProvider provider = new InstanceBuildKiteProvider();
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Service credentials not provided"));
        }
    }

    @Test
    public void testRefreshNotSupported() {
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceBuildKiteProvider provider = new InstanceBuildKiteProvider();
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);
        try {
            provider.refreshInstance(null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("BuildKite X.509 Certificates cannot be refreshed"));
        }
    }

    @Test
    public void testValidateSanUri() {
        InstanceBuildKiteProvider provider = new InstanceBuildKiteProvider();
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
    public void testValidateOIDCTokenIssuerMismatch() {
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_AUDIENCE, "https://athenz.io");

        InstanceBuildKiteProvider provider = new InstanceBuildKiteProvider();
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);

        provider.signingKeyResolver.addPublicKey("0", Crypto.loadPublicKey(ecPublicKey));

        // our issuer will not match

        Map<String, Object> claims = new HashMap<>(testClaims);
        claims.put("iss", "https://some-other-issuer.com");
        String idToken = generateIdToken(Duration.ZERO, claims);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "my-org:my-pipe:123:job-uuid", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token issuer is not BuildKite"));
    }

    @Test
    public void testValidateOIDCTokenAudienceMismatch() {
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_AUDIENCE, "https://test.athenz.io");

        InstanceBuildKiteProvider provider = new InstanceBuildKiteProvider();
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);

        provider.signingKeyResolver.addPublicKey("0", Crypto.loadPublicKey(ecPublicKey));

        // our audience will not match

        Map<String, Object> claims = new HashMap<>(testClaims);
        claims.put("aud", "https://some-other-audience.com");
        String idToken = generateIdToken(Duration.ZERO, testClaims);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "my-org:my-pipe:123:job-uuid", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token audience is not ZTS Server audience"));
    }

    @Test
    public void testValidateOIDCTokenStartNotRecentEnough() {
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_AUDIENCE, "https://athenz.io");

        InstanceBuildKiteProvider provider = new InstanceBuildKiteProvider();
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);

        provider.signingKeyResolver.addPublicKey("0", Crypto.loadPublicKey(ecPublicKey));

        // our issue time is not recent enough

        String idToken = generateIdToken(Duration.ofSeconds(400).negated(), testClaims);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "athenz:sia:0001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("job start time is not recent enough"));
    }

    @Test
    public void testValidateOIDCTokenRunIdMismatch() {
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_AUDIENCE, "https://athenz.io");

        InstanceBuildKiteProvider provider = new InstanceBuildKiteProvider();
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);

        provider.signingKeyResolver.addPublicKey("0", Crypto.loadPublicKey(ecPublicKey));

        // instance ID from confirmation attributes does not match claims

        String idToken = generateIdToken(Duration.ZERO, testClaims);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "my-org:my-pipe:124:job-uuid", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("invalid instance id: my-org:my-pipe:123:job-uuid/my-org:my-pipe:124:job-uuid"));

        // missing organization slug

        Map<String, ?> claims = new HashMap<>(testClaims);
        claims.remove("organization_slug");
        idToken = generateIdToken(Duration.ZERO, claims);
        errMsg.setLength(0);
        result = provider.validateOIDCToken(idToken, "sports", "api", "athenz:sia:1001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token does not contain required organization_slug claim"));

        // missing pipeline slug

        claims = new HashMap<>(testClaims);
        claims.remove("pipeline_slug");
        idToken = generateIdToken(Duration.ZERO, claims);
        errMsg.setLength(0);
        result = provider.validateOIDCToken(idToken, "sports", "api", "athenz:sia:1001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token does not contain required pipeline_slug claim"));

        // missing job id

        claims = new HashMap<>(testClaims);
        claims.remove("job_id");
        idToken = generateIdToken(Duration.ZERO, claims);
        errMsg.setLength(0);
        result = provider.validateOIDCToken(idToken, "sports", "api", "athenz:sia:1001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token does not contain required job_id claim"));

        // missing build number

        claims = new HashMap<>(testClaims);
        claims.remove("build_number");
        idToken = generateIdToken(Duration.ZERO, claims);
        errMsg.setLength(0);
        result = provider.validateOIDCToken(idToken, "sports", "api", "athenz:sia:1001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token does not contain required build_number claim"));
    }

    @Test
    public void testValidateOIDCTokenMissingSubject() {
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceBuildKiteProvider.BUILD_KITE_PROP_AUDIENCE, "https://athenz.io");

        InstanceBuildKiteProvider provider = new InstanceBuildKiteProvider();
        provider.initialize("sys.auth.build_kite",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceBuildKiteProvider", null, null);

        provider.signingKeyResolver.addPublicKey("0", Crypto.loadPublicKey(ecPublicKey));

        // create an id token without the subject claim

        Map<String, ?> claims = new HashMap<>(testClaims);
        claims.remove("sub");
        String idToken = generateIdToken(Duration.ZERO, claims);

        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "my-org:my-pipe:123:job-uuid", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token does not contain required subject claim"));
    }

    private String generateIdToken(Duration issuedAtOffset, Map<String, ?> claims) {
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        JwtBuilder jwtBuilder = Jwts.builder()
                .setExpiration(Date.from(Instant.now().plus(issuedAtOffset).plusSeconds(3600)))
                .setIssuedAt(Date.from(Instant.now().plus(issuedAtOffset)));
        claims.forEach(jwtBuilder::claim);
        return jwtBuilder.setHeaderParam("kid", "0").signWith(privateKey, SignatureAlgorithm.ES256).compact();
    }
}
