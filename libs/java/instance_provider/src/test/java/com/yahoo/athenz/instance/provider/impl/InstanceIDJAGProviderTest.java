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

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class InstanceIDJAGProviderTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");

    private final ClassLoader classLoader = this.getClass().getClassLoader();

    private static final String ID_JAG_ISSUER = "https://ouryahoo-qa.oktapreview.com/oauth2/auszk0d21jOU4XApV1d7";
    private static final String ID_JAG_AUDIENCE = "https://ouryahoo-qa.oktapreview.com/oauth2/auszk0d21jOU4XApV1d7";
    private static final String ID_JAG_DOMAIN = "sports";
    private static final String ID_JAG_CLIENT_ID = "wlp12tsy8084bo8FU1d8";
    private static final String ID_JAG_SERVICE = "wlp12tsy8084bo8fu1d8";
    private static final String ID_JAG_SUB_PROFILE = "ai_agent";

    private static Map<String, Object> actClaim() {

        Map<String, Object> innerAct = new LinkedHashMap<>();
        innerAct.put("sub", "0oa12h8wsb9KwK0fY1d8");
        innerAct.put("sub_profile", "service");

        Map<String, Object> middleAct = new LinkedHashMap<>();
        middleAct.put("act", innerAct);
        middleAct.put("sub", "wlp12h9yjhs9WonAM1d8");
        middleAct.put("sub_profile", "ai_agent");

        Map<String, Object> outerAct = new LinkedHashMap<>();
        outerAct.put("act", middleAct);
        outerAct.put("sub", ID_JAG_CLIENT_ID);
        outerAct.put("sub_profile", ID_JAG_SUB_PROFILE);

        return outerAct;
    }

    private static Map<String, Object> testClaims() {

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", ID_JAG_ISSUER);
        claims.put("aud", ID_JAG_AUDIENCE);
        claims.put("sub", "0oa12h8wsb9KwK0fY1d8");
        claims.put("client_id", ID_JAG_CLIENT_ID);
        claims.put("act", actClaim());
        return claims;
    }

    private static Map<String, String> testAttributes() {

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_ID, "id-jag-instance-001");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI,
                "spiffe://ns/default/sports/" + ID_JAG_SERVICE + ",athenz://instanceid/sys.auth.id_jag/id-jag-instance-001");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, ID_JAG_SERVICE + ".sports.id-jag.athenz.io");
        return attributes;
    }

    private static void setStandardProperties(final String jwksUri) {
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_JWKS_URI, jwksUri);
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_ISSUER, ID_JAG_ISSUER);
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_AUDIENCE, ID_JAG_AUDIENCE);
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_DOMAIN, ID_JAG_DOMAIN);
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_ACT_SUB_PROFILE, ID_JAG_SUB_PROFILE);
    }

    private InstanceIDJAGProvider createProvider(final String jwksResource) {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource(jwksResource)).toString();
        setStandardProperties(jwksUri);
        InstanceIDJAGProvider provider = new InstanceIDJAGProvider();
        provider.initialize("sys.auth.id_jag",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceIDJAGProvider", null, null);
        return provider;
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty(InstanceIDJAGProvider.ID_JAG_PROP_JWKS_URI);
        System.clearProperty(InstanceIDJAGProvider.ID_JAG_PROP_ISSUER);
        System.clearProperty(InstanceIDJAGProvider.ID_JAG_PROP_AUDIENCE);
        System.clearProperty(InstanceIDJAGProvider.ID_JAG_PROP_DOMAIN);
        System.clearProperty(InstanceIDJAGProvider.ID_JAG_PROP_ACT_SUB_PROFILE);
        System.clearProperty(InstanceIDJAGProvider.ID_JAG_PROP_PROVIDER_DNS_SUFFIX);
        System.clearProperty(InstanceIDJAGProvider.ID_JAG_PROP_CERT_EXPIRY_TIME);
    }

    @Test
    public void testInitializeWithConfig() {
        setStandardProperties("https://test.jwks");
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_PROVIDER_DNS_SUFFIX, "id-jag.athenz.io,jag.athenz.io");
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_CERT_EXPIRY_TIME, "120");

        InstanceIDJAGProvider provider = new InstanceIDJAGProvider();
        provider.initialize("sys.auth.id_jag",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceIDJAGProvider", null, null);

        assertEquals(provider.getProviderScheme(), InstanceProvider.Scheme.CLASS);
        assertEquals(provider.getSVIDType(), InstanceProvider.SVIDType.X509);
        assertEquals(provider.dnsSuffixes.size(), 2);
        assertEquals(provider.certExpiryTime, 120);
        provider.close();
    }

    @Test
    public void testInitializeWithOpenIdConfig() throws IOException {

        File issuerFile = new File("./src/test/resources/config-openid/");
        File configFile = new File("./src/test/resources/config-openid/.well-known/openid-configuration");
        File jwksUriFile = new File("./src/test/resources/jwt_jwks.json");
        InstanceSpaceliftProviderTest.createOpenIdConfigFile(configFile, jwksUriFile);

        setStandardProperties("https://test.jwks");
        System.clearProperty(InstanceIDJAGProvider.ID_JAG_PROP_JWKS_URI);
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_ISSUER, "file://" + issuerFile.getCanonicalPath());

        InstanceIDJAGProvider provider = new InstanceIDJAGProvider();
        provider.initialize("sys.auth.id_jag",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceIDJAGProvider", null, null);
        assertNotNull(provider.jwtProcessor);
        Files.delete(configFile.toPath());
    }

    @Test
    public void testInitializeMissingDomain() {
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_JWKS_URI, "https://test.jwks");
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_ISSUER, ID_JAG_ISSUER);
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_AUDIENCE, ID_JAG_AUDIENCE);
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_ACT_SUB_PROFILE, ID_JAG_SUB_PROFILE);

        InstanceIDJAGProvider provider = new InstanceIDJAGProvider();
        try {
            provider.initialize("sys.auth.id_jag",
                    "class://com.yahoo.athenz.instance.provider.impl.InstanceIDJAGProvider", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Domain not specified"));
        }
    }

    @Test
    public void testInitializeMissingAudience() {
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_JWKS_URI, "https://test.jwks");
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_ISSUER, ID_JAG_ISSUER);
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_DOMAIN, ID_JAG_DOMAIN);
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_ACT_SUB_PROFILE, ID_JAG_SUB_PROFILE);

        InstanceIDJAGProvider provider = new InstanceIDJAGProvider();
        try {
            provider.initialize("sys.auth.id_jag",
                    "class://com.yahoo.athenz.instance.provider.impl.InstanceIDJAGProvider", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Audience not specified"));
        }
    }

    @Test
    public void testInitializeDefaultActSubProfile() {
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_JWKS_URI, "https://test.jwks");
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_ISSUER, ID_JAG_ISSUER);
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_AUDIENCE, ID_JAG_AUDIENCE);
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_DOMAIN, ID_JAG_DOMAIN);

        InstanceIDJAGProvider provider = new InstanceIDJAGProvider();
        provider.initialize("sys.auth.id_jag",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceIDJAGProvider", null, null);
        assertEquals(provider.actSubProfile, "ai_agent");
    }

    @Test
    public void testInitializeEmptyActSubProfile() {
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_JWKS_URI, "https://test.jwks");
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_ISSUER, ID_JAG_ISSUER);
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_AUDIENCE, ID_JAG_AUDIENCE);
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_DOMAIN, ID_JAG_DOMAIN);
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_ACT_SUB_PROFILE, "");

        InstanceIDJAGProvider provider = new InstanceIDJAGProvider();
        try {
            provider.initialize("sys.auth.id_jag",
                    "class://com.yahoo.athenz.instance.provider.impl.InstanceIDJAGProvider", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Act sub profile not specified"));
        }
    }

    @Test
    public void testInitializeMissingIssuer() {
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_JWKS_URI, "https://test.jwks");
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_AUDIENCE, ID_JAG_AUDIENCE);
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_DOMAIN, ID_JAG_DOMAIN);
        System.setProperty(InstanceIDJAGProvider.ID_JAG_PROP_ACT_SUB_PROFILE, ID_JAG_SUB_PROFILE);

        InstanceIDJAGProvider provider = new InstanceIDJAGProvider();
        try {
            provider.initialize("sys.auth.id_jag",
                    "class://com.yahoo.athenz.instance.provider.impl.InstanceIDJAGProvider", null, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Issuer not specified"));
        }
    }

    @Test
    public void testConfirmInstance() throws ProviderResourceException {

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain(ID_JAG_DOMAIN);
        confirmation.setService(ID_JAG_SERVICE);
        confirmation.setAttestationData(generateIdJagToken(Duration.ZERO, testClaims()));
        confirmation.setAttributes(testAttributes());

        InstanceConfirmation confirmResponse = provider.confirmInstance(confirmation);
        assertNotNull(confirmResponse);
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_REFRESH), "false");
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_USAGE), "client");
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_EXPIRY_TIME), "360");
    }

    @Test
    public void testConfirmInstanceMixedCaseSanDNS() throws ProviderResourceException {

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        // the workload generates its CSR with the mixed case client id as the
        // service component of the sanDNS entry while ZTS lowercases the
        // service name in the confirmation object, so the sanDNS service
        // component comparison must ignore case

        Map<String, String> attributes = testAttributes();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, ID_JAG_CLIENT_ID + ".sports.id-jag.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain(ID_JAG_DOMAIN);
        confirmation.setService(ID_JAG_SERVICE);
        confirmation.setAttestationData(generateIdJagToken(Duration.ZERO, testClaims()));
        confirmation.setAttributes(attributes);

        InstanceConfirmation confirmResponse = provider.confirmInstance(confirmation);
        assertNotNull(confirmResponse);
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_USAGE), "client");
    }

    @Test
    public void testConfirmInstanceInvalidDomain() {

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("weather");
        confirmation.setService(ID_JAG_SERVICE);
        confirmation.setAttestationData(generateIdJagToken(Duration.ZERO, testClaims()));
        confirmation.setAttributes(testAttributes());

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Domain: weather is not the configured domain: sports"));
        }
    }

    @Test
    public void testConfirmInstanceWithSanIP() {

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        Map<String, String> attributes = testAttributes();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.1");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain(ID_JAG_DOMAIN);
        confirmation.setService(ID_JAG_SERVICE);
        confirmation.setAttributes(attributes);

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

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        Map<String, String> attributes = testAttributes();
        attributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "host1.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain(ID_JAG_DOMAIN);
        confirmation.setService(ID_JAG_SERVICE);
        confirmation.setAttributes(attributes);

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

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        Map<String, String> attributes = testAttributes();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "https://athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain(ID_JAG_DOMAIN);
        confirmation.setService(ID_JAG_SERVICE);
        confirmation.setAttributes(attributes);

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

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain(ID_JAG_DOMAIN);
        confirmation.setService(ID_JAG_SERVICE);
        confirmation.setAttributes(testAttributes());

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Service credentials not provided"));
        }
    }

    @Test
    public void testConfirmInstanceInvalidToken() {

        InstanceIDJAGProvider provider = createProvider("jwt_jwks_empty.json");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain(ID_JAG_DOMAIN);
        confirmation.setService(ID_JAG_SERVICE);
        confirmation.setAttestationData(generateIdJagToken(Duration.ZERO, testClaims()));
        confirmation.setAttributes(testAttributes());

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("no matching key(s) found"));
        }
    }

    @Test
    public void testConfirmInstanceInvalidSanDNS() {

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        Map<String, String> attributes = testAttributes();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "host1.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain(ID_JAG_DOMAIN);
        confirmation.setService(ID_JAG_SERVICE);
        confirmation.setAttestationData(generateIdJagToken(Duration.ZERO, testClaims()));
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Unable to validate certificate request sanDNS entries"));
        }
    }

    @Test
    public void testRefreshNotSupported() {

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");
        try {
            provider.refreshInstance(null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("ID JAG X.509 Certificates cannot be refreshed"));
        }
    }

    @Test
    public void testValidateSanUri() {
        InstanceIDJAGProvider provider = new InstanceIDJAGProvider();
        assertTrue(provider.validateSanUri(null));
        assertTrue(provider.validateSanUri(""));
        assertTrue(provider.validateSanUri("spiffe://ns/athenz.production/instanceid"));
        assertTrue(provider.validateSanUri("athenz://instanceid/athenz.production/instanceid"));
        assertTrue(provider.validateSanUri("athenz://instanceid/athenz.production/instanceid,spiffe://ns/athenz.production/instanceid"));
        assertFalse(provider.validateSanUri("athenz://instanceid/athenz.production/instanceid,https://athenz.io"));
        assertFalse(provider.validateSanUri("athenz://hostname/host1"));
    }

    @Test
    public void testValidateIDJAGTokenWithoutJWTProcessor() {

        InstanceIDJAGProvider provider = new InstanceIDJAGProvider();

        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(provider.validateIDJAGToken("some-jwt", ID_JAG_SERVICE, errMsg));
        assertTrue(errMsg.toString().contains("JWT Processor not initialized"));
    }

    @Test
    public void testValidateIDJAGTokenInvalidTokenType() {

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        // a standard id token type is not accepted as an id jag token

        final String idToken = generateToken(JwtsHelper.TYPE_JWT, Duration.ZERO, testClaims());
        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(provider.validateIDJAGToken(idToken, ID_JAG_SERVICE, errMsg));
        assertTrue(errMsg.toString().contains("Unable to parse and validate token"));
    }

    @Test
    public void testValidateIDJAGTokenIssuerMismatch() {

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        Map<String, Object> claims = testClaims();
        claims.put("iss", "https://some-other-issuer.com");

        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(provider.validateIDJAGToken(generateIdJagToken(Duration.ZERO, claims), ID_JAG_SERVICE, errMsg));
        assertTrue(errMsg.toString().contains("token issuer is not the configured issuer"));
    }

    @Test
    public void testValidateIDJAGTokenAudienceMismatch() {

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        Map<String, Object> claims = testClaims();
        claims.put("aud", "https://some-other-audience.com");

        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(provider.validateIDJAGToken(generateIdJagToken(Duration.ZERO, claims), ID_JAG_SERVICE, errMsg));
        assertTrue(errMsg.toString().contains("token audience is not the configured audience"));
    }

    @Test
    public void testValidateIDJAGTokenIssueTimeNotRecentEnough() {

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        StringBuilder errMsg = new StringBuilder(256);
        final String token = generateIdJagToken(Duration.ofSeconds(400).negated(), testClaims());
        assertFalse(provider.validateIDJAGToken(token, ID_JAG_SERVICE, errMsg));
        assertTrue(errMsg.toString().contains("token issue time is not recent enough"));

        // a token without an issue time at all is rejected as well

        errMsg.setLength(0);
        assertFalse(provider.validateIDJAGToken(generateIdJagToken(null, testClaims()), ID_JAG_SERVICE, errMsg));
        assertTrue(errMsg.toString().contains("token issue time is not recent enough, issued at: null"));
    }

    @Test
    public void testValidateIDJAGTokenMissingActClaim() {

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        // without the act claim at all

        Map<String, Object> claims = testClaims();
        claims.remove("act");

        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(provider.validateIDJAGToken(generateIdJagToken(Duration.ZERO, claims), ID_JAG_SERVICE, errMsg));
        assertTrue(errMsg.toString().contains("token does not contain required act claim"));

        // with an act claim that is not a json object

        claims.put("act", ID_JAG_CLIENT_ID);
        errMsg.setLength(0);
        assertFalse(provider.validateIDJAGToken(generateIdJagToken(Duration.ZERO, claims), ID_JAG_SERVICE, errMsg));
        assertTrue(errMsg.toString().contains("token does not contain required act claim"));
    }

    @Test
    public void testValidateIDJAGTokenSubProfileMismatch() {

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        // the outermost actor carries a profile we're not configured for

        Map<String, Object> act = actClaim();
        act.put("sub_profile", "service");
        Map<String, Object> claims = testClaims();
        claims.put("act", act);

        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(provider.validateIDJAGToken(generateIdJagToken(Duration.ZERO, claims), ID_JAG_SERVICE, errMsg));
        assertTrue(errMsg.toString().contains("token act sub_profile: service does not match configured value: ai_agent"));

        // the outermost actor carries no profile at all

        act.remove("sub_profile");
        claims.put("act", act);
        errMsg.setLength(0);
        assertFalse(provider.validateIDJAGToken(generateIdJagToken(Duration.ZERO, claims), ID_JAG_SERVICE, errMsg));
        assertTrue(errMsg.toString().contains("token act sub_profile: null does not match configured value: ai_agent"));
    }

    @Test
    public void testValidateIDJAGTokenMissingActSubject() {

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        Map<String, Object> act = actClaim();
        act.remove("sub");
        Map<String, Object> claims = testClaims();
        claims.put("act", act);

        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(provider.validateIDJAGToken(generateIdJagToken(Duration.ZERO, claims), ID_JAG_SERVICE, errMsg));
        assertTrue(errMsg.toString().contains("token act claim does not contain required sub field"));
    }

    @Test
    public void testValidateIDJAGTokenMissingClientId() {

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        Map<String, Object> claims = testClaims();
        claims.remove("client_id");

        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(provider.validateIDJAGToken(generateIdJagToken(Duration.ZERO, claims), ID_JAG_SERVICE, errMsg));
        assertTrue(errMsg.toString().contains("token does not contain required client_id claim"));
    }

    @Test
    public void testValidateIDJAGTokenClientIdActSubMismatch() {

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        Map<String, Object> claims = testClaims();
        claims.put("client_id", "wlp12h9yjhs9WonAM1d8");

        StringBuilder errMsg = new StringBuilder(256);
        assertFalse(provider.validateIDJAGToken(generateIdJagToken(Duration.ZERO, claims), ID_JAG_SERVICE, errMsg));
        assertTrue(errMsg.toString().contains("token client_id: wlp12h9yjhs9WonAM1d8 does not match act sub: "
                + ID_JAG_CLIENT_ID));
    }

    @Test
    public void testValidateIDJAGTokenServiceMismatch() {

        InstanceIDJAGProvider provider = createProvider("jwt_jwks.json");

        StringBuilder errMsg = new StringBuilder(256);
        final String token = generateIdJagToken(Duration.ZERO, testClaims());
        assertFalse(provider.validateIDJAGToken(token, "api", errMsg));
        assertTrue(errMsg.toString().contains("service name: api does not match token client_id: " + ID_JAG_CLIENT_ID));
    }

    @Test
    public void testGetActStringField() {
        InstanceIDJAGProvider provider = new InstanceIDJAGProvider();
        Map<String, Object> act = new HashMap<>();
        act.put("sub", "service1");
        act.put("act", new HashMap<>());
        assertEquals(provider.getActStringField(act, "sub"), "service1");
        assertNull(provider.getActStringField(act, "act"));
        assertNull(provider.getActStringField(act, "sub_profile"));
    }

    private String generateIdJagToken(Duration issuedAtOffset, Map<String, ?> claims) {
        return generateToken(JwtsHelper.TYPE_JWT_JAG, issuedAtOffset, claims);
    }

    private String generateToken(final String tokenType, Duration issuedAtOffset, Map<String, ?> claims) {

        try {
            PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

            // a null offset generates a token without any issue time

            JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
            JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                    .expirationTime(Date.from(Instant.now().plusSeconds(3600)));
            if (issuedAtOffset != null) {
                claimsSetBuilder.expirationTime(Date.from(Instant.now().plus(issuedAtOffset).plusSeconds(3600)))
                        .issueTime(Date.from(Instant.now().plus(issuedAtOffset)));
            }
            claims.forEach(claimsSetBuilder::claim);

            SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType(tokenType)).keyID("eckey1").build(), claimsSetBuilder.build());
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (Exception ex) {
            return null;
        }
    }
}
