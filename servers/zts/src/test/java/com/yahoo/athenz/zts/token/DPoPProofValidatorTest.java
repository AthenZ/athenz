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
package com.yahoo.athenz.zts.token;

import com.nimbusds.jose.JWSAlgorithm;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.DPoPProof;
import com.yahoo.athenz.auth.token.DPoPProofException;
import com.yahoo.athenz.auth.token.DPoPProofOptions;
import com.yahoo.athenz.zts.ZTSConsts;
import jakarta.servlet.http.HttpServletRequest;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.testng.Assert.*;

public class DPoPProofValidatorTest {

    private static final String ISSUER = "https://athenz.io:4443/zts/v1";
    private static final String HTU = ISSUER + "/oauth2/token";

    private static final List<String> DPOP_PROPERTIES = List.of(
            ZTSConsts.ZTS_PROP_DPOP_SIGNING_ALGORITHMS,
            ZTSConsts.ZTS_PROP_DPOP_PROOF_MAX_AGE,
            ZTSConsts.ZTS_PROP_DPOP_PROOF_CLOCK_SKEW,
            ZTSConsts.ZTS_PROP_DPOP_ALLOWED_HTU,
            ZTSConsts.ZTS_PROP_DPOP_HTU_MATCH_REQUEST_HOST,
            ZTSConsts.ZTS_PROP_DPOP_REQUIRE_CERT_KEY_MATCH,
            ZTSConsts.ZTS_PROP_DPOP_MAX_PROOF_SIZE,
            ZTSConsts.ZTS_PROP_DPOP_MIN_RSA_KEY_SIZE);

    private KeyPair dpopKey;
    private KeyPair otherKey;

    @BeforeClass
    public void setup() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        dpopKey = generator.generateKeyPair();
        otherKey = generator.generateKeyPair();
    }

    @AfterMethod
    public void clearProperties() {
        DPOP_PROPERTIES.forEach(System::clearProperty);
    }

    private String proof(final String htu) {
        return DPoPProof.generate(dpopKey.getPrivate(), dpopKey.getPublic(), "POST", htu, null, null,
                System.currentTimeMillis() / 1000);
    }

    private static HttpServletRequest request(String... proofs) {
        return requestWithHost("athenz.io:4443", proofs);
    }

    private static HttpServletRequest requestWithHost(final String host, String... proofs) {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("Host")).thenReturn(host);
        Mockito.when(request.getMethod()).thenReturn("POST");
        Mockito.when(request.getHeaders(DPoPProof.HTTP_HEADER))
                .thenReturn(Collections.enumeration(Arrays.asList(proofs)));
        return request;
    }

    private static Principal certPrincipal(KeyPair keyPair) {
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("sports", "api",
                "x509-certificate-details", 0, null);
        X509Certificate cert = Mockito.mock(X509Certificate.class);
        Mockito.when(cert.getPublicKey()).thenReturn(keyPair.getPublic());
        principal.setX509Certificate(cert);
        return principal;
    }

    private static void assertRejected(DPoPProofValidator validator, HttpServletRequest request,
            Principal principal, final String reason) {
        try {
            validator.validate(request, principal);
            fail("expected rejection: " + reason);
        } catch (DPoPProofException ex) {
            assertEquals(ex.getMessage(), reason);
        }
    }

    @Test
    public void testDefaults() {
        DPoPProofValidator validator = new DPoPProofValidator(Set.of(ISSUER));
        assertEquals(validator.getSupportedAlgorithms(), Arrays.asList("ES256", "ES384", "ES512",
                "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"));
        assertEquals(validator.getOptions().getAllowedHtus(), Set.of(HTU));
        assertEquals(validator.getOptions().getMaxAgeSecs(), DPoPProofOptions.DEFAULT_MAX_AGE_SECS);
        assertEquals(validator.getOptions().getClockSkewSecs(), DPoPProofOptions.DEFAULT_CLOCK_SKEW_SECS);
        assertEquals(validator.getOptions().getMaxProofSize(), DPoPProofOptions.DEFAULT_MAX_PROOF_SIZE);
        assertEquals(validator.getOptions().getMinRsaKeySize(), DPoPProofOptions.DEFAULT_MIN_RSA_KEY_SIZE);
        assertFalse(validator.isRequireCertKeyMatch());
        assertTrue(validator.isHtuMatchRequestHost());
    }

    @Test
    public void testConfiguredProperties() {
        System.setProperty(ZTSConsts.ZTS_PROP_DPOP_SIGNING_ALGORITHMS, " ES256 , PS256,, ");
        System.setProperty(ZTSConsts.ZTS_PROP_DPOP_PROOF_MAX_AGE, "60");
        System.setProperty(ZTSConsts.ZTS_PROP_DPOP_PROOF_CLOCK_SKEW, "5");
        System.setProperty(ZTSConsts.ZTS_PROP_DPOP_MAX_PROOF_SIZE, "4096");
        System.setProperty(ZTSConsts.ZTS_PROP_DPOP_MIN_RSA_KEY_SIZE, "3072");
        System.setProperty(ZTSConsts.ZTS_PROP_DPOP_REQUIRE_CERT_KEY_MATCH, "true");
        System.setProperty(ZTSConsts.ZTS_PROP_DPOP_HTU_MATCH_REQUEST_HOST, "false");
        System.setProperty(ZTSConsts.ZTS_PROP_DPOP_ALLOWED_HTU,
                "https://zts.athenz.io/zts/v1/oauth2/token, ,HTTPS://ALB.athenz.io:443/zts/v1/oauth2/token");

        DPoPProofValidator validator = new DPoPProofValidator(Set.of(ISSUER));
        assertEquals(validator.getSupportedAlgorithms(), Arrays.asList("ES256", "PS256"));
        assertEquals(validator.getOptions().getAllowedAlgorithms(), Set.of(JWSAlgorithm.ES256, JWSAlgorithm.PS256));
        assertEquals(validator.getOptions().getMaxAgeSecs(), 60);
        assertEquals(validator.getOptions().getClockSkewSecs(), 5);
        assertEquals(validator.getOptions().getMaxProofSize(), 4096);
        assertEquals(validator.getOptions().getMinRsaKeySize(), 3072);
        assertTrue(validator.isRequireCertKeyMatch());
        assertFalse(validator.isHtuMatchRequestHost());
        assertEquals(validator.getOptions().getAllowedHtus(), Set.of(HTU,
                "https://zts.athenz.io/zts/v1/oauth2/token", "https://alb.athenz.io/zts/v1/oauth2/token"));
    }

    @Test
    public void testInvalidAlgorithms() {
        for (String algs : Arrays.asList("HS256", "ES256,foo", "none", "EdDSA", " , ")) {
            System.setProperty(ZTSConsts.ZTS_PROP_DPOP_SIGNING_ALGORITHMS, algs);
            try {
                new DPoPProofValidator(Set.of(ISSUER));
                fail("algorithms accepted: " + algs);
            } catch (IllegalArgumentException ignored) {
            }
        }
    }

    @Test
    public void testInvalidNumericProperties() {
        System.setProperty(ZTSConsts.ZTS_PROP_DPOP_PROOF_MAX_AGE, "abc");
        try {
            new DPoPProofValidator(Set.of(ISSUER));
            fail();
        } catch (IllegalArgumentException ignored) {
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_DPOP_PROOF_MAX_AGE);
        System.setProperty(ZTSConsts.ZTS_PROP_DPOP_PROOF_CLOCK_SKEW, "-1");
        try {
            new DPoPProofValidator(Set.of(ISSUER));
            fail();
        } catch (IllegalArgumentException ignored) {
        }
    }

    @Test
    public void testAllowedHtuFromIssuers() {
        // zts uses the bare server hostname as the oauth issuer when
        // athenz.zts.oauth_issuer is not configured - it can't be an htu

        Set<String> issuers = new HashSet<>(Arrays.asList(ISSUER, "https://ZTS.athenz.io:443/zts/v1",
                null, "", "not a uri", "ftp://athenz.io/zts/v1", "zts-host.athenz.io"));
        DPoPProofValidator validator = new DPoPProofValidator(issuers);
        assertEquals(validator.getOptions().getAllowedHtus(), Set.of(HTU, "https://zts.athenz.io/zts/v1/oauth2/token"));
    }

    @Test
    public void testNoValidHtu() {
        try {
            new DPoPProofValidator(null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "DPoP allowed htu set must not be empty");
        }

        System.setProperty(ZTSConsts.ZTS_PROP_DPOP_ALLOWED_HTU, "/zts/v1/oauth2/token");
        try {
            new DPoPProofValidator(Set.of(ISSUER));
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid DPoP htu value: /zts/v1/oauth2/token");
        }
    }

    @Test
    public void testValidateNoHeader() {
        DPoPProofValidator validator = new DPoPProofValidator(Set.of(ISSUER));
        assertNull(validator.validate(request(), null));

        HttpServletRequest nullHeaders = Mockito.mock(HttpServletRequest.class);
        Mockito.when(nullHeaders.getHeaders(DPoPProof.HTTP_HEADER)).thenReturn(null);
        assertNull(validator.validate(nullHeaders, null));
    }

    @Test
    public void testValidateSuccess() {
        DPoPProofValidator validator = new DPoPProofValidator(Set.of(ISSUER));
        final String expectedJkt = DPoPProof.computeJwkThumbprint(dpopKey.getPublic());

        assertEquals(validator.validate(request(proof(HTU)), null), expectedJkt);

        // principal without a certificate

        Principal principal = SimplePrincipal.create("sports", "api", "creds", 0, null);
        assertEquals(validator.validate(request(proof(HTU)), principal), expectedJkt);

        // cert key match is not enforced by default

        assertEquals(validator.validate(request(proof(HTU)), certPrincipal(otherKey)), expectedJkt);
    }

    @Test
    public void testValidateHeaderErrors() {
        DPoPProofValidator validator = new DPoPProofValidator(Set.of(ISSUER));

        assertRejected(validator, request(proof(HTU), proof(HTU)), null, "multiple DPoP headers");
        assertRejected(validator, request(""), null, "empty proof");
        assertRejected(validator, request("  "), null, "empty proof");
        assertRejected(validator, request("not-a-jwt"), null, "malformed proof");
        assertRejected(validator, request(proof("https://other.athenz.io/zts/v1/oauth2/token")), null,
                "htu mismatch");

        System.setProperty(ZTSConsts.ZTS_PROP_DPOP_MAX_PROOF_SIZE, "64");
        DPoPProofValidator smallValidator = new DPoPProofValidator(Set.of(ISSUER));
        assertRejected(smallValidator, request(proof(HTU)), null, "proof too large");
    }

    @Test
    public void testValidateHttpMethod() {
        DPoPProofValidator validator = new DPoPProofValidator(Set.of(ISSUER));
        HttpServletRequest request = request(proof(HTU));
        Mockito.when(request.getMethod()).thenReturn("GET");
        assertRejected(validator, request, null, "htm mismatch");
    }

    @Test
    public void testValidateCertKeyMatch() {
        System.setProperty(ZTSConsts.ZTS_PROP_DPOP_REQUIRE_CERT_KEY_MATCH, "true");
        DPoPProofValidator validator = new DPoPProofValidator(Set.of(ISSUER));
        final String expectedJkt = DPoPProof.computeJwkThumbprint(dpopKey.getPublic());

        assertEquals(validator.validate(request(proof(HTU)), certPrincipal(dpopKey)), expectedJkt);
        assertRejected(validator, request(proof(HTU)), certPrincipal(otherKey),
                "proof key does not match certificate key");

        // without a certificate (e.g. client assertion) the check is skipped

        Principal principal = SimplePrincipal.create("sports", "api", "creds", 0, null);
        assertEquals(validator.validate(request(proof(HTU)), principal), expectedJkt);
        assertEquals(validator.validate(request(proof(HTU)), null), expectedJkt);
    }

    @Test
    public void testValidateHtuMatchesRequestHost() {

        // a proof created for one allowed url is not accepted through another

        final String albHtu = "https://alb.athenz.io/zts/v1/oauth2/token";
        System.setProperty(ZTSConsts.ZTS_PROP_DPOP_ALLOWED_HTU, albHtu);
        DPoPProofValidator validator = new DPoPProofValidator(Set.of(ISSUER));
        final String expectedJkt = DPoPProof.computeJwkThumbprint(dpopKey.getPublic());

        assertEquals(validator.validate(requestWithHost("athenz.io:4443", proof(HTU)), null), expectedJkt);
        assertEquals(validator.validate(requestWithHost("ALB.athenz.io", proof(albHtu)), null), expectedJkt);
        assertRejected(validator, requestWithHost("alb.athenz.io", proof(HTU)), null, "htu does not match request host");
        assertRejected(validator, requestWithHost("athenz.io:4443", proof(albHtu)), null,
                "htu does not match request host");

        // without a Host header the server name is used

        HttpServletRequest serverName = requestWithHost(null, proof(albHtu));
        Mockito.when(serverName.getServerName()).thenReturn("alb.athenz.io");
        assertEquals(validator.validate(serverName, null), expectedJkt);

        // a request without any host is rejected

        assertRejected(validator, requestWithHost("", proof(HTU)), null, "htu does not match request host");

        // the check can be disabled for proxies that rewrite the Host header

        System.setProperty(ZTSConsts.ZTS_PROP_DPOP_HTU_MATCH_REQUEST_HOST, "false");
        DPoPProofValidator hostAgnostic = new DPoPProofValidator(Set.of(ISSUER));
        assertEquals(hostAgnostic.validate(requestWithHost("alb.athenz.io", proof(HTU)), null), expectedJkt);
        assertRejected(hostAgnostic, requestWithHost("alb.athenz.io", proof("https://other.athenz.io/oauth2/token")),
                null, "htu mismatch");
    }

    @Test
    public void testValidateHtuMatchesIpv6RequestHost() {

        final String ipv6Htu = "https://[2001:db8::1]:4443/zts/v1/oauth2/token";
        System.setProperty(ZTSConsts.ZTS_PROP_DPOP_ALLOWED_HTU, ipv6Htu);
        DPoPProofValidator validator = new DPoPProofValidator(Set.of(ISSUER));
        final String expectedJkt = DPoPProof.computeJwkThumbprint(dpopKey.getPublic());

        assertEquals(validator.validate(requestWithHost("[2001:DB8::1]:4443", proof(ipv6Htu)), null), expectedJkt);
        assertRejected(validator, requestWithHost("[2001:db8::2]:4443", proof(ipv6Htu)), null,
                "htu does not match request host");
    }

    @Test
    public void testGetRequestHost() {

        for (String[] test : new String[][] {
                { "zts.athenz.io", "zts.athenz.io" },
                { "ZTS.Athenz.io:4443", "zts.athenz.io" },
                { "[2001:db8::1]:4443", "[2001:db8::1]" },
                { "[2001:db8::1]", "[2001:db8::1]" },
                { "", null } }) {
            HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
            Mockito.when(request.getHeader("Host")).thenReturn(test[0]);
            assertEquals(DPoPProofValidator.getRequestHost(request), test[1], test[0]);
        }

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getServerName()).thenReturn("Server.athenz.io");
        assertEquals(DPoPProofValidator.getRequestHost(request), "server.athenz.io");
    }

    @Test
    public void testValidateHtuMatchesHostMappedIssuer() {

        // requests to a host mapped to an external issuer (e.g. through a gateway)
        // accept proofs for that issuer's token endpoint, but only on that host

        final String extIssuer = "https://zts-ext.athenz.io/zts/v1";
        final String extHtu = extIssuer + "/oauth2/token";
        DPoPProofValidator validator = new DPoPProofValidator(Set.of(ISSUER, extIssuer),
                request -> "zts-int.athenz.io".equals(request.getHeader("Host")) ? extIssuer : null);
        final String expectedJkt = DPoPProof.computeJwkThumbprint(dpopKey.getPublic());

        assertEquals(validator.validate(requestWithHost("zts-int.athenz.io", proof(extHtu)), null), expectedJkt);
        assertEquals(validator.validate(requestWithHost("athenz.io:4443", proof(HTU)), null), expectedJkt);
        assertRejected(validator, requestWithHost("athenz.io:4443", proof(extHtu)), null,
                "htu does not match request host");
        assertRejected(validator, requestWithHost("zts-int.athenz.io", proof(HTU)), null,
                "htu does not match request host");

        // mapped issuers that are empty or not valid uris never match

        for (String mappedIssuer : new String[] { "", "not a uri" }) {
            DPoPProofValidator invalidMapping = new DPoPProofValidator(Set.of(ISSUER, extIssuer),
                    request -> mappedIssuer);
            assertRejected(invalidMapping, requestWithHost("zts-int.athenz.io", proof(extHtu)), null,
                    "htu does not match request host");
        }
    }

    @Test
    public void testValidateSeparateOpenIDIssuerDeployment() {

        // clients use https://zts.athenz.io:4443/zts/v1 while the openid issuer is
        // https://zts-oidc.athenz.io/zts/v1 and the oauth issuer is the default
        // (bare server hostname, which is not a valid htu)

        final String ztsHtu = "https://zts.athenz.io:4443/zts/v1/oauth2/token";
        final String oidcHtu = "https://zts-oidc.athenz.io/zts/v1/oauth2/token";
        final Set<String> issuers = Set.of("zts-node1.athenz.io", "https://zts-oidc.athenz.io/zts/v1");
        final String expectedJkt = DPoPProof.computeJwkThumbprint(dpopKey.getPublic());

        // only the openid issuer token endpoint is allowed by default

        DPoPProofValidator validator = new DPoPProofValidator(issuers);
        assertEquals(validator.getOptions().getAllowedHtus(), Set.of(oidcHtu));
        assertRejected(validator, requestWithHost("zts.athenz.io:4443", proof(ztsHtu)), null, "htu mismatch");
        assertEquals(validator.validate(requestWithHost("zts-oidc.athenz.io", proof(oidcHtu)), null), expectedJkt);

        // the zts url is allowed once configured, and each url is only
        // accepted on its own host

        System.setProperty(ZTSConsts.ZTS_PROP_DPOP_ALLOWED_HTU, ztsHtu);
        validator = new DPoPProofValidator(issuers);
        assertEquals(validator.validate(requestWithHost("zts.athenz.io:4443", proof(ztsHtu)), null), expectedJkt);
        assertEquals(validator.validate(requestWithHost("zts-oidc.athenz.io", proof(oidcHtu)), null), expectedJkt);
        assertEquals(validator.validate(requestWithHost("zts-oidc.athenz.io:443", proof(oidcHtu)), null), expectedJkt);
        assertRejected(validator, requestWithHost("zts.athenz.io:4443", proof(oidcHtu)), null,
                "htu does not match request host");
        assertRejected(validator, requestWithHost("zts-oidc.athenz.io", proof(ztsHtu)), null,
                "htu does not match request host");

        // a different port on the same host is still checked by the allowed set

        assertRejected(validator, requestWithHost("zts.athenz.io", proof("https://zts.athenz.io/zts/v1/oauth2/token")),
                null, "htu mismatch");
    }
}
