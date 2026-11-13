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
package com.yahoo.athenz.auth.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.*;

public class DPoPProofTest {

    private static final String HTU = "https://zts.athenz.io:4443/zts/v1/oauth2/token";
    private static final String HTM = "POST";

    private KeyPair ecP256;
    private KeyPair ecP384;
    private KeyPair ecP521;
    private KeyPair rsa2048;
    private KeyPair rsa1024;
    private DPoPProofOptions options;

    @BeforeClass
    public void setup() throws Exception {
        ecP256 = ecKeyPair("secp256r1");
        ecP384 = ecKeyPair("secp384r1");
        ecP521 = ecKeyPair("secp521r1");
        rsa2048 = rsaKeyPair(2048);
        rsa1024 = rsaKeyPair(1024);
        options = DPoPProofOptions.builder().addAllowedHtu(HTU).build();
    }

    private static KeyPair ecKeyPair(final String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    private static KeyPair rsaKeyPair(int size) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(size);
        return generator.generateKeyPair();
    }

    private static long now() {
        return System.currentTimeMillis() / 1000;
    }

    private static JWTClaimsSet.Builder validClaims(long iat) {
        return new JWTClaimsSet.Builder()
                .jwtID("jti-001")
                .claim(DPoPProof.CLAIM_HTM, HTM)
                .claim(DPoPProof.CLAIM_HTU, HTU)
                .issueTime(new Date(iat * 1000));
    }

    private static JWSHeader.Builder ecHeader(KeyPair keyPair, JWSAlgorithm alg) {
        return new JWSHeader.Builder(alg).type(new JOSEObjectType(DPoPProof.JWT_TYPE))
                .jwk(DPoPProof.toPublicJwk(keyPair.getPublic()));
    }

    private static String sign(JWSHeader header, JWTClaimsSet claims, JWSSigner signer) throws JOSEException {
        SignedJWT signedJWT = new SignedJWT(header, claims);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    private String signEC256(JWTClaimsSet claims) throws JOSEException {
        return sign(ecHeader(ecP256, JWSAlgorithm.ES256).build(), claims,
                new ECDSASigner((ECPrivateKey) ecP256.getPrivate()));
    }

    private static String rawProof(final String headerJson, final String payloadJson) {
        return Base64URL.encode(headerJson.getBytes(StandardCharsets.UTF_8)) + "."
                + Base64URL.encode(payloadJson.getBytes(StandardCharsets.UTF_8)) + ".c2lnbmF0dXJl";
    }

    private void assertRejected(final String proof, final String reason) {
        assertRejected(proof, HTM, options, now(), reason);
    }

    private static void assertRejected(final String proof, final String htm, DPoPProofOptions options,
            long now, final String reason) {
        try {
            new DPoPProof(proof, htm, options, now);
            fail("proof accepted, expected: " + reason);
        } catch (DPoPProofException ex) {
            assertEquals(ex.getMessage(), reason);
        }
    }

    @Test
    public void testRfc7638ThumbprintVector() throws ParseException, JOSEException {
        RSAKey rsaKey = RSAKey.parse("{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4"
                + "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0"
                + "_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G"
                + "_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}");
        assertEquals(DPoPProof.computeJwkThumbprint(rsaKey.toRSAPublicKey()),
                "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    @Test
    public void testComputeAccessTokenHashRfc9449Vector() {
        assertEquals(DPoPProof.computeAccessTokenHash("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"),
                "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");
    }

    @Test
    public void testGenerateAndValidateRoundTrip() throws ParseException {
        for (KeyPair keyPair : Arrays.asList(ecP256, ecP384, ecP521, rsa2048)) {
            long now = now();
            final String proof = DPoPProof.generate(keyPair.getPrivate(), keyPair.getPublic(), HTM, HTU,
                    null, null, now);

            DPoPProof dpopProof = new DPoPProof(proof, HTM, options, now);
            assertEquals(dpopProof.getJwkThumbprint(), DPoPProof.computeJwkThumbprint(keyPair.getPublic()));
            assertEquals(dpopProof.getHtm(), HTM);
            assertEquals(dpopProof.getHtu(), HTU);
            assertEquals(dpopProof.getIssueTime(), now);
            assertNotNull(dpopProof.getJwtId());
            assertNull(dpopProof.getNonce());
            assertNull(dpopProof.getAccessTokenHash());
            assertEquals(dpopProof.getPublicKey().getEncoded(), keyPair.getPublic().getEncoded());

            // the embedded jwk must be the public key only

            SignedJWT signedJWT = SignedJWT.parse(proof);
            assertFalse(signedJWT.getHeader().getJWK().isPrivate());
            assertEquals(signedJWT.getHeader().getType().getType(), DPoPProof.JWT_TYPE);
        }
    }

    @Test
    public void testGenerateAlgorithms() throws ParseException {
        assertEquals(SignedJWT.parse(DPoPProof.generate(ecP256.getPrivate(), ecP256.getPublic(), HTM, HTU,
                null, null, now())).getHeader().getAlgorithm(), JWSAlgorithm.ES256);
        assertEquals(SignedJWT.parse(DPoPProof.generate(ecP384.getPrivate(), ecP384.getPublic(), HTM, HTU,
                null, null, now())).getHeader().getAlgorithm(), JWSAlgorithm.ES384);
        assertEquals(SignedJWT.parse(DPoPProof.generate(ecP521.getPrivate(), ecP521.getPublic(), HTM, HTU,
                null, null, now())).getHeader().getAlgorithm(), JWSAlgorithm.ES512);
        assertEquals(SignedJWT.parse(DPoPProof.generate(rsa2048.getPrivate(), rsa2048.getPublic(), HTM, HTU,
                null, null, now())).getHeader().getAlgorithm(), JWSAlgorithm.RS256);
    }

    @Test
    public void testGenerateFreshJwtId() throws ParseException {
        long now = now();
        final String proof1 = DPoPProof.generate(ecP256.getPrivate(), ecP256.getPublic(), HTM, HTU, null, null, now);
        final String proof2 = DPoPProof.generate(ecP256.getPrivate(), ecP256.getPublic(), HTM, HTU, null, null, now);
        assertNotEquals(SignedJWT.parse(proof1).getJWTClaimsSet().getJWTID(),
                SignedJWT.parse(proof2).getJWTClaimsSet().getJWTID());
    }

    @Test
    public void testGenerateWithAccessTokenAndNonce() throws ParseException {
        long now = now();
        final String proof = DPoPProof.generate(ecP256.getPrivate(), ecP256.getPublic(), HTM, HTU,
                "access-token", "server-nonce", now);

        JWTClaimsSet claims = SignedJWT.parse(proof).getJWTClaimsSet();
        assertEquals(claims.getStringClaim(DPoPProof.CLAIM_ATH), DPoPProof.computeAccessTokenHash("access-token"));
        assertEquals(claims.getStringClaim(DPoPProof.CLAIM_NONCE), "server-nonce");

        DPoPProof dpopProof = new DPoPProof(proof, HTM, options, now);
        assertEquals(dpopProof.getAccessTokenHash(), DPoPProof.computeAccessTokenHash("access-token"));
        assertEquals(dpopProof.getNonce(), "server-nonce");
    }

    @Test
    public void testGenerateUnsupportedKeys() throws Exception {

        KeyPairGenerator dsaGenerator = KeyPairGenerator.getInstance("DSA");
        dsaGenerator.initialize(2048);
        KeyPair dsa = dsaGenerator.generateKeyPair();
        try {
            DPoPProof.generate(dsa.getPrivate(), dsa.getPublic(), HTM, HTU, null, null, now());
            fail();
        } catch (DPoPProofException ex) {
            assertEquals(ex.getMessage(), "unsupported key type");
        }
        try {
            DPoPProof.computeJwkThumbprint(dsa.getPublic());
            fail();
        } catch (DPoPProofException ex) {
            assertEquals(ex.getMessage(), "unsupported key type");
        }

        // secp256k1 is a known jwk curve but we don't sign proofs with it

        KeyPairGenerator bcGenerator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        bcGenerator.initialize(new ECGenParameterSpec("secp256k1"));
        KeyPair secp256k1 = bcGenerator.generateKeyPair();
        try {
            DPoPProof.generate(secp256k1.getPrivate(), secp256k1.getPublic(), HTM, HTU, null, null, now());
            fail();
        } catch (DPoPProofException ex) {
            assertTrue(ex.getMessage().startsWith("unsupported ec curve: "));
        }

        // secp224r1 is not a jwk curve at all

        bcGenerator.initialize(new ECGenParameterSpec("secp224r1"));
        KeyPair secp224r1 = bcGenerator.generateKeyPair();
        try {
            DPoPProof.computeJwkThumbprint(secp224r1.getPublic());
            fail();
        } catch (DPoPProofException ex) {
            assertEquals(ex.getMessage(), "unsupported ec curve");
        }
    }

    @Test
    public void testGenerateSignFailure() {
        try {
            DPoPProof.generate(rsa2048.getPrivate(), ecP256.getPublic(), HTM, HTU, null, null, now());
            fail();
        } catch (DPoPProofException ex) {
            assertEquals(ex.getMessage(), "unable to sign proof");
        }
    }

    @Test
    public void testEmptyAndOversizedProof() {
        assertRejected(null, "empty proof");
        assertRejected("", "empty proof");
        assertRejected("   ", "empty proof");

        DPoPProofOptions smallOptions = DPoPProofOptions.builder().addAllowedHtu(HTU).maxProofSize(100).build();
        final String proof = DPoPProof.generate(ecP256.getPrivate(), ecP256.getPublic(), HTM, HTU, null, null, now());
        assertRejected(proof, HTM, smallOptions, now(), "proof too large");
    }

    @Test
    public void testMalformedProof() {
        assertRejected("not-a-jwt", "malformed proof");
        assertRejected("a.b.c.d.e", "malformed proof");
    }

    @Test
    public void testUnsecuredProof() {
        PlainJWT plainJWT = new PlainJWT(validClaims(now()).build());
        assertRejected(plainJWT.serialize(), "malformed proof");
    }

    @Test
    public void testHmacProof() throws JOSEException {
        byte[] secret = new byte[32];
        Arrays.fill(secret, (byte) 7);
        final String proof = sign(new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(new JOSEObjectType(DPoPProof.JWT_TYPE)).build(), validClaims(now()).build(), new MACSigner(secret));
        assertRejected(proof, "unsupported alg: HS256");
    }

    @Test
    public void testInvalidType() throws JOSEException {
        ECDSASigner signer = new ECDSASigner((ECPrivateKey) ecP256.getPrivate());
        JWTClaimsSet claims = validClaims(now()).build();

        JWSHeader noType = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .jwk(DPoPProof.toPublicJwk(ecP256.getPublic())).build();
        assertRejected(sign(noType, claims, signer), "invalid typ header");

        for (String type : Arrays.asList("jwt", "at+jwt", "dpop")) {
            JWSHeader header = ecHeader(ecP256, JWSAlgorithm.ES256).type(new JOSEObjectType(type)).build();
            assertRejected(sign(header, claims, signer), "invalid typ header");
        }

        // media type comparison is case-insensitive

        JWSHeader upperType = ecHeader(ecP256, JWSAlgorithm.ES256).type(new JOSEObjectType("DPoP+JWT")).build();
        assertNotNull(new DPoPProof(sign(upperType, claims, signer), HTM, options, now()).getJwkThumbprint());
    }

    @Test
    public void testAlgorithmNotAllowed() throws JOSEException {
        DPoPProofOptions es384Only = DPoPProofOptions.builder().addAllowedHtu(HTU)
                .allowedAlgorithms(Collections.singletonList(JWSAlgorithm.ES384)).build();
        assertRejected(signEC256(validClaims(now()).build()), HTM, es384Only, now(), "unsupported alg: ES256");
    }

    @Test
    public void testMissingJwk() throws JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(DPoPProof.JWT_TYPE)).keyID("key-1").build();
        assertRejected(sign(header, validClaims(now()).build(), new ECDSASigner((ECPrivateKey) ecP256.getPrivate())),
                "missing jwk header");
    }

    @Test
    public void testPrivateJwkInHeader() throws Exception {

        // nimbus refuses to parse a header with a private or symmetric jwk

        ECKey privateJwk = new ECKey.Builder((ECKey) DPoPProof.toPublicJwk(ecP256.getPublic()))
                .privateKey((ECPrivateKey) ecP256.getPrivate()).build();
        final String payload = validClaims(now()).build().toString();
        assertRejected(rawProof("{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":" + privateJwk.toJSONString() + "}",
                payload), "malformed proof");
        assertRejected(rawProof("{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{\"kty\":\"oct\",\"k\":\"c2VjcmV0\"}}",
                payload), "malformed proof");
    }

    @Test
    public void testValidateJwk() throws Exception {

        ECKey privateJwk = new ECKey.Builder((ECKey) DPoPProof.toPublicJwk(ecP256.getPublic()))
                .privateKey((ECPrivateKey) ecP256.getPrivate()).build();
        assertValidateJwkRejected(JWSAlgorithm.ES256, privateJwk, "jwk contains private key material");

        OctetSequenceKey octKey = new OctetSequenceKey.Builder(new byte[32]).build();
        assertValidateJwkRejected(JWSAlgorithm.ES256, octKey, "jwk contains private key material");

        OctetKeyPair okp = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(new byte[32])).build();
        assertValidateJwkRejected(JWSAlgorithm.ES256, okp, "unsupported jwk key type: OKP");

        JWK p384 = DPoPProof.toPublicJwk(ecP384.getPublic());
        assertValidateJwkRejected(JWSAlgorithm.ES256, p384, "jwk curve does not match alg");
        assertValidateJwkRejected(JWSAlgorithm.ES512, p384, "jwk curve does not match alg");

        JWK p256 = DPoPProof.toPublicJwk(ecP256.getPublic());
        JWK rsa = DPoPProof.toPublicJwk(rsa2048.getPublic());
        assertValidateJwkRejected(JWSAlgorithm.RS256, p256, "jwk key type does not match alg");
        assertValidateJwkRejected(JWSAlgorithm.ES256, rsa, "jwk key type does not match alg");
        assertValidateJwkRejected(JWSAlgorithm.PS256, DPoPProof.toPublicJwk(rsa1024.getPublic()),
                "jwk rsa key too small");

        DPoPProof.validateJwk(JWSAlgorithm.ES256, p256, 2048);
        DPoPProof.validateJwk(JWSAlgorithm.ES384, p384, 2048);
        DPoPProof.validateJwk(JWSAlgorithm.PS512, rsa, 2048);
    }

    private static void assertValidateJwkRejected(JWSAlgorithm alg, JWK jwk, final String reason) {
        try {
            DPoPProof.validateJwk(alg, jwk, 2048);
            fail();
        } catch (DPoPProofException ex) {
            assertEquals(ex.getMessage(), reason);
        }
    }

    @Test
    public void testSmallRsaKey() throws JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(new JOSEObjectType(DPoPProof.JWT_TYPE))
                .jwk(DPoPProof.toPublicJwk(rsa1024.getPublic())).build();
        final String proof = sign(header, validClaims(now()).build(), new RSASSASigner(rsa1024.getPrivate(), true));
        assertRejected(proof, "jwk rsa key too small");

        // the minimum size is configurable

        DPoPProofOptions weakOptions = DPoPProofOptions.builder().addAllowedHtu(HTU).minRsaKeySize(1024).build();
        assertNotNull(new DPoPProof(proof, HTM, weakOptions, now()).getJwkThumbprint());
    }

    @Test
    public void testInvalidSignature() throws Exception {

        // signed with a key that does not match the embedded jwk

        JWSHeader header = ecHeader(ecP256, JWSAlgorithm.ES256).build();
        KeyPair other = ecKeyPair("secp256r1");
        assertRejected(sign(header, validClaims(now()).build(), new ECDSASigner((ECPrivateKey) other.getPrivate())),
                "invalid signature");

        // tampered payload

        final String proof = signEC256(validClaims(now()).build());
        final String[] parts = proof.split("\\.");
        final String tamperedPayload = Base64URL.encode(validClaims(now()).jwtID("jti-002").build().toString()).toString();
        assertRejected(parts[0] + "." + tamperedPayload + "." + parts[2], "invalid signature");
    }

    @Test
    public void testUnknownCriticalHeader() throws JOSEException {
        JWSHeader header = ecHeader(ecP256, JWSAlgorithm.ES256)
                .criticalParams(Collections.singleton("exp-param")).customParam("exp-param", "value").build();
        assertRejected(sign(header, validClaims(now()).build(), new ECDSASigner((ECPrivateKey) ecP256.getPrivate())),
                "invalid signature");
    }

    @Test
    public void testInvalidClaimTypes() throws JOSEException {
        assertRejected(signEC256(validClaims(now()).claim(DPoPProof.CLAIM_HTM, 123).build()), "invalid claims");
        assertRejected(signEC256(validClaims(now()).claim(DPoPProof.CLAIM_HTU, List.of(HTU)).build()), "invalid claims");
        assertRejected(signEC256(validClaims(now()).claim(DPoPProof.CLAIM_NONCE, Map.of("a", "b")).build()),
                "invalid claims");
    }

    @Test
    public void testMissingClaims() throws JOSEException {
        long now = now();
        assertRejected(signEC256(validClaims(now).jwtID(null).build()), "missing jti claim");
        assertRejected(signEC256(validClaims(now).jwtID("").build()), "missing jti claim");
        assertRejected(signEC256(validClaims(now).claim(DPoPProof.CLAIM_HTM, null).build()), "missing htm claim");
        assertRejected(signEC256(validClaims(now).claim(DPoPProof.CLAIM_HTU, null).build()), "missing htu claim");
        assertRejected(signEC256(validClaims(now).issueTime(null).build()), "missing iat claim");
    }

    @Test
    public void testJwtIdLength() throws JOSEException {
        char[] jti = new char[DPoPProof.MAX_JTI_LENGTH];
        Arrays.fill(jti, 'a');
        assertNotNull(new DPoPProof(signEC256(validClaims(now()).jwtID(new String(jti)).build()), HTM, options, now()));

        char[] longJti = new char[DPoPProof.MAX_JTI_LENGTH + 1];
        Arrays.fill(longJti, 'a');
        assertRejected(signEC256(validClaims(now()).jwtID(new String(longJti)).build()), "jti claim too long");
    }

    @Test
    public void testHtmMismatch() throws JOSEException {
        assertRejected(signEC256(validClaims(now()).claim(DPoPProof.CLAIM_HTM, "post").build()), "htm mismatch");
        assertRejected(signEC256(validClaims(now()).claim(DPoPProof.CLAIM_HTM, "GET").build()), "htm mismatch");
        assertRejected(signEC256(validClaims(now()).build()), "GET", options, now(), "htm mismatch");
    }

    @Test
    public void testHtuMatching() throws JOSEException {
        long now = now();
        assertRejected(signEC256(validClaims(now).claim(DPoPProof.CLAIM_HTU,
                "https://other.athenz.io:4443/zts/v1/oauth2/token").build()), "htu mismatch");
        assertRejected(signEC256(validClaims(now).claim(DPoPProof.CLAIM_HTU,
                "https://zts.athenz.io/zts/v1/oauth2/token").build()), "htu mismatch");
        assertRejected(signEC256(validClaims(now).claim(DPoPProof.CLAIM_HTU,
                "/zts/v1/oauth2/token").build()), "htu mismatch");
        assertRejected(signEC256(validClaims(now).claim(DPoPProof.CLAIM_HTU,
                "https://zts.athenz.io:4443/zts/v1/oauth2/token/").build()), "htu mismatch");

        // query, fragment and case differences are normalized

        final String proof = signEC256(validClaims(now).claim(DPoPProof.CLAIM_HTU,
                "HTTPS://ZTS.athenz.io:4443/zts/v1/oauth2/token?x=1#frag").build());
        assertNotNull(new DPoPProof(proof, HTM, options, now));
    }

    @Test
    public void testIssueTimeWindow() throws JOSEException {
        long now = now();

        assertNotNull(new DPoPProof(signEC256(validClaims(now - 30).build()), HTM, options, now));
        assertRejected(signEC256(validClaims(now - 31).build()), HTM, options, now, "proof expired");

        assertNotNull(new DPoPProof(signEC256(validClaims(now + 10).build()), HTM, options, now));
        assertRejected(signEC256(validClaims(now + 11).build()), HTM, options, now, "proof issued in the future");

        DPoPProofOptions strict = DPoPProofOptions.builder().addAllowedHtu(HTU).maxAgeSecs(0).clockSkewSecs(0).build();
        assertNotNull(new DPoPProof(signEC256(validClaims(now).build()), HTM, strict, now));
        assertRejected(signEC256(validClaims(now - 1).build()), HTM, strict, now, "proof expired");
        assertRejected(signEC256(validClaims(now + 1).build()), HTM, strict, now, "proof issued in the future");
    }

    @Test
    public void testNormalizeHtu() {
        assertEquals(DPoPProof.normalizeHtu("https://zts.athenz.io/zts/v1/oauth2/token"),
                "https://zts.athenz.io/zts/v1/oauth2/token");
        assertEquals(DPoPProof.normalizeHtu("HTTPS://ZTS.Athenz.IO/zts/v1/oauth2/token"),
                "https://zts.athenz.io/zts/v1/oauth2/token");
        assertEquals(DPoPProof.normalizeHtu("https://zts.athenz.io:443/zts/v1/oauth2/token"),
                "https://zts.athenz.io/zts/v1/oauth2/token");
        assertEquals(DPoPProof.normalizeHtu("http://zts.athenz.io:80/token"), "http://zts.athenz.io/token");
        assertEquals(DPoPProof.normalizeHtu("http://zts.athenz.io:443/token"), "http://zts.athenz.io:443/token");
        assertEquals(DPoPProof.normalizeHtu("https://zts.athenz.io:4443/token?a=b#c"), "https://zts.athenz.io:4443/token");
        assertEquals(DPoPProof.normalizeHtu("https://zts.athenz.io"), "https://zts.athenz.io/");
        assertEquals(DPoPProof.normalizeHtu("https://zts.athenz.io/Path/"), "https://zts.athenz.io/Path/");
        assertEquals(DPoPProof.normalizeHtu("https://[::1]:4443/token"), "https://[::1]:4443/token");

        assertNull(DPoPProof.normalizeHtu(null));
        assertNull(DPoPProof.normalizeHtu("/zts/v1/oauth2/token"));
        assertNull(DPoPProof.normalizeHtu("ftp://zts.athenz.io/token"));
        assertNull(DPoPProof.normalizeHtu("mailto:user@athenz.io"));
        assertNull(DPoPProof.normalizeHtu("https://zts athenz/token"));
        assertNull(DPoPProof.normalizeHtu("https:///token"));
    }

    @Test
    public void testOptionsDefaults() {
        assertEquals(options.getAllowedAlgorithms().size(), 9);
        assertTrue(options.getAllowedAlgorithms().containsAll(DPoPProofOptions.DEFAULT_ALGORITHMS));
        assertEquals(options.getAllowedHtus(), Collections.singleton(DPoPProof.normalizeHtu(HTU)));
        assertEquals(options.getMaxAgeSecs(), DPoPProofOptions.DEFAULT_MAX_AGE_SECS);
        assertEquals(options.getClockSkewSecs(), DPoPProofOptions.DEFAULT_CLOCK_SKEW_SECS);
        assertEquals(options.getMaxProofSize(), DPoPProofOptions.DEFAULT_MAX_PROOF_SIZE);
        assertEquals(options.getMinRsaKeySize(), DPoPProofOptions.DEFAULT_MIN_RSA_KEY_SIZE);
    }

    @Test
    public void testOptionsInvalidValues() {
        assertOptionRejected(() -> DPoPProofOptions.builder().build(), "DPoP allowed htu set must not be empty");
        assertOptionRejected(() -> DPoPProofOptions.builder().addAllowedHtu("/token"), "Invalid DPoP htu value: /token");
        assertOptionRejected(() -> DPoPProofOptions.builder().allowedAlgorithms(null),
                "DPoP algorithm list must not be empty");
        assertOptionRejected(() -> DPoPProofOptions.builder().allowedAlgorithms(Collections.emptyList()),
                "DPoP algorithm list must not be empty");
        assertOptionRejected(() -> DPoPProofOptions.builder().allowedAlgorithms(List.of(JWSAlgorithm.HS256)),
                "Unsupported DPoP signing algorithm: HS256");
        assertOptionRejected(() -> DPoPProofOptions.builder().allowedAlgorithms(List.of(JWSAlgorithm.EdDSA)),
                "Unsupported DPoP signing algorithm: EdDSA");
        assertOptionRejected(() -> DPoPProofOptions.builder().maxAgeSecs(-1), "DPoP max age must not be negative");
        assertOptionRejected(() -> DPoPProofOptions.builder().clockSkewSecs(-1), "DPoP clock skew must not be negative");
        assertOptionRejected(() -> DPoPProofOptions.builder().maxProofSize(0), "DPoP max proof size must be positive");
        assertOptionRejected(() -> DPoPProofOptions.builder().minRsaKeySize(0), "DPoP min RSA key size must be positive");
    }

    private static void assertOptionRejected(Runnable runnable, final String message) {
        try {
            runnable.run();
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), message);
        }
    }

    @Test
    public void testOptionsImmutable() {
        try {
            options.getAllowedHtus().add("https://other/token");
            fail();
        } catch (UnsupportedOperationException ignored) {
        }
        try {
            options.getAllowedAlgorithms().add(JWSAlgorithm.ES256K);
            fail();
        } catch (UnsupportedOperationException ignored) {
        }
    }

    @Test
    public void testExceptionConstructors() {
        DPoPProofException ex = new DPoPProofException("reason");
        assertEquals(ex.getMessage(), "reason");
        assertNull(ex.getCause());

        IllegalStateException cause = new IllegalStateException("cause");
        ex = new DPoPProofException("reason", cause);
        assertEquals(ex.getMessage(), "reason");
        assertEquals(ex.getCause(), cause);
    }
}
