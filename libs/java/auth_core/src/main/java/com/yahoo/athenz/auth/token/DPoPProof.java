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
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/**
 * Parses and validates a DPoP proof JWT as defined in RFC 9449, and
 * generates proofs for clients. The class has no server dependencies so it
 * can be used by authorization servers, resource servers and clients.
 */
public final class DPoPProof {

    public static final String HTTP_HEADER = "DPoP";
    public static final String TOKEN_TYPE = "DPoP";
    public static final String JWT_TYPE = "dpop+jwt";
    public static final String CLAIM_HTM = "htm";
    public static final String CLAIM_HTU = "htu";
    public static final String CLAIM_ATH = "ath";
    public static final String CLAIM_NONCE = "nonce";

    static final int MAX_JTI_LENGTH = 256;

    private static final DefaultJWSVerifierFactory VERIFIER_FACTORY = new DefaultJWSVerifierFactory();

    private final String jwkThumbprint;
    private final String jwtId;
    private final long issueTime;
    private final String htm;
    private final String htu;
    private final String nonce;
    private final String accessTokenHash;
    private final PublicKey publicKey;

    /**
     * Parse and fully validate the given DPoP proof.
     *
     * @param proof value of the DPoP http header
     * @param expectedHtm http method of the request carrying the proof
     * @param options validation policy
     * @param nowSecs current time in seconds since epoch
     * @throws DPoPProofException if the proof is not valid
     */
    public DPoPProof(final String proof, final String expectedHtm, final DPoPProofOptions options, long nowSecs) {

        if (proof == null || proof.isBlank()) {
            throw new DPoPProofException("empty proof");
        }
        if (proof.length() > options.getMaxProofSize()) {
            throw new DPoPProofException("proof too large");
        }

        // SignedJWT parsing rejects unsecured (alg=none) and JWE objects

        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(proof);
        } catch (ParseException ex) {
            throw new DPoPProofException("malformed proof");
        }

        final JWSHeader header = signedJWT.getHeader();
        final JOSEObjectType type = header.getType();
        if (type == null || !JWT_TYPE.equalsIgnoreCase(type.getType())) {
            throw new DPoPProofException("invalid typ header");
        }

        final JWSAlgorithm alg = header.getAlgorithm();
        if (!options.getAllowedAlgorithms().contains(alg)) {
            throw new DPoPProofException("unsupported alg: " + alg);
        }

        // we only use the embedded jwk. kid/jku/x5u/x5c are ignored
        // and we never fetch anything based on the proof contents

        final JWK jwk = header.getJWK();
        validateJwk(alg, jwk, options.getMinRsaKeySize());

        try {
            publicKey = ((AsymmetricJWK) jwk).toPublicKey();
            JWSVerifier verifier = VERIFIER_FACTORY.createJWSVerifier(header, publicKey);
            if (!signedJWT.verify(verifier)) {
                throw new DPoPProofException("invalid signature");
            }
        } catch (JOSEException ex) {
            throw new DPoPProofException("unable to verify signature");
        }

        JWTClaimsSet claims;
        try {
            claims = signedJWT.getJWTClaimsSet();
            htm = claims.getStringClaim(CLAIM_HTM);
            htu = claims.getStringClaim(CLAIM_HTU);
            nonce = claims.getStringClaim(CLAIM_NONCE);
            accessTokenHash = claims.getStringClaim(CLAIM_ATH);
        } catch (ParseException ex) {
            throw new DPoPProofException("invalid claims");
        }

        jwtId = claims.getJWTID();
        if (jwtId == null || jwtId.isEmpty()) {
            throw new DPoPProofException("missing jti claim");
        }
        if (jwtId.length() > MAX_JTI_LENGTH) {
            throw new DPoPProofException("jti claim too long");
        }
        if (htm == null) {
            throw new DPoPProofException("missing htm claim");
        }
        if (htu == null) {
            throw new DPoPProofException("missing htu claim");
        }
        final Date iat = claims.getIssueTime();
        if (iat == null) {
            throw new DPoPProofException("missing iat claim");
        }
        issueTime = iat.getTime() / 1000;

        if (!htm.equals(expectedHtm)) {
            throw new DPoPProofException("htm mismatch");
        }
        final String normalizedHtu = normalizeHtu(htu);
        if (normalizedHtu == null || !options.getAllowedHtus().contains(normalizedHtu)) {
            throw new DPoPProofException("htu mismatch");
        }

        if (issueTime > nowSecs + options.getClockSkewSecs()) {
            throw new DPoPProofException("proof issued in the future");
        }
        if (issueTime < nowSecs - options.getMaxAgeSecs()) {
            throw new DPoPProofException("proof expired");
        }

        try {
            jwkThumbprint = jwk.computeThumbprint().toString();
        } catch (JOSEException ex) {
            throw new DPoPProofException("unable to compute jwk thumbprint");
        }
    }

    static void validateJwk(final JWSAlgorithm alg, final JWK jwk, int minRsaKeySize) {

        if (jwk == null) {
            throw new DPoPProofException("missing jwk header");
        }
        if (jwk.isPrivate()) {
            throw new DPoPProofException("jwk contains private key material");
        }

        final KeyType keyType = jwk.getKeyType();
        if (KeyType.EC.equals(keyType)) {
            if (!JWSAlgorithm.Family.EC.contains(alg)) {
                throw new DPoPProofException("jwk key type does not match alg");
            }
            Set<Curve> curves = Curve.forJWSAlgorithm(alg);
            if (curves == null || !curves.contains(jwk.toECKey().getCurve())) {
                throw new DPoPProofException("jwk curve does not match alg");
            }
        } else if (KeyType.RSA.equals(keyType)) {
            if (!JWSAlgorithm.Family.RSA.contains(alg)) {
                throw new DPoPProofException("jwk key type does not match alg");
            }
            if (jwk.size() < minRsaKeySize) {
                throw new DPoPProofException("jwk rsa key too small");
            }
        } else {
            throw new DPoPProofException("unsupported jwk key type: " + keyType);
        }
    }

    /**
     * @return RFC 7638 SHA-256 thumbprint of the proof jwk, base64url encoded without padding
     */
    public String getJwkThumbprint() {
        return jwkThumbprint;
    }

    public String getJwtId() {
        return jwtId;
    }

    public long getIssueTime() {
        return issueTime;
    }

    public String getHtm() {
        return htm;
    }

    public String getHtu() {
        return htu;
    }

    /**
     * @return the nonce claim or null if not present
     */
    public String getNonce() {
        return nonce;
    }

    /**
     * @return the ath claim or null if not present
     */
    public String getAccessTokenHash() {
        return accessTokenHash;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Normalize an htu value for comparison: drop query and fragment,
     * lowercase scheme and host, drop the default port and use "/" for an
     * empty path. Only absolute http/https uris without userinfo are accepted.
     *
     * @param uri uri to normalize
     * @return normalized uri or null if the uri is not acceptable
     */
    public static String normalizeHtu(final String uri) {

        if (uri == null) {
            return null;
        }

        URI parsed;
        try {
            parsed = new URI(uri);
        } catch (URISyntaxException ex) {
            return null;
        }

        if (!parsed.isAbsolute() || parsed.getRawUserInfo() != null || parsed.getHost() == null) {
            return null;
        }

        final String scheme = parsed.getScheme().toLowerCase(Locale.ROOT);
        int defaultPort;
        switch (scheme) {
            case "https":
                defaultPort = 443;
                break;
            case "http":
                defaultPort = 80;
                break;
            default:
                return null;
        }

        StringBuilder normalized = new StringBuilder(uri.length());
        normalized.append(scheme).append("://").append(parsed.getHost().toLowerCase(Locale.ROOT));
        final int port = parsed.getPort();
        if (port != -1 && port != defaultPort) {
            normalized.append(':').append(port);
        }
        final String path = parsed.getRawPath();
        normalized.append(path == null || path.isEmpty() ? "/" : path);
        return normalized.toString();
    }

    /**
     * Compute the RFC 7638 SHA-256 thumbprint of the given public key.
     *
     * @param key RSA or EC public key
     * @return base64url encoded thumbprint without padding
     * @throws DPoPProofException if the key type or curve is not supported
     */
    public static String computeJwkThumbprint(final PublicKey key) {
        try {
            return toPublicJwk(key).computeThumbprint().toString();
        } catch (JOSEException ex) {
            throw new DPoPProofException("unable to compute jwk thumbprint", ex);
        }
    }

    /**
     * Compute the ath claim value for the given access token.
     *
     * @param accessToken access token value
     * @return base64url(SHA-256(ASCII(access token))) without padding
     */
    public static String computeAccessTokenHash(final String accessToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64URL.encode(digest.digest(accessToken.getBytes(StandardCharsets.US_ASCII))).toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new DPoPProofException("unable to compute access token hash", ex);
        }
    }

    /**
     * Generate a signed DPoP proof.
     *
     * @param privateKey private key used to sign the proof
     * @param publicKey public key matching the private key; embedded as the jwk header
     * @param htm http method of the request
     * @param htu http uri of the request (without query and fragment)
     * @param accessToken optional access token; when set the ath claim is included
     * @param nonce optional server provided nonce
     * @param iatSecs issue time in seconds since epoch
     * @return serialized proof
     * @throws DPoPProofException if the key is not supported or signing fails
     */
    public static String generate(final PrivateKey privateKey, final PublicKey publicKey, final String htm,
            final String htu, final String accessToken, final String nonce, long iatSecs) {

        final JWK jwk = toPublicJwk(publicKey);
        final JWSAlgorithm alg = signingAlgorithm(jwk);

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim(CLAIM_HTM, htm)
                .claim(CLAIM_HTU, htu)
                .issueTime(new Date(iatSecs * 1000));
        if (accessToken != null) {
            claimsBuilder.claim(CLAIM_ATH, computeAccessTokenHash(accessToken));
        }
        if (nonce != null) {
            claimsBuilder.claim(CLAIM_NONCE, nonce);
        }

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(alg).type(new JOSEObjectType(JWT_TYPE)).jwk(jwk).build(),
                claimsBuilder.build());
        try {
            signedJWT.sign(JwtsHelper.getJWSSigner(privateKey));
        } catch (JOSEException ex) {
            throw new DPoPProofException("unable to sign proof", ex);
        }
        return signedJWT.serialize();
    }

    static JWK toPublicJwk(final PublicKey key) {
        if (key instanceof RSAPublicKey) {
            return new RSAKey.Builder((RSAPublicKey) key).build();
        }
        if (key instanceof ECPublicKey) {
            final ECPublicKey ecKey = (ECPublicKey) key;
            final Curve curve = Curve.forECParameterSpec(ecKey.getParams());
            if (curve == null) {
                throw new DPoPProofException("unsupported ec curve");
            }
            return new ECKey.Builder(curve, ecKey).build();
        }
        throw new DPoPProofException("unsupported key type");
    }

    static JWSAlgorithm signingAlgorithm(final JWK jwk) {
        if (KeyType.RSA.equals(jwk.getKeyType())) {
            return JWSAlgorithm.RS256;
        }
        final Curve curve = jwk.toECKey().getCurve();
        if (Curve.P_256.equals(curve)) {
            return JWSAlgorithm.ES256;
        } else if (Curve.P_384.equals(curve)) {
            return JWSAlgorithm.ES384;
        } else if (Curve.P_521.equals(curve)) {
            return JWSAlgorithm.ES512;
        }
        throw new DPoPProofException("unsupported ec curve: " + curve);
    }
}
