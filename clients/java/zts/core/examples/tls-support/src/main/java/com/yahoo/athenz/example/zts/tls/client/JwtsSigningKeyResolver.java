package com.yahoo.athenz.example.zts.tls.client;

import com.yahoo.athenz.zts.JWK;
import com.yahoo.athenz.zts.JWKList;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolver;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class JwtsSigningKeyResolver implements SigningKeyResolver {

    private static final Map<String, String> EC_CURVE_ALIASES = createCurveAliasMap();

    ConcurrentHashMap<String, PublicKey> publicKeys;

    public JwtsSigningKeyResolver(JWKList jwkList) {

        publicKeys = new ConcurrentHashMap<>();
        for (JWK key : jwkList.getKeys()) {
            addPublicKey(key);
        }
    }

    @Override
    public Key resolveSigningKey(JwsHeader jwsHeader, Claims claims) {
        return resolveSigningKey(jwsHeader);
    }

    @Override
    public Key resolveSigningKey(JwsHeader jwsHeader, String body) {
        return resolveSigningKey(jwsHeader);
    }

    private Key resolveSigningKey(JwsHeader jwsHeader) {
        return publicKeys.get(jwsHeader.getKeyId());
    }

    public void addPublicKey(final JWK key) {
        try {
            publicKeys.put(key.getKid(), getPublicKey(key));
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new IllegalArgumentException("unable to generate public key with id: " + key.getKid());
        }
    }

    private BigInteger urlString2BigInteger(String base64URL) {
        byte[] bytes = Base64.getUrlDecoder().decode(base64URL.getBytes());
        return new BigInteger(1, bytes);
    }

    private static Map<String, String> createCurveAliasMap() {
        Map<String, String> curveAliases = new HashMap<>();
        curveAliases.put("prime256v1", "secp256r1");
        curveAliases.put("P-256", "secp256r1");
        curveAliases.put("P-384", "secp384r1");
        curveAliases.put("P-521", "secp521r1");
        return Collections.unmodifiableMap(curveAliases);
    }

    public PublicKey getPublicKey(JWK key) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException {

        PublicKey publicKey;
        KeyFactory factory;
        switch (key.getKty()) {
            case "RSA":
                RSAPublicKeySpec rsaKeySpec = new RSAPublicKeySpec(urlString2BigInteger(key.getN()), urlString2BigInteger(key.getE()));
                factory = KeyFactory.getInstance("RSA");
                publicKey = factory.generatePublic(rsaKeySpec);
                break;
            case "EC":
                AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
                parameters.init(new ECGenParameterSpec(EC_CURVE_ALIASES.getOrDefault(key.getCrv(), key.getCrv())));
                ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
                ECPoint ecPoint = new ECPoint(urlString2BigInteger(key.getX()), urlString2BigInteger(key.getY()));
                ECPublicKeySpec ecKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
                factory = KeyFactory.getInstance("EC");
                publicKey = factory.generatePublic(ecKeySpec);
                break;
            default:
                throw new NoSuchAlgorithmException(key.getKty());
        }
        return publicKey;
    }
}
