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
package com.yahoo.athenz.auth.token.jwts;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.*;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class Key {

    private static final Map<String, String> EC_CURVE_ALIASES = createCurveAliasMap();

    private static final ObjectMapper JSON_MAPPER = initJsonMapper();

    static ObjectMapper initJsonMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return mapper;
    }
    private String alg;
    private String e;
    private String kid;
    private String kty;
    private String n;
    private String use;
    private String x;
    private String y;
    private String crv;

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public String getE() {
        return e;
    }

    public void setE(String e) {
        this.e = e;
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public String getKty() {
        return kty;
    }

    public void setKty(String kty) {
        this.kty = kty;
    }

    public String getN() {
        return n;
    }

    public void setN(String n) {
        this.n = n;
    }

    public String getUse() {
        return use;
    }

    public void setUse(String use) {
        this.use = use;
    }

    public String getCrv() {
        return crv;
    }

    public void setCrv(String crv) {
        this.crv = crv;
    }

    public String getY() {
        return y;
    }

    public void setY(String y) {
        this.y = y;
    }

    public String getX() {
        return x;
    }

    public void setX(String x) {
        this.x = x;
    }

    private static Map<String, String> createCurveAliasMap() {
        Map<String, String> curveAliases = new HashMap<>();
        curveAliases.put("prime256v1", "secp256r1");
        curveAliases.put("P-256", "secp256r1");
        curveAliases.put("P-384", "secp384r1");
        curveAliases.put("P-521", "secp521r1");
        return Collections.unmodifiableMap(curveAliases);
    }

    private BigInteger urlString2BigInteger(String base64URL) {
        byte[] bytes = Base64.getUrlDecoder().decode(base64URL.getBytes());
        return new BigInteger(1, bytes);
    }

    public PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException {

        PublicKey publicKey;
        KeyFactory factory;
        switch (kty) {
            case "RSA":
                RSAPublicKeySpec rsaKeySpec = new RSAPublicKeySpec(urlString2BigInteger(n), urlString2BigInteger(e));
                factory = KeyFactory.getInstance("RSA");
                publicKey = factory.generatePublic(rsaKeySpec);
                break;
            case "EC":
                AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
                parameters.init(new ECGenParameterSpec(EC_CURVE_ALIASES.getOrDefault(crv, crv)));
                ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
                ECPoint ecPoint = new ECPoint(urlString2BigInteger(x), urlString2BigInteger(y));
                ECPublicKeySpec ecKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
                factory = KeyFactory.getInstance("EC");
                publicKey = factory.generatePublic(ecKeySpec);
                break;
            default:
                throw new NoSuchAlgorithmException(kty);
        }
        return publicKey;
    }
    
    public static Key fromString(String jwkStr) throws JsonProcessingException {
        return JSON_MAPPER.readValue(jwkStr, Key.class);
    }
}
