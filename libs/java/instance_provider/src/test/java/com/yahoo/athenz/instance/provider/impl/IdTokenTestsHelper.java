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

import com.yahoo.athenz.auth.token.IdToken;
import com.yahoo.athenz.auth.util.Crypto;
import io.jsonwebtoken.SignatureAlgorithm;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

public class IdTokenTestsHelper {

    private static final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    static void removeOpenIdConfigFile(File configFile, File jwksUri) {
        try {
            Files.delete(configFile.toPath());
        } catch (Exception ignored) {
        }
        try {
            Files.delete(jwksUri.toPath());
        } catch (Exception ignored) {
        }
    }

    static void createOpenIdConfigFile(File configFile, File jwksUri, boolean createJkws) throws IOException {

        final String fileContents = "{\n" +
                "    \"jwks_uri\": \"file://" + jwksUri.getCanonicalPath() + "\"\n" +
                "}";
        Files.write(configFile.toPath(), fileContents.getBytes());

        if (createJkws) {
            final String keyContents = "{\n" +
                    "    \"keys\": [\n" +
                    "        {\n" +
                    "        \"kty\": \"EC\",\n" +
                    "        \"kid\": \"c9986ee3-7b2a-4f20-d86a-0839356f2541\",\n" +
                    "        \"alg\": \"ES256\",\n" +
                    "        \"use\": \"sig\",\n" +
                    "        \"crv\": \"P-256\",\n" +
                    "        \"x\": \"Rbb6kjqP5au-I7BKfclt2nmizr5CbeYBFjCs7hMBUDU\",\n" +
                    "        \"y\": \"VMHAvuMYRntAmIYMN80exPpplufSMeehuNHWXTRICs8\"\n" +
                    "        }\n" +
                    "    ]\n" +
                    "}";
            Files.write(jwksUri.toPath(), keyContents.getBytes());
        }
    }

    static void createOpenIdConfigFileWithKey(File configFile, File jwksUri, boolean createJkws, ECPublicKey pubKey) throws IOException {

        final String fileContents = "{\n" +
                "    \"jwks_uri\": \"file://" + jwksUri.getCanonicalPath() + "\"\n" +
                "}";
        Files.write(configFile.toPath(), fileContents.getBytes());
        
        if (createJkws) {
            final String keyContents = "{\n" +
                    "    \"keys\": [\n" +
                    "        {\n" +
                    "        \"kty\": \"EC\",\n" +
                    "        \"kid\": \"c9986ee3-7b2a-4f20-d86a-0839356f2541\",\n" +
                    "        \"alg\": \"ES256\",\n" +
                    "        \"use\": \"sig\",\n" +
                    "        \"crv\": \"P-256\",\n" +
                    "        \"x\": \"Rbb6kjqP5au-I7BKfclt2nmizr5CbeYBFjCs7hMBUDU\",\n" +
                    "        \"y\": \"VMHAvuMYRntAmIYMN80exPpplufSMeehuNHWXTRICs8\"\n" +
                    "        },\n" +
                    "        {\n" +
                    "        \"kty\": \"EC\",\n" +
                    "        \"kid\": \"eckey1\",\n" +
                    "        \"alg\": \"ES256\",\n" +
                    "        \"use\": \"sig\",\n" +
                    "        \"crv\": \"P-256\",\n" +
                    "        \"x\": \"" + Base64.getUrlEncoder().withoutPadding().encodeToString(pubKey.getW().getAffineX().toByteArray()) + "\",\n" +
                    "        \"y\": \"" + Base64.getUrlEncoder().withoutPadding().encodeToString(pubKey.getW().getAffineY().toByteArray()) + "\"\n" +
                    "        }\n" +
                    "    ]\n" +
                    "}";
            Files.write(jwksUri.toPath(), keyContents.getBytes());
        }
    }

    static String createToken() {
        return createToken(null, "https://zts.athenz.io/zts/v1", "https://container.googleapis.com/v1/projects/my-project/zones/us-east1-a/clusters/my-cluster");
    }

    static String createToken(String sub, String aud, String issuer) {
        IdToken sampleToken = new IdToken();
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        long now = System.currentTimeMillis() / 1000;
        sampleToken.setExpiryTime(now + 3600);
        sampleToken.setIssueTime(now);
        sampleToken.setAudience(aud);
        sampleToken.setSubject(sub);
        sampleToken.setIssuer(issuer);
        return sampleToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
    }
}
