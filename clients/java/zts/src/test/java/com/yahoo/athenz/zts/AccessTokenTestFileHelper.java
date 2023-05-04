package com.yahoo.athenz.zts;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.util.Crypto;
import io.jsonwebtoken.SignatureAlgorithm;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static org.testng.Assert.fail;

public class AccessTokenTestFileHelper {

    private static final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private static final File tokenFile = new File("./src/test/resources/test.domain/admin");
    private static final File invalidTokenFile = new File("./src/test/resources/test.domain/invalid");

    private static AccessToken createAccessToken(long now) {
        return createAccessToken(now, 3600);
    }

    private static AccessToken createAccessToken(long now, int expiry) {

        AccessToken accessToken = new AccessToken();
        accessToken.setAuthTime(now);
        accessToken.setScope(Collections.singletonList("admin"));
        accessToken.setSubject("subject");
        accessToken.setUserId("userid");
        accessToken.setExpiryTime(now + expiry);
        accessToken.setIssueTime(now);
        accessToken.setClientId("mtls");
        accessToken.setAudience("coretech");
        accessToken.setVersion(1);
        accessToken.setIssuer("athenz");
        accessToken.setProxyPrincipal("proxy.user");
        accessToken.setConfirmEntry("x5t#uri", "spiffe://athenz/sa/api");

        try {
            Path path = Paths.get("src/test/resources/mtls_token_spec.cert");
            String certStr = new String(Files.readAllBytes(path));
            X509Certificate cert = Crypto.loadX509Certificate(certStr);
            accessToken.setConfirmX509CertHash(cert);
        } catch (IOException ignored) {
            fail();
        }

        return accessToken;
    }

    public static String getSignedAccessToken(int expiry) {
        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now, expiry);
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        return accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
    }

    public static void setupTokenFile() {
        AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);

        accessTokenResponse.setAccess_token(accessJws);
        accessTokenResponse.setExpires_in(28800);
        accessTokenResponse.setScope("admin");
        accessTokenResponse.setToken_type("Bearer");

        ObjectMapper objectMapper = new ObjectMapper();

        try {
            objectMapper.writeValue(tokenFile, accessTokenResponse);
            System.out.println("Write new access token " + accessTokenResponse.toString() + " to file: " + tokenFile + " successfully");
        } catch (IOException e) {
            e.printStackTrace();
            fail();
        }
    }

    public static void setupInvalidTokenFile() {
        String str = "Invalid access token";

        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(invalidTokenFile));
            writer.write(str);
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
            fail();
        }

    }
}
