package com.yahoo.athenz.zts;

import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static com.yahoo.athenz.zts.AccessTokenTestFileHelper.setupTokenFile;
import static org.testng.Assert.*;

public class ZTSAccessTokenFileLoaderTest {

    private JwtsSigningKeyResolver resolver;

    private final File confFile = new File("./src/test/resources/athenz.conf");

    @BeforeMethod
    public void setup() throws IOException {
        File jwksUri = new File("./src/test/resources/jwt_jwks.json");
        resolver = new JwtsSigningKeyResolver("file://" + jwksUri.getCanonicalPath(), null);

        System.setProperty(ZTSAccessTokenFileLoader.ACCESS_TOKEN_PATH_PROPERTY, "./src/test/resources/");
        System.setProperty("athenz.athenz_conf", confFile.getAbsolutePath());
        setupTokenFile();
    }

    @Test
    public void voidTestPreload() {
        ZTSAccessTokenFileLoader ztsAccessTokenFileLoader = new ZTSAccessTokenFileLoader(resolver);
        ztsAccessTokenFileLoader.preload();
    }

    @Test
    public void testFileUtil() {
        final String domain = "test.domain";
        List<String> roles = new ArrayList<>();
        ZTSAccessTokenFileLoader ztsAccessTokenFileLoader = new ZTSAccessTokenFileLoader(resolver);
        ztsAccessTokenFileLoader.preload();

        AccessTokenResponse accessTokenResponse = null;

        try {
            accessTokenResponse = ztsAccessTokenFileLoader.lookupAccessTokenFromDisk(domain, roles);
        } catch (IOException e) {
            fail();
        }

        assertNull(accessTokenResponse);

        roles.add("admin");
        try {
            accessTokenResponse = ztsAccessTokenFileLoader.lookupAccessTokenFromDisk(domain, roles);
        } catch (IOException e) {
            fail();
        }

        assertNotNull(accessTokenResponse);
        assertEquals(accessTokenResponse.getScope(), "admin");
        assertEquals(accessTokenResponse.getToken_type(), "Bearer");

        AccessToken accessToken = new AccessToken(accessTokenResponse.getAccess_token(), resolver);

        assertEquals(accessToken.getScope(), Collections.singleton("admin"));
        assertEquals(accessToken.getIssuer(), "athenz");
    }
}
