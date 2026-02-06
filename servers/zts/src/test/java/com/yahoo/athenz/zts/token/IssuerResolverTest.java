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

import com.yahoo.athenz.zts.ZTSConsts;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;

import static org.testng.Assert.*;

public class IssuerResolverTest {

    private static final String TEST_DIR = "/tmp/issuer_resolver_test";
    private static final String DEFAULT_OAUTH_ISSUER = "https://athenz.io/zts/v1";
    private static final String DEFAULT_OPENID_ISSUER = "https://athenz.io/zts/v1/openid";
    private static final String DEFAULT_OIDC_PORT_ISSUER = "https://athenz.io:8443/zts/v1/openid";
    private static final int OIDC_PORT = 8443;
    private static final int HTTPS_PORT = 443;

    @BeforeMethod
    public void setup() throws IOException {
        // Clean up test directory
        deleteTestDirectory();
        Files.createDirectories(Paths.get(TEST_DIR));
        
        // Clear the system property
        System.clearProperty(ZTSConsts.ZTS_PROP_HOST_ISSUER_MAPPING_FILE);
    }

    @AfterMethod
    public void tearDown() {
        // Clear the system property
        System.clearProperty(ZTSConsts.ZTS_PROP_HOST_ISSUER_MAPPING_FILE);
        
        // Clean up test directory
        deleteTestDirectory();
    }

    private void deleteTestDirectory() {
        try {
            Path testPath = Paths.get(TEST_DIR);
            if (Files.exists(testPath)) {
                Files.walk(testPath)
                    .sorted((a, b) -> -a.compareTo(b))
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            // Ignore
                        }
                    });
            }
        } catch (IOException e) {
            // Ignore
        }
    }

    @Test
    public void testIssuerResolverWithoutMappingFile() {
        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        assertNotNull(resolver);
        Set<String> oauth2Issuers = resolver.getOauth2Issuers();
        assertNotNull(oauth2Issuers);
        assertEquals(oauth2Issuers.size(), 3);
        assertTrue(oauth2Issuers.contains(DEFAULT_OAUTH_ISSUER));
        assertTrue(oauth2Issuers.contains(DEFAULT_OPENID_ISSUER));
        assertTrue(oauth2Issuers.contains(DEFAULT_OIDC_PORT_ISSUER));
    }

    @Test
    public void testIssuerResolverWithValidMappingFile() throws IOException {
        // Create a valid mapping file
        String mappingFile = TEST_DIR + "/mapping.json";
        String jsonContent = "[{\"host\":\"example.com\",\"issuer\":\"https://example.com/issuer\"}," +
                            "{\"host\":\"test.com\",\"issuer\":\"https://test.com/issuer\"}]";
        Files.write(Paths.get(mappingFile), jsonContent.getBytes());

        System.setProperty(ZTSConsts.ZTS_PROP_HOST_ISSUER_MAPPING_FILE, mappingFile);

        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        assertNotNull(resolver);
        Set<String> oauth2Issuers = resolver.getOauth2Issuers();
        assertNotNull(oauth2Issuers);
        // Should have 3 default + 2 from mapping = 5
        assertEquals(oauth2Issuers.size(), 5);
        assertTrue(oauth2Issuers.contains("https://example.com/issuer"));
        assertTrue(oauth2Issuers.contains("https://test.com/issuer"));
    }

    @Test
    public void testIssuerResolverWithEmptyMappingFile() throws IOException {
        // Create an empty mapping file
        String mappingFile = TEST_DIR + "/empty_mapping.json";
        String jsonContent = "[]";
        Files.write(Paths.get(mappingFile), jsonContent.getBytes());

        System.setProperty(ZTSConsts.ZTS_PROP_HOST_ISSUER_MAPPING_FILE, mappingFile);

        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        assertNotNull(resolver);
        Set<String> oauth2Issuers = resolver.getOauth2Issuers();
        assertNotNull(oauth2Issuers);
        // Should only have the 3 default issuers
        assertEquals(oauth2Issuers.size(), 3);
    }

    @Test
    public void testIssuerResolverWithInvalidMappingFile() throws IOException {
        // Create a file with invalid entries (empty host or issuer)
        String mappingFile = TEST_DIR + "/invalid_mapping.json";
        String jsonContent = "[{\"host\":\"\",\"issuer\":\"https://example.com/issuer\"}," +
                            "{\"host\":\"test.com\",\"issuer\":\"\"}," +
                            "{\"host\":\"valid.com\",\"issuer\":\"https://valid.com/issuer\"}]";
        Files.write(Paths.get(mappingFile), jsonContent.getBytes());

        System.setProperty(ZTSConsts.ZTS_PROP_HOST_ISSUER_MAPPING_FILE, mappingFile);

        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        assertNotNull(resolver);
        Set<String> oauth2Issuers = resolver.getOauth2Issuers();
        assertNotNull(oauth2Issuers);
        // Should have 3 default + 1 valid from mapping = 4
        assertEquals(oauth2Issuers.size(), 4);
        assertTrue(oauth2Issuers.contains("https://valid.com/issuer"));
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testIssuerResolverWithNonExistentFile() {
        System.setProperty(ZTSConsts.ZTS_PROP_HOST_ISSUER_MAPPING_FILE, TEST_DIR + "/nonexistent.json");

        new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );
    }

    @Test
    public void testGetOauth2Issuers() {
        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        Set<String> issuers = resolver.getOauth2Issuers();
        assertNotNull(issuers);
        assertFalse(issuers.isEmpty());
        assertTrue(issuers.contains(DEFAULT_OAUTH_ISSUER));
    }

    @Test
    public void testIsOauth2Issuer() {
        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        assertTrue(resolver.isOauth2Issuer(DEFAULT_OAUTH_ISSUER));
        assertTrue(resolver.isOauth2Issuer(DEFAULT_OPENID_ISSUER));
        assertTrue(resolver.isOauth2Issuer(DEFAULT_OIDC_PORT_ISSUER));
        assertFalse(resolver.isOauth2Issuer("https://unknown.com/issuer"));
        assertFalse(resolver.isOauth2Issuer(null));
    }

    @Test
    public void testIsOauth2IssuerWithMapping() throws IOException {
        String mappingFile = TEST_DIR + "/mapping.json";
        String jsonContent = "[{\"host\":\"example.com\",\"issuer\":\"https://example.com/issuer\"}]";
        Files.write(Paths.get(mappingFile), jsonContent.getBytes());

        System.setProperty(ZTSConsts.ZTS_PROP_HOST_ISSUER_MAPPING_FILE, mappingFile);

        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        assertTrue(resolver.isOauth2Issuer("https://example.com/issuer"));
        assertTrue(resolver.isOauth2Issuer(DEFAULT_OAUTH_ISSUER));
    }

    @Test
    public void testGetAccessTokenIssuerWithHostMapping() throws IOException {
        String mappingFile = TEST_DIR + "/mapping.json";
        String jsonContent = "[{\"host\":\"example.com\",\"issuer\":\"https://example.com/issuer\"}]";
        Files.write(Paths.get(mappingFile), jsonContent.getBytes());

        System.setProperty(ZTSConsts.ZTS_PROP_HOST_ISSUER_MAPPING_FILE, mappingFile);

        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("Host")).thenReturn("example.com")
                .thenReturn("example.com:443");

        String issuer = resolver.getAccessTokenIssuer(request, false);
        assertEquals(issuer, "https://example.com/issuer");

        issuer = resolver.getAccessTokenIssuer(request, false);
        assertEquals(issuer, "https://example.com/issuer");
    }

    @Test
    public void testGetAccessTokenIssuerWithHostMappingCaseInsensitive() throws IOException {
        String mappingFile = TEST_DIR + "/mapping.json";
        String jsonContent = "[{\"host\":\"example.com\",\"issuer\":\"https://example.com/issuer\"}]";
        Files.write(Paths.get(mappingFile), jsonContent.getBytes());

        System.setProperty(ZTSConsts.ZTS_PROP_HOST_ISSUER_MAPPING_FILE, mappingFile);

        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("Host")).thenReturn("EXAMPLE.COM");

        String issuer = resolver.getAccessTokenIssuer(request, false);
        assertEquals(issuer, "https://example.com/issuer");
    }

    @Test
    public void testGetAccessTokenIssuerWithoutHostMapping() {
        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("Host")).thenReturn("unknown.com");

        String issuer = resolver.getAccessTokenIssuer(request, false);
        assertEquals(issuer, DEFAULT_OAUTH_ISSUER);

        issuer = resolver.getAccessTokenIssuer(request, true);
        assertEquals(issuer, DEFAULT_OPENID_ISSUER);
    }

    @Test
    public void testGetAccessTokenIssuerWithServerNameFallback() throws IOException {
        String mappingFile = TEST_DIR + "/mapping.json";
        String jsonContent = "[{\"host\":\"example.com\",\"issuer\":\"https://example.com/issuer\"}]";
        Files.write(Paths.get(mappingFile), jsonContent.getBytes());

        System.setProperty(ZTSConsts.ZTS_PROP_HOST_ISSUER_MAPPING_FILE, mappingFile);

        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("Host")).thenReturn(null);
        Mockito.when(request.getServerName()).thenReturn("example.com");

        String issuer = resolver.getAccessTokenIssuer(request, false);
        assertEquals(issuer, "https://example.com/issuer");
    }

    @Test
    public void testGetAccessTokenIssuerWithNullRequest() {
        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        String issuer = resolver.getAccessTokenIssuer(null, false);
        assertEquals(issuer, DEFAULT_OAUTH_ISSUER);

        issuer = resolver.getAccessTokenIssuer(null, true);
        assertEquals(issuer, DEFAULT_OPENID_ISSUER);
    }

    @Test
    public void testGetIDTokenIssuerWithHostMapping() throws IOException {
        String mappingFile = TEST_DIR + "/mapping.json";
        String jsonContent = "[{\"host\":\"example.com\",\"issuer\":\"https://example.com/issuer\"}]";
        Files.write(Paths.get(mappingFile), jsonContent.getBytes());

        System.setProperty(ZTSConsts.ZTS_PROP_HOST_ISSUER_MAPPING_FILE, mappingFile);

        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("Host")).thenReturn("example.com");

        String issuer = resolver.getIDTokenIssuer(request, null);
        assertEquals(issuer, "https://example.com/issuer");
    }

    @Test
    public void testGetIDTokenIssuerWithoutHostMapping() {
        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("Host")).thenReturn("unknown.com");
        Mockito.when(request.getLocalPort()).thenReturn(HTTPS_PORT);

        String issuer = resolver.getIDTokenIssuer(request, null);
        assertEquals(issuer, DEFAULT_OPENID_ISSUER);
    }

    @Test
    public void testGetIDTokenIssuerWithOidcPort() {
        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("Host")).thenReturn("unknown.com");
        Mockito.when(request.getLocalPort()).thenReturn(OIDC_PORT);

        String issuer = resolver.getIDTokenIssuer(request, null);
        assertEquals(issuer, DEFAULT_OIDC_PORT_ISSUER);
    }

    @Test
    public void testGetIDTokenIssuerWithIssuerOptionOpenId() {
        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("Host")).thenReturn("unknown.com");
        Mockito.when(request.getLocalPort()).thenReturn(OIDC_PORT);

        String issuer = resolver.getIDTokenIssuer(request, ZTSConsts.ZTS_ISSUER_TYPE_OPENID);
        assertEquals(issuer, DEFAULT_OPENID_ISSUER);
    }

    @Test
    public void testGetIDTokenIssuerWithIssuerOptionOidcPort() {
        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("Host")).thenReturn("unknown.com");
        Mockito.when(request.getLocalPort()).thenReturn(HTTPS_PORT);

        String issuer = resolver.getIDTokenIssuer(request, ZTSConsts.ZTS_ISSUER_TYPE_OIDC_PORT);
        assertEquals(issuer, DEFAULT_OIDC_PORT_ISSUER);
    }

    @Test
    public void testGetIDTokenIssuerWithNullRequest() {
        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            OIDC_PORT,
            HTTPS_PORT
        );

        String issuer = resolver.getIDTokenIssuer(null, null);
        assertEquals(issuer, DEFAULT_OIDC_PORT_ISSUER);
    }

    @Test
    public void testGetIDTokenIssuerWithOidcPortSameAsHttpsPort() {
        // When OIDC port equals HTTPS port, should use OpenID issuer
        IssuerResolver resolver = new IssuerResolver(
            DEFAULT_OAUTH_ISSUER,
            DEFAULT_OPENID_ISSUER,
            DEFAULT_OIDC_PORT_ISSUER,
            HTTPS_PORT,
            HTTPS_PORT
        );

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("Host")).thenReturn("unknown.com");
        Mockito.when(request.getLocalPort()).thenReturn(HTTPS_PORT);

        String issuer = resolver.getIDTokenIssuer(request, null);
        assertEquals(issuer, DEFAULT_OPENID_ISSUER);
    }
}
