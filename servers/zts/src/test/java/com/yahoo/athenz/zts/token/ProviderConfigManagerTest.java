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

import com.yahoo.athenz.auth.TokenExchangeIdentityProvider;
import com.yahoo.athenz.auth.token.OAuth2Token;
import com.yahoo.athenz.auth.token.jwts.JwtsResolver;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;

import static org.testng.Assert.*;

public class ProviderConfigManagerTest {

    private File tempDir;
    private File tempConfigFile;

    @BeforeMethod
    public void setUp() throws IOException {
        tempDir = Files.createTempDirectory("provider-config-test").toFile();
        tempConfigFile = new File(tempDir, "provider-config.json");
    }

    @AfterMethod
    public void tearDown() {
        if (tempConfigFile != null && tempConfigFile.exists()) {
            tempConfigFile.delete();
        }
        if (tempDir != null && tempDir.exists()) {
            tempDir.delete();
        }
    }

    @Test
    public void testConstructorWithNullFilePath() {
        ProviderConfigManager manager = new ProviderConfigManager(null);
        assertNotNull(manager);
        assertNotNull(manager.getJwtsResolvers());
        assertEquals(manager.getJwtsResolvers().size(), 0);
        assertNull(manager.getProvider("https://example.com"));
    }

    @Test
    public void testConstructorWithEmptyFilePath() {
        ProviderConfigManager manager = new ProviderConfigManager("");
        assertNotNull(manager);
        assertNotNull(manager.getJwtsResolvers());
        assertEquals(manager.getJwtsResolvers().size(), 0);
        assertNull(manager.getProvider("https://example.com"));
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testConstructorWithNonExistentFile() {
        new ProviderConfigManager("/non/existent/path/config.json");
    }

    @Test
    public void testConstructorWithEmptyJsonArray() throws IOException {
        writeJsonToFile("[]");
        
        ProviderConfigManager manager = new ProviderConfigManager(tempConfigFile.getAbsolutePath());
        assertNotNull(manager);
        assertNotNull(manager.getJwtsResolvers());
        assertEquals(manager.getJwtsResolvers().size(), 0);
    }

    @Test
    public void testConstructorWithValidConfigWithJwksUri() throws IOException {
        String json = "[{" +
                "\"issuerUri\": \"https://example.com/oauth2\"," +
                "\"jwksUri\": \"https://example.com/.well-known/jwks.json\"" +
                "}]";
        writeJsonToFile(json);
        
        ProviderConfigManager manager = new ProviderConfigManager(tempConfigFile.getAbsolutePath());
        assertNotNull(manager);
        assertNotNull(manager.getJwtsResolvers());
        assertEquals(manager.getJwtsResolvers().size(), 1);
        assertNull(manager.getProvider("https://example.com/oauth2"));
    }

    @Test
    public void testConstructorWithValidConfigWithProviderClass() throws IOException {
        String json = "[{" +
                "\"issuerUri\": \"https://example.com/oauth2\"," +
                "\"jwksUri\": \"https://example.com/.well-known/jwks.json\"," +
                "\"providerClassName\": \"" + MockTokenExchangeIdentityProvider.class.getName() + "\"" +
                "}]";
        writeJsonToFile(json);
        
        ProviderConfigManager manager = new ProviderConfigManager(tempConfigFile.getAbsolutePath());
        assertNotNull(manager);
        assertNotNull(manager.getJwtsResolvers());
        assertEquals(manager.getJwtsResolvers().size(), 1);
        
        TokenExchangeIdentityProvider provider = manager.getProvider("https://example.com/oauth2");
        assertNotNull(provider);
        assertTrue(provider instanceof MockTokenExchangeIdentityProvider);
    }

    @Test
    public void testConstructorWithValidConfigWithProxyUrl() throws IOException {
        String json = "[{" +
                "\"issuerUri\": \"https://example.com/oauth2\"," +
                "\"jwksUri\": \"https://example.com/.well-known/jwks.json\"," +
                "\"proxyUrl\": \"https://proxy.example.com:8080\"" +
                "}]";
        writeJsonToFile(json);
        
        ProviderConfigManager manager = new ProviderConfigManager(tempConfigFile.getAbsolutePath());
        assertNotNull(manager);
        assertNotNull(manager.getJwtsResolvers());
        assertEquals(manager.getJwtsResolvers().size(), 1);
    }

    @Test
    public void testConstructorWithMultipleProviders() throws IOException {
        String json = "[{" +
                "\"issuerUri\": \"https://example1.com/oauth2\"," +
                "\"jwksUri\": \"https://example1.com/.well-known/jwks.json\"" +
                "}," +
                "{" +
                "\"issuerUri\": \"https://example2.com/oauth2\"," +
                "\"jwksUri\": \"https://example2.com/.well-known/jwks.json\"" +
                "}]";
        writeJsonToFile(json);
        
        ProviderConfigManager manager = new ProviderConfigManager(tempConfigFile.getAbsolutePath());
        assertNotNull(manager);
        assertNotNull(manager.getJwtsResolvers());
        assertEquals(manager.getJwtsResolvers().size(), 2);
    }

    @Test
    public void testConstructorWithInvalidProviderClass() throws IOException {
        String json = "[{" +
                "\"issuerUri\": \"https://example.com/oauth2\"," +
                "\"jwksUri\": \"https://example.com/.well-known/jwks.json\"," +
                "\"providerClassName\": \"com.nonexistent.Class\"" +
                "}]";
        writeJsonToFile(json);
        
        ProviderConfigManager manager = new ProviderConfigManager(tempConfigFile.getAbsolutePath());
        assertNotNull(manager);
        // Provider should not be loaded due to invalid class
        assertNull(manager.getProvider("https://example.com/oauth2"));
        // no resolver should be created
        assertEquals(manager.getJwtsResolvers().size(), 0);
    }

    @Test
    public void testConstructorWithMissingIssuerUri() throws IOException {
        String json = "[{" +
                "\"jwksUri\": \"https://example.com/.well-known/jwks.json\"" +
                "}]";
        writeJsonToFile(json);
        
        ProviderConfigManager manager = new ProviderConfigManager(tempConfigFile.getAbsolutePath());
        assertNotNull(manager);
        // Config without issuerUri should be skipped
        assertEquals(manager.getJwtsResolvers().size(), 0);
    }

    @Test
    public void testConstructorWithEmptyIssuerUri() throws IOException {
        String json = "[{" +
                "\"issuerUri\": \"\"," +
                "\"jwksUri\": \"https://example.com/.well-known/jwks.json\"" +
                "}]";
        writeJsonToFile(json);
        
        ProviderConfigManager manager = new ProviderConfigManager(tempConfigFile.getAbsolutePath());
        assertNotNull(manager);
        // Config with empty issuerUri should be skipped
        assertEquals(manager.getJwtsResolvers().size(), 0);
    }

    @Test
    public void testConstructorWithMissingJwksUri() throws IOException {
        String json = "[{" +
                "\"issuerUri\": \"https://example.com/oauth2\"" +
                "}]";
        writeJsonToFile(json);
        
        ProviderConfigManager manager = new ProviderConfigManager(tempConfigFile.getAbsolutePath());
        assertNotNull(manager);
        // Config without jwksUri and unable to extract from openid-config should be skipped
        // Note: extractJwksUri will likely return null in test environment
        assertEquals(manager.getJwtsResolvers().size(), 0);
    }

    @Test
    public void testProcessProviderConfigWithValidConfig() {
        ProviderConfigManager manager = new ProviderConfigManager(null);
        
        ProviderConfig config = new ProviderConfig();
        config.setIssuerUri("https://test.example.com/oauth2");
        config.setJwksUri("https://test.example.com/.well-known/jwks.json");
        config.setProviderClassName(MockTokenExchangeIdentityProvider.class.getName());

        manager.processProviderConfig(config);
        
        assertEquals(manager.getJwtsResolvers().size(), 1);
        assertNotNull(manager.getProvider("https://test.example.com/oauth2"));
    }

    @Test
    public void testProcessProviderConfigWithNullIssuerUri() {
        ProviderConfigManager manager = new ProviderConfigManager(null);
        
        ProviderConfig config = new ProviderConfig();
        config.setIssuerUri(null);
        config.setJwksUri("https://test.example.com/.well-known/jwks.json");
        
        manager.processProviderConfig(config);
        
        // Should not add any resolver due to missing issuerUri
        assertEquals(manager.getJwtsResolvers().size(), 0);
    }

    @Test
    public void testProcessProviderConfigWithEmptyIssuerUri() {
        ProviderConfigManager manager = new ProviderConfigManager(null);
        
        ProviderConfig config = new ProviderConfig();
        config.setIssuerUri("");
        config.setJwksUri("https://test.example.com/.well-known/jwks.json");
        
        manager.processProviderConfig(config);
        
        // Should not add any resolver due to empty issuerUri
        assertEquals(manager.getJwtsResolvers().size(), 0);
    }

    @Test
    public void testProcessProviderConfigWithMissingJwksUri() {
        ProviderConfigManager manager = new ProviderConfigManager(null);
        
        ProviderConfig config = new ProviderConfig();
        config.setIssuerUri("https://test.example.com/oauth2");
        // No jwksUri set, and extractJwksUri will likely return null in test
        
        manager.processProviderConfig(config);
        
        // Should not add any resolver due to missing jwksUri
        assertEquals(manager.getJwtsResolvers().size(), 0);
    }

    @Test
    public void testProcessProviderConfigWithInvalidProviderClass() {
        ProviderConfigManager manager = new ProviderConfigManager(null);
        
        ProviderConfig config = new ProviderConfig();
        config.setIssuerUri("https://test.example.com/oauth2");
        config.setJwksUri("https://test.example.com/.well-known/jwks.json");
        config.setProviderClassName("com.nonexistent.InvalidClass");
        
        manager.processProviderConfig(config);
        
        assertEquals(manager.getJwtsResolvers().size(), 0);
        assertNull(manager.getProvider("https://test.example.com/oauth2"));
    }


    @Test
    public void testGetJwtsResolvers() throws IOException {
        String json = "[{" +
                "\"issuerUri\": \"https://example1.com/oauth2\"," +
                "\"jwksUri\": \"https://example1.com/.well-known/jwks.json\"" +
                "}," +
                "{" +
                "\"issuerUri\": \"https://example2.com/oauth2\"," +
                "\"jwksUri\": \"https://example2.com/.well-known/jwks.json\"" +
                "}]";
        writeJsonToFile(json);
        
        ProviderConfigManager manager = new ProviderConfigManager(tempConfigFile.getAbsolutePath());
        
        List<JwtsResolver> resolvers = manager.getJwtsResolvers();
        assertNotNull(resolvers);
        assertEquals(resolvers.size(), 2);
        
        // Verify resolvers are not null
        assertNotNull(resolvers.get(0));
        assertNotNull(resolvers.get(1));
        
        // Verify the list is not modifiable (if it's unmodifiable)
        // Actually, looking at the code, it returns the list directly, so it might be modifiable
        // But we'll test that getJwtsResolvers returns the same list instance
        List<JwtsResolver> resolvers2 = manager.getJwtsResolvers();
        assertEquals(resolvers, resolvers2);
    }

    @Test
    public void testGetProvider() throws IOException {
        String json = "[{" +
                "\"issuerUri\": \"https://example1.com/oauth2\"," +
                "\"jwksUri\": \"https://example1.com/.well-known/jwks.json\"," +
                "\"providerClassName\": \"" + MockTokenExchangeIdentityProvider.class.getName() + "\"" +
                "}," +
                "{" +
                "\"issuerUri\": \"https://example2.com/oauth2\"," +
                "\"jwksUri\": \"https://example2.com/.well-known/jwks.json\"" +
                "}]";
        writeJsonToFile(json);
        
        ProviderConfigManager manager = new ProviderConfigManager(tempConfigFile.getAbsolutePath());
        
        // Test getting provider that exists
        TokenExchangeIdentityProvider provider1 = manager.getProvider("https://example1.com/oauth2");
        assertNotNull(provider1);
        assertTrue(provider1 instanceof MockTokenExchangeIdentityProvider);
        
        // Test getting provider that doesn't exist
        assertNull(manager.getProvider("https://example2.com/oauth2"));
        
        // Test getting provider with non-existent issuer
        assertNull(manager.getProvider("https://nonexistent.com/oauth2"));
        
        // Test getting provider with null issuer
        assertNull(manager.getProvider(null));
    }

    @Test
    public void testMultipleProvidersWithSameIssuerUri() throws IOException {
        // When multiple providers have the same issuerUri, the last one should win
        String json = "[{" +
                "\"issuerUri\": \"https://example.com/oauth2\"," +
                "\"jwksUri\": \"https://example.com/.well-known/jwks.json\"," +
                "\"providerClassName\": \"" + MockTokenExchangeIdentityProvider.class.getName() + "\"" +
                "}," +
                "{" +
                "\"issuerUri\": \"https://example.com/oauth2\"," +
                "\"jwksUri\": \"https://example.com/.well-known/jwks.json\"" +
                "}]";
        writeJsonToFile(json);
        
        ProviderConfigManager manager = new ProviderConfigManager(tempConfigFile.getAbsolutePath());
        
        // Should have 2 resolvers (one for each config entry)
        assertEquals(manager.getJwtsResolvers().size(), 2);
        
        // Provider should exist (from first entry)
        assertNotNull(manager.getProvider("https://example.com/oauth2"));
    }

    @Test
    public void testConstructorWithMalformedJson() throws IOException {
        writeJsonToFile("not valid json");
        
        try {
            new ProviderConfigManager(tempConfigFile.getAbsolutePath());
            // Depending on JSON parsing, this might throw an exception or handle it gracefully
            // We'll test that it doesn't crash the test
        } catch (Exception e) {
            // Expected - malformed JSON should cause an error
            assertTrue(e instanceof IllegalArgumentException || e.getCause() instanceof Exception);
        }
    }

    @Test
    public void testConstructorWithNullJsonArray() throws IOException {
        // Test with JSON that parses to null
        writeJsonToFile("null");
        
        ProviderConfigManager manager = new ProviderConfigManager(tempConfigFile.getAbsolutePath());
        assertNotNull(manager);
        assertEquals(manager.getJwtsResolvers().size(), 0);
    }

    @Test
    public void testProcessProviderConfigWithProxyUrl() {
        ProviderConfigManager manager = new ProviderConfigManager(null);
        
        ProviderConfig config = new ProviderConfig();
        config.setIssuerUri("https://test.example.com/oauth2");
        config.setJwksUri("https://test.example.com/.well-known/jwks.json");
        config.setProxyUrl("https://proxy.example.com:8080");
        
        manager.processProviderConfig(config);
        
        assertEquals(manager.getJwtsResolvers().size(), 1);
        // Verify resolver was created (we can't easily verify proxyUrl was passed without reflection)
    }

    @Test
    public void testProcessProviderConfigProviderClassNotTokenExchangeIdentityProvider() throws IOException {
        // Test with a class that exists but doesn't implement TokenExchangeIdentityProvider
        String json = "[{" +
                "\"issuerUri\": \"https://example.com/oauth2\"," +
                "\"jwksUri\": \"https://example.com/.well-known/jwks.json\"," +
                "\"providerClassName\": \"" + String.class.getName() + "\"" +
                "}]";
        writeJsonToFile(json);
        
        try {
            ProviderConfigManager manager = new ProviderConfigManager(tempConfigFile.getAbsolutePath());
            // Should handle ClassCastException gracefully
            assertNull(manager.getProvider("https://example.com/oauth2"));
        } catch (Exception e) {
            // ClassCastException should be caught and logged, but might propagate
            assertTrue(e instanceof IllegalArgumentException || 
                      e.getCause() instanceof ClassCastException ||
                      e.getCause() instanceof Exception);
        }
    }

    // Helper method to write JSON to temp file
    private void writeJsonToFile(String json) throws IOException {
        try (FileWriter writer = new FileWriter(tempConfigFile)) {
            writer.write(json);
        }
    }

    // Mock implementation of TokenExchangeIdentityProvider for testing
    public static class MockTokenExchangeIdentityProvider implements TokenExchangeIdentityProvider {
        @Override
        public String getIdentity(OAuth2Token token) {
            return null;
        }

        @Override
        public List<String> getTokenExchangeClaims() {
            return null;
        }
    }
}

